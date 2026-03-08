"""Unsloth GRPO trainer for OpenRange CTF trajectories.

Provides binary and progressive reward functions for training models
to solve CTF challenges via tool-calling in qwen3_coder XML format.

Reward design (v9, from open-trajectory-gym):
  - Flag-dominant (0.85) maintains ~0.90 RLOO solve/fail gap
  - Process signals (0.15 total) create within-group variance
  - Physics-inspired efficiency: step_ratio × action_novelty × temporal_decay
  - Hallucination penalty decays ALL process signals (energy loss model)

Usage::

    from open_range.training.grpo_trainer import run_grpo, GRPOConfig
    run_grpo(GRPOConfig(
        model_name="outputs/sft-merged",
        data_paths=["data/online_rl.jsonl"],
        output_dir="outputs/grpo",
    ))

Or via CLI::

    openrange grpo --model outputs/sft-merged --data data/online_rl.jsonl
"""

from __future__ import annotations

import difflib
import json
import logging
import math
import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool call parsing (qwen3_coder XML format)
# ---------------------------------------------------------------------------

_TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*<function=(\w+)>(.*?)</function>\s*</tool_call>",
    re.DOTALL,
)
_PARAM_RE = re.compile(r"<parameter=(\w+)>(.*?)</parameter>", re.DOTALL)
_FLAG_RE = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Known tools & phase classification (from open-trajectory-gym)
# ---------------------------------------------------------------------------

_FLAG_PLACEHOLDERS = frozenset({
    "content_of_flag_here", "FLAG{...}", "", "CHECK",
    "gctf{DUMMY_FLAG}", "flag{this_is_fake_flag}",
})

# OpenEnv MCP tools + common CTF tools
_KNOWN_TOOL_NAMES = frozenset({
    "shell_command", "exec_command", "execute_command",
    "python_code", "read_file", "grep", "file_search",
    "submit_flag", "flag_found", "submit_finding",
    "get_challenge", "get_progress", "check_services",
    "write_stdin", "apply_patch", "web_search",
    "list_sessions", "close_session",
})

_SHELL_WRAPPERS = frozenset({
    "shell_command", "exec_command", "execute_command",
})

_FLAG_TOOLS = frozenset({"submit_flag", "flag_found"})

# Phase classification by binary name (set-based, no regex)
_RECON_BINARIES = frozenset({
    "nmap", "masscan", "ping", "traceroute", "whois", "dig",
    "nslookup", "host", "arp-scan", "netdiscover", "ftp",
    "smbclient", "smbmap", "rpcclient", "snmpwalk", "enum4linux",
})
_ENUM_BINARIES = frozenset({
    "curl", "wget", "gobuster", "ffuf", "dirb", "dirsearch",
    "nikto", "wpscan", "whatweb", "ls", "cat", "head", "tail",
    "find", "grep", "strings", "file", "id", "whoami", "ps",
    "env", "uname", "hostname", "ip", "ifconfig", "netstat", "ss",
    "xxd", "hexdump", "objdump", "readelf", "unzip", "tar",
})
_EXPLOIT_BINARIES = frozenset({
    "sqlmap", "hydra", "john", "hashcat", "python", "python3",
    "ruby", "perl", "gcc", "nc", "ncat", "netcat", "ssh", "scp",
    "msfconsole", "msfvenom", "chmod", "gdb", "ltrace", "strace",
    "sshpass", "bash", "node", "java", "php", "socat",
})
_TOOL_NAME_PHASES = {
    "web_search": "recon", "read_file": "enum", "grep": "enum",
    "file_search": "enum", "python_code": "exploit",
    "apply_patch": "exploit", "flag_found": "flag",
    "submit_flag": "flag", "get_challenge": "recon",
    "check_services": "recon", "get_progress": "enum",
}


def parse_tool_calls(text: str) -> list[dict[str, Any]]:
    """Parse qwen3_coder XML tool calls from model output.

    Returns list of {"name": str, "arguments": dict}.
    """
    # Strip thinking tags before parsing
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    calls = []
    for match in _TOOL_CALL_RE.finditer(text):
        name = match.group(1)
        body = match.group(2)
        args = {}
        for pm in _PARAM_RE.finditer(body):
            args[pm.group(1)] = pm.group(2).strip()
        calls.append({"name": name, "arguments": args})
    return calls


def extract_flags_from_text(text: str) -> list[str]:
    """Extract flag{...} patterns from text."""
    return _FLAG_RE.findall(text)


def _is_real_flag(flag: str) -> bool:
    """Return True if flag is a real value, not a placeholder."""
    if not flag:
        return False
    if flag in _FLAG_PLACEHOLDERS:
        return False
    for poison in ("content_of_flag_here", "dummy_flag", "fake_flag",
                    "this_is_fake", "placeholder"):
        if poison in flag.lower():
            return False
    return True


def _action_fingerprint(tc: dict[str, Any]) -> str:
    """Fingerprint a tool call. Shell wrappers include binary name."""
    name = tc.get("name", "")
    if name in _SHELL_WRAPPERS:
        cmd = _extract_command_str(tc)
        if cmd:
            binary = cmd.split()[0].rsplit("/", 1)[-1].lower()
            return f"{name}:{binary}"
    return name


def _extract_command_str(tc: dict[str, Any]) -> str:
    """Extract the command string from a tool call's arguments."""
    args = tc.get("arguments", {})
    if isinstance(args, dict):
        for key in ("command", "code", "content", "query", "path", "flag"):
            val = args.get(key)
            if val and isinstance(val, str):
                return val.strip()
    return ""


def _classify_phase(tc: dict[str, Any]) -> str | None:
    """Classify a tool call into a CTF phase. Set-based, no regex."""
    name = tc.get("name", "")
    if name in _TOOL_NAME_PHASES:
        return _TOOL_NAME_PHASES[name]
    if name in _SHELL_WRAPPERS:
        cmd = _extract_command_str(tc)
        if not cmd:
            return None
        first_token = cmd.split()[0].rsplit("/", 1)[-1].lower()
        if first_token in _RECON_BINARIES:
            return "recon"
        if first_token in _ENUM_BINARIES:
            return "enum"
        if first_token in _EXPLOIT_BINARIES:
            return "exploit"
    return None


# ---------------------------------------------------------------------------
# Reward functions (TRL GRPOTrainer compatible)
# ---------------------------------------------------------------------------
# TRL GRPOTrainer reward_funcs signature:
#   def reward_fn(completions, **kwargs) -> list[float]
# completions: list of list of dicts (messages) or list of strings
# kwargs may include: prompts, ground_truth, ground_truth_flag, etc.

# RNG for noise injection (variance guarantee)
_reward_rng = random.Random(3407)


def binary_reward(completions: list, **kwargs) -> list[float]:
    """Binary flag-capture reward: 1.0 if correct flag found, else 0.0.

    Checks completions for:
    1. submit_flag tool calls with matching value
    2. flag{...} patterns matching ground truth (only if flag tool was called)

    Filters out known placeholder/fake flags.
    """
    ground_truths = kwargs.get("ground_truth") or kwargs.get("ground_truth_flag", [])
    if not ground_truths:
        return [0.0] * len(completions)

    rewards = []
    for i, completion in enumerate(completions):
        gt = ground_truths[i] if i < len(ground_truths) else ""
        if not gt or not _is_real_flag(gt):
            rewards.append(0.0)
            continue

        text = _completion_to_text(completion)
        tool_calls = parse_tool_calls(text)

        found = False
        for tc in tool_calls:
            if tc["name"] in _FLAG_TOOLS:
                submitted = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
                if submitted.strip() == gt.strip():
                    found = True
                    break
        if not found:
            # Only count flag pattern if a flag submission tool was called
            has_flag_tool = any(tc["name"] in _FLAG_TOOLS for tc in tool_calls)
            if has_flag_tool:
                flags = extract_flags_from_text(text)
                found = any(f.strip() == gt.strip() for f in flags)

        rewards.append(1.0 if found else 0.0)

    return rewards


def progressive_reward(completions: list, **kwargs) -> list[float]:
    """v9 production reward: flag(0.85) + efficiency(0.10) + format(0.05).

    Flag-dominant weighting maintains ~0.90 RLOO solve/fail gap.
    Process signals (0.15) create within-group variance without
    compressing between-group gradient signal.

    Key mechanisms from open-trajectory-gym:
    - Physics-inspired efficiency: step_ratio × action_novelty × temporal_decay
    - Minimum work gate: <3 tool calls caps process signals
    - Hallucination energy loss: wrong flag decays ALL process signals
    - Premature hallucination penalty: earlier bad flags penalized more
    - Near-miss tolerance: similarity ≥ 0.8 reduces penalty 90%
    - Noise injection: ±0.01 prevents zero-variance batches
    """
    ground_truths = kwargs.get("ground_truth") or kwargs.get("ground_truth_flag", [])
    optimal_steps_list = kwargs.get("optimal_steps", [])
    rewards = []

    for i, completion in enumerate(completions):
        gt = ground_truths[i] if i < len(ground_truths) else ""
        opt_steps = optimal_steps_list[i] if i < len(optimal_steps_list) else None
        text = _completion_to_text(completion)
        tool_calls = parse_tool_calls(text)

        # --- Flag score (0.85 weight) ---
        flag_sc = _score_flag(text, gt, tool_calls)

        # --- Efficiency score (0.10 weight) ---
        eff_sc = _score_efficiency(
            len(tool_calls), opt_steps,
            flag_found=(flag_sc >= 1.0),
            tool_calls=tool_calls,
        )

        # --- Format score (0.05 weight) ---
        fmt_sc = _score_format(tool_calls)

        # --- Minimum work gate ---
        if len(tool_calls) < 3:
            fmt_sc = min(fmt_sc, 0.3)

        # --- Hallucination penalty (energy loss) ---
        hall_sc = _score_hallucination(tool_calls, flag_sc, gt)
        if hall_sc < 0:
            _DECAY = 0.3
            eff_sc *= _DECAY
            fmt_sc *= _DECAY

        # --- Weighted sum ---
        score = (
            0.85 * flag_sc
            + 0.10 * eff_sc
            + 0.05 * fmt_sc
            + hall_sc  # Additive penalty (already negative)
        )

        # Noise injection for variance guarantee
        score += _reward_rng.uniform(-0.01, 0.01)

        rewards.append(max(score, -1.0))

    return rewards


def _score_flag(text: str, gt: str, tool_calls: list[dict]) -> float:
    """Score flag capture. Returns 0.0, 0.1, or 1.0."""
    if not gt or not _is_real_flag(gt):
        return 0.0

    # Check flag submission tool calls
    has_flag_tool = False
    for tc in tool_calls:
        if tc["name"] in _FLAG_TOOLS:
            has_flag_tool = True
            submitted = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
            if submitted.strip() == gt.strip():
                return 1.0

    # Exact match in text (only if flag tool was called)
    if has_flag_tool and gt in text:
        return 1.0

    # Partial credit: flag-like pattern found (learning signal)
    if re.search(r"FLAG\{[a-zA-Z0-9_-]+\}", text):
        return 0.1

    return 0.0


def _score_efficiency(
    actual_steps: int,
    optimal_steps: int | None,
    flag_found: bool = False,
    tool_calls: list[dict] | None = None,
) -> float:
    """Physics-inspired efficiency: step_ratio × action_novelty × temporal_decay.

    Three components:
      1. Step ratio (classical efficiency): min(optimal/actual, 1.0)
      2. Action novelty (information redundancy): unique_fingerprints / total
      3. Temporal decay (time cost): exp(-λ × excess_steps / optimal)

    Non-flag completions capped at 0.3. <3 steps → 0.0.
    """
    if actual_steps < 3:
        return 0.0

    opt = optimal_steps or 10

    step_ratio = min(opt / actual_steps, 1.0)

    # Action novelty via fingerprinting
    if tool_calls and len(tool_calls) > 0:
        fingerprints = [_action_fingerprint(tc) for tc in tool_calls]
        novelty = len(set(fingerprints)) / len(fingerprints)
    else:
        novelty = 1.0

    # Temporal decay (λ=0.3)
    excess = max(0, actual_steps - opt) / max(opt, 1)
    time_decay = math.exp(-0.3 * excess)

    score = step_ratio * novelty * time_decay

    if not flag_found:
        return min(score, 0.3)
    return score


def _score_format(tool_calls: list[dict]) -> float:
    """Signal fidelity: valid instrument readings from known tools only."""
    if not tool_calls:
        return 0.0

    valid = 0
    known_count = 0
    for tc in tool_calls:
        name = tc.get("name", "")
        if name not in _KNOWN_TOOL_NAMES:
            continue
        known_count += 1
        args = tc.get("arguments", {})
        if isinstance(args, dict) and args:
            valid += 1
        elif args:
            valid += 0.5

    if known_count == 0:
        return 0.0
    return min(valid / known_count, 1.0)


def _score_hallucination(
    tool_calls: list[dict],
    flag_sc: float,
    gt: str | None,
) -> float:
    """Energy loss for false flag submissions.

    Returns negative penalty. Features:
    - Premature penalty: earlier bad flags penalized more (×1.0-2.0)
    - Near-miss tolerance: similarity ≥ 0.8 reduces penalty 90%
    """
    if flag_sc >= 1.0:
        return 0.0

    penalty = 0.20
    for tc in tool_calls:
        if tc["name"] in _FLAG_TOOLS:
            pen = -penalty

            # Premature submission multiplier
            premature_mult = 1.0 + max(0.0, 1.0 - len(tool_calls) / 5.0)
            pen *= premature_mult

            # Near-miss tolerance
            if gt and _is_real_flag(gt):
                submitted = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
                if submitted:
                    similarity = difflib.SequenceMatcher(
                        None, submitted.strip(), gt.strip()
                    ).ratio()
                    if similarity >= 0.8:
                        pen *= 0.1

            return pen

    return 0.0


def _completion_to_text(completion: Any) -> str:
    """Extract text from a TRL completion (string or message list)."""
    if isinstance(completion, str):
        return completion
    if isinstance(completion, list):
        parts = []
        for msg in completion:
            if isinstance(msg, dict):
                parts.append(msg.get("content", ""))
            elif isinstance(msg, str):
                parts.append(msg)
        return "\n".join(parts)
    return str(completion)


# ---------------------------------------------------------------------------
# Online reward (executes against OpenEnv environment)
# ---------------------------------------------------------------------------


def make_online_reward(env_url: str, timeout: float = 30.0):
    """Create a reward function that executes tool calls against an OpenEnv server.

    Args:
        env_url: Base URL of the OpenRange server (e.g. http://localhost:8000).
        timeout: HTTP request timeout in seconds.

    Returns:
        A reward function compatible with TRL GRPOTrainer.
    """
    import httpx

    def online_reward(completions: list, **kwargs) -> list[float]:
        ground_truths = kwargs.get("ground_truth") or kwargs.get("ground_truth_flag", [])
        rewards = []

        for i, completion in enumerate(completions):
            gt = ground_truths[i] if i < len(ground_truths) else ""
            text = _completion_to_text(completion)
            tool_calls = parse_tool_calls(text)

            episode_reward = 0.0
            try:
                # Reset environment for this episode
                with httpx.Client(base_url=env_url, timeout=timeout) as client:
                    client.post("/reset")

                    for tc in tool_calls:
                        name = tc["name"]
                        args = tc["arguments"]

                        # Map tool calls to RangeAction commands
                        if name in ("shell_command", "exec_command"):
                            command = args.get("command", "")
                        elif name in ("submit_flag", "flag_found"):
                            command = f"submit_flag {args.get('flag', args.get('value', ''))}"
                        elif name == "python_code":
                            command = f"python3 -c {json.dumps(args.get('code', ''))}"
                        elif name == "read_file":
                            command = f"cat {args.get('path', args.get('file', ''))}"
                        elif name == "grep":
                            pattern = args.get("pattern", "")
                            path = args.get("path", ".")
                            command = f"grep -r {json.dumps(pattern)} {path}"
                        else:
                            command = f"{name} {' '.join(str(v) for v in args.values())}"

                        resp = client.post("/step", json={
                            "command": command,
                            "mode": "red",
                        })
                        data = resp.json()
                        obs = data.get("observation", data)

                        reward = obs.get("reward", 0.0) or 0.0
                        episode_reward += reward

                        if obs.get("done", False):
                            break

                        # Check for flag capture
                        flags = obs.get("flags_captured", [])
                        if flags and gt and gt in flags:
                            episode_reward += 1.0
                            break

            except Exception as e:
                logger.warning("Online reward failed for sample %d: %s", i, e)
                # Fall back to text-based binary check
                episode_reward = binary_reward([completion], ground_truth=[gt])[0] * 0.5

            rewards.append(episode_reward)

        return rewards

    return online_reward


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


# OpenEnv tool definitions for chat template (activates qwen3_coder format)
OPENENV_TOOLS = [
    {"type": "function", "function": {"name": "shell_command", "description": "Execute a shell command",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "python_code", "description": "Execute Python code",
        "parameters": {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}}},
    {"type": "function", "function": {"name": "submit_flag", "description": "Submit a captured flag",
        "parameters": {"type": "object", "properties": {"flag": {"type": "string"}}, "required": ["flag"]}}},
    {"type": "function", "function": {"name": "submit_finding", "description": "Submit a security finding",
        "parameters": {"type": "object", "properties": {"description": {"type": "string"}}, "required": ["description"]}}},
    {"type": "function", "function": {"name": "read_file", "description": "Read a file",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "get_challenge", "description": "Get challenge briefing",
        "parameters": {"type": "object", "properties": {"role": {"type": "string", "default": "red"}}}}},
    {"type": "function", "function": {"name": "get_progress", "description": "Get current progress",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "check_services", "description": "Check service health",
        "parameters": {"type": "object", "properties": {}}}},
]


def load_grpo_data(
    data_paths: list[str | Path],
    tokenizer: Any,
) -> list[dict[str, Any]]:
    """Load online RL JSONL data for GRPO training.

    Each record should have:
    - messages: list of system/user messages (prompts only, no assistant)
    - ground_truth_flag: the correct flag for reward computation
    - metadata: optional challenge metadata

    CRITICAL: Passes tools= to apply_chat_template to activate qwen3_coder
    XML format. Without tools=, the model generates wrong format.

    Returns list of dicts with "prompt" (tokenized text) and "ground_truth".
    """
    from open_range.training.dataset import load_jsonl_records
    from open_range.training.sft_trainer import convert_messages_for_qwen35

    records = load_jsonl_records(data_paths)
    dataset = []
    skipped = 0

    for record in records:
        messages = record.get("messages", [])
        gt_flag = record.get("ground_truth_flag", "")

        if not messages:
            skipped += 1
            continue

        # Filter out placeholder flags
        if gt_flag and not _is_real_flag(gt_flag):
            logger.warning("Skipped sample with placeholder flag: %s", gt_flag)
            skipped += 1
            continue

        # Keep only system and user messages (prompts, no completions)
        prompt_messages = [m for m in messages if m.get("role") in ("system", "user")]
        if not prompt_messages:
            skipped += 1
            continue

        # Convert to qwen3_coder format
        converted = convert_messages_for_qwen35(prompt_messages)

        try:
            prompt_text = tokenizer.apply_chat_template(
                converted,
                tools=OPENENV_TOOLS,  # Activates qwen3_coder XML format
                tokenize=False,
                add_generation_prompt=True,
            )
            dataset.append({
                "prompt": prompt_text,
                "ground_truth": gt_flag,
            })
        except Exception as e:
            logger.warning("Skipped GRPO sample: %s", e)
            skipped += 1

    logger.info("Loaded %d GRPO prompts (%d skipped)", len(dataset), skipped)
    return dataset


# ---------------------------------------------------------------------------
# GRPO config
# ---------------------------------------------------------------------------


@dataclass
class GRPOConfig:
    """Configuration for Unsloth GRPO training."""

    model_name: str = "outputs/sft-merged"  # Start from SFT checkpoint
    max_seq_length: int = 4096
    load_in_4bit: bool = False
    load_in_16bit: bool = True

    # LoRA
    lora_r: int = 16
    lora_alpha: int = 16
    lora_dropout: float = 0
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])

    # GRPO specific
    num_generations: int = 4  # Completions per prompt for group scoring
    max_completion_length: int = 2048
    temperature: float = 0.7
    beta: float = 0.04  # KL penalty coefficient

    # Training
    epochs: int = 1
    batch_size: int = 1
    gradient_accumulation_steps: int = 4
    learning_rate: float = 5e-6  # Lower than SFT
    warmup_steps: int = 10
    weight_decay: float = 0.01
    lr_scheduler_type: str = "cosine"
    logging_steps: int = 1
    save_steps: int = 25
    save_total_limit: int = 2
    seed: int = 3407

    # Reward
    reward_mode: str = "progressive"  # "binary", "progressive", or "online"
    env_url: str | None = None  # Required for "online" mode

    # Data
    data_paths: list[str] = field(default_factory=list)

    # Output
    output_dir: str = "outputs/grpo"
    merge_output_dir: str | None = None


# ---------------------------------------------------------------------------
# Main GRPO training function
# ---------------------------------------------------------------------------


def run_grpo(config: GRPOConfig) -> dict[str, Any]:
    """Run Unsloth GRPO training.

    Returns dict with training stats.
    """
    import os
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

    from unsloth import FastLanguageModel
    from trl import GRPOTrainer, GRPOConfig as TRLGRPOConfig
    from datasets import Dataset

    # --- 1. Load model (no fast_inference — TRL 0.24.0 incompatible with vLLM 0.17.0) ---
    logger.info("Loading model: %s", config.model_name)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=config.model_name,
        max_seq_length=config.max_seq_length,
        load_in_4bit=config.load_in_4bit,
        load_in_16bit=config.load_in_16bit,
        full_finetuning=False,
        dtype=None,
    )

    # --- 2. Apply LoRA ---
    logger.info("Applying LoRA (r=%d, alpha=%d)", config.lora_r, config.lora_alpha)
    model = FastLanguageModel.get_peft_model(
        model,
        r=config.lora_r,
        target_modules=config.target_modules,
        lora_alpha=config.lora_alpha,
        lora_dropout=config.lora_dropout,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=config.seed,
        max_seq_length=config.max_seq_length,
    )

    # --- 3. Load data ---
    logger.info("Loading GRPO data from %d files", len(config.data_paths))
    raw_data = load_grpo_data(config.data_paths, tokenizer)

    if not raw_data:
        raise ValueError("No GRPO training samples loaded!")

    dataset = Dataset.from_dict({
        "prompt": [d["prompt"] for d in raw_data],
        "ground_truth": [d["ground_truth"] for d in raw_data],
    })
    logger.info("Dataset: %d prompts", len(dataset))

    # --- 4. Select reward function(s) ---
    if config.reward_mode == "binary":
        reward_funcs = [binary_reward]
        logger.info("Using binary reward (flag capture only)")
    elif config.reward_mode == "online":
        if not config.env_url:
            raise ValueError("env_url required for online reward mode")
        reward_funcs = [make_online_reward(config.env_url)]
        logger.info("Using online reward (env=%s)", config.env_url)
    else:  # progressive (default)
        reward_funcs = [progressive_reward]
        logger.info("Using progressive reward (6 signals)")

    # --- 5. Train ---
    logger.info("Starting GRPO training...")
    trainer = GRPOTrainer(
        model=model,
        processing_class=tokenizer,
        reward_funcs=reward_funcs,
        args=TRLGRPOConfig(
            output_dir=config.output_dir,
            num_generations=config.num_generations,
            max_completion_length=config.max_completion_length,
            per_device_train_batch_size=config.batch_size,
            gradient_accumulation_steps=config.gradient_accumulation_steps,
            num_train_epochs=config.epochs,
            warmup_steps=config.warmup_steps,
            learning_rate=config.learning_rate,
            weight_decay=config.weight_decay,
            lr_scheduler_type=config.lr_scheduler_type,
            logging_steps=config.logging_steps,
            save_steps=config.save_steps,
            save_total_limit=config.save_total_limit,
            seed=config.seed,
            bf16=True,
            report_to="none",
            beta=config.beta,
            temperature=config.temperature,
        ),
        train_dataset=dataset,
    )

    stats = trainer.train()
    logger.info("GRPO training complete! Loss: %.4f", stats.training_loss)

    # --- 6. Save LoRA adapter ---
    final_dir = str(Path(config.output_dir) / "final")
    logger.info("Saving LoRA adapter to %s", final_dir)
    model.save_pretrained(final_dir)
    tokenizer.save_pretrained(final_dir)

    # --- 7. Optionally merge ---
    if config.merge_output_dir:
        logger.info("Merging LoRA -> %s", config.merge_output_dir)
        model.save_pretrained_merged(
            config.merge_output_dir,
            tokenizer,
            save_method="merged_16bit",
        )
        logger.info("Merged model saved to %s", config.merge_output_dir)

    return {
        "training_loss": stats.training_loss,
        "num_prompts": len(raw_data),
        "max_seq_length": config.max_seq_length,
        "reward_mode": config.reward_mode,
        "lora_adapter": final_dir,
        "merged_model": config.merge_output_dir,
    }
