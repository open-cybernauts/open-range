"""Unsloth SFT trainer for OpenRange CTF trajectories.

Converts OpenAI-style tool_calls to qwen3_coder XML format for Qwen3.5 training.
No truncation — dynamically sizes sequence length to fit all data.

Usage::

    from open_range.training.sft_trainer import run_sft
    run_sft(
        model_name="Qwen/Qwen3.5-4B",
        data_paths=["data/sft.jsonl"],
        output_dir="outputs/sft",
    )

Or via CLI::

    openrange train sft --model Qwen/Qwen3.5-4B --data data/sft.jsonl
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Format conversion: OpenAI tool_calls → qwen3_coder XML
# ---------------------------------------------------------------------------


def _tool_calls_to_qwen3_coder(tool_calls: list[dict[str, Any]]) -> str:
    """Convert OpenAI-style tool_calls to qwen3_coder XML format.

    Input (OpenAI)::

        [{"id": "tc1", "type": "function",
          "function": {"name": "shell_command",
                       "arguments": '{"command": "ls -la"}'}}]

    Output (qwen3_coder)::

        <tool_call>
        <function=shell_command>
        <parameter=command>ls -la</parameter>
        </function>
        </tool_call>
    """
    parts = []
    for tc in tool_calls:
        func = tc.get("function", {})
        name = func.get("name", "unknown")
        args_raw = func.get("arguments", "{}")
        if isinstance(args_raw, str):
            try:
                args = json.loads(args_raw)
            except json.JSONDecodeError:
                args = {"input": args_raw}
        else:
            args = args_raw

        params = []
        for k, v in args.items():
            params.append(f"<parameter={k}>{v}</parameter>")

        parts.append(
            "<tool_call>\n"
            f"<function={name}>\n"
            + "\n".join(params) + "\n"
            "</function>\n"
            "</tool_call>"
        )
    return "\n".join(parts)


def convert_messages_for_qwen35(
    messages: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Convert OpenAI-format messages to flat ChatML-compatible messages.

    Handles:
    - assistant messages with tool_calls → content + qwen3_coder XML
    - tool role messages → user role with <tool_response> wrapper
    - preserves <think> tags in assistant content
    - preserves system/user/assistant roles
    """
    converted = []
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "") or ""
        tool_calls = msg.get("tool_calls")

        if role == "assistant" and tool_calls:
            # Merge thinking/content with qwen3_coder tool calls
            xml_calls = _tool_calls_to_qwen3_coder(tool_calls)
            if content:
                full_content = f"{content}\n\n{xml_calls}"
            else:
                full_content = xml_calls
            converted.append({"role": "assistant", "content": full_content})

        elif role == "tool":
            # Convert tool response to user message with wrapper
            tool_name = msg.get("name", "tool")
            converted.append({
                "role": "user",
                "content": f"<tool_response>\n{content}\n</tool_response>",
            })

        elif role in ("system", "user", "assistant"):
            converted.append({"role": role, "content": content})

    return converted


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_sft_data(
    data_paths: list[str | Path],
    tokenizer: Any,
    *,
    min_reward: float | None = None,
) -> list[str]:
    """Load JSONL SFT data and convert to tokenized text strings.

    Args:
        data_paths: Paths to JSONL files with OpenAI-format messages.
        tokenizer: HuggingFace tokenizer with apply_chat_template.
        min_reward: If set, filter samples below this reward threshold.

    Returns:
        List of formatted text strings ready for SFT.
    """
    from open_range.training.dataset import load_jsonl_records

    records = load_jsonl_records(data_paths)
    texts = []
    skipped = 0

    for record in records:
        # Optional reward filtering
        if min_reward is not None:
            reward = record.get("reward", record.get("metadata", {}).get("reward"))
            if reward is not None and reward < min_reward:
                skipped += 1
                continue

        messages = record.get("messages", [])
        if not messages:
            skipped += 1
            continue

        # Convert to qwen3_coder format
        converted = convert_messages_for_qwen35(messages)

        try:
            text = tokenizer.apply_chat_template(
                converted,
                tokenize=False,
                add_generation_prompt=False,
            )
            texts.append(text)
        except Exception as e:
            logger.warning("Skipped sample: %s", e)
            skipped += 1

    logger.info("Loaded %d samples (%d skipped)", len(texts), skipped)
    return texts


# ---------------------------------------------------------------------------
# SFT config
# ---------------------------------------------------------------------------


@dataclass
class SFTConfig:
    """Configuration for Unsloth SFT training."""

    model_name: str = "Qwen/Qwen3.5-4B"
    max_seq_length: int = 0  # 0 = auto-detect from data
    load_in_4bit: bool = False  # NOT recommended for Qwen3.5
    load_in_16bit: bool = True

    # LoRA (Unsloth official defaults)
    lora_r: int = 16
    lora_alpha: int = 16
    lora_dropout: float = 0
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])

    # Training
    epochs: int = 3
    batch_size: int = 2
    gradient_accumulation_steps: int = 4
    learning_rate: float = 2e-5
    warmup_steps: int = 10
    weight_decay: float = 0.01
    lr_scheduler_type: str = "cosine"
    optim: str = "adamw_8bit"
    logging_steps: int = 5
    save_steps: int = 50
    save_total_limit: int = 2
    seed: int = 3407

    # Data
    data_paths: list[str] = field(default_factory=list)
    min_reward: float | None = None

    # Output
    output_dir: str = "outputs/sft"
    merge_output_dir: str | None = None  # If set, also save merged model


# ---------------------------------------------------------------------------
# Main training function
# ---------------------------------------------------------------------------


def run_sft(config: SFTConfig) -> dict[str, Any]:
    """Run Unsloth SFT training following official Unsloth instructions.

    Returns dict with training stats.
    """
    import os
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

    from unsloth import FastLanguageModel
    from trl import SFTTrainer
    from trl import SFTConfig as TRLSFTConfig
    from datasets import Dataset

    # --- 1. Load model (Unsloth official pattern) ---
    logger.info("Loading model: %s", config.model_name)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=config.model_name,
        max_seq_length=config.max_seq_length or 8192,  # initial, may update
        load_in_4bit=config.load_in_4bit,
        load_in_16bit=config.load_in_16bit,
        full_finetuning=False,
        dtype=None,  # auto-detect
    )

    # --- 2. Load + format data ---
    logger.info("Loading SFT data from %d files", len(config.data_paths))
    texts = load_sft_data(
        config.data_paths,
        tokenizer,
        min_reward=config.min_reward,
    )

    if not texts:
        raise ValueError("No training samples loaded!")

    # Auto-detect max sequence length from data (no truncation)
    if config.max_seq_length == 0:
        token_lengths = [
            len(tokenizer.encode(t, add_special_tokens=False))
            for t in texts
        ]
        max_tokens = max(token_lengths)
        # Round up to next power of 2 for efficiency, cap at 131072
        seq_len = 1
        while seq_len < max_tokens:
            seq_len *= 2
        config.max_seq_length = min(seq_len, 131072)
        logger.info(
            "Auto sequence length: max=%d tokens → padded to %d",
            max_tokens, config.max_seq_length,
        )

        # Reload model with correct max_seq_length
        logger.info("Reloading model with max_seq_length=%d", config.max_seq_length)
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=config.model_name,
            max_seq_length=config.max_seq_length,
            load_in_4bit=config.load_in_4bit,
            load_in_16bit=config.load_in_16bit,
            full_finetuning=False,
            dtype=None,
        )

    # --- 3. Apply LoRA (Unsloth official config) ---
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

    # --- 4. Create dataset ---
    dataset = Dataset.from_dict({"text": texts})
    logger.info("Dataset: %d samples, max_seq_length=%d", len(dataset), config.max_seq_length)

    # --- 5. Train (Unsloth official pattern) ---
    logger.info("Starting SFT training...")
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        tokenizer=tokenizer,
        args=TRLSFTConfig(
            dataset_text_field="text",
            max_seq_length=config.max_seq_length,
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
            output_dir=config.output_dir,
            optim=config.optim,
            seed=config.seed,
            bf16=True,
            report_to="none",
            dataset_num_proc=1,
        ),
    )

    stats = trainer.train()
    logger.info("Training complete! Loss: %.4f", stats.training_loss)

    # --- 6. Save LoRA adapter ---
    final_dir = str(Path(config.output_dir) / "final")
    logger.info("Saving LoRA adapter to %s", final_dir)
    model.save_pretrained(final_dir)
    tokenizer.save_pretrained(final_dir)

    # --- 7. Optionally merge + save for vLLM ---
    if config.merge_output_dir:
        logger.info("Merging LoRA → %s", config.merge_output_dir)
        model.save_pretrained_merged(
            config.merge_output_dir,
            tokenizer,
            save_method="merged_16bit",
        )
        logger.info("Merged model saved to %s", config.merge_output_dir)

    return {
        "training_loss": stats.training_loss,
        "num_samples": len(texts),
        "max_seq_length": config.max_seq_length,
        "epochs": config.epochs,
        "lora_adapter": final_dir,
        "merged_model": config.merge_output_dir,
    }
