#!/usr/bin/env python3
"""Test Tier 1 snapshot generation with LLM Builder + local Docker.

Usage:
    export AZURE_API_KEY="..."
    export AZURE_API_BASE="..."
    export AZURE_API_VERSION="2025-04-01-preview"
    uv run python scripts/test_tier1_llm.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import yaml

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from open_range.builder.builder import LLMSnapshotBuilder
from open_range.protocols import BuildContext
from open_range.server.environment import RangeEnvironment
from open_range.server.models import RangeAction


def load_manifest(path: str = "manifests/tier1_basic.yaml") -> dict:
    """Load and return the tier1 manifest as a dict."""
    manifest_path = Path(__file__).resolve().parent.parent / path
    with open(manifest_path) as f:
        return yaml.safe_load(f)


async def build_snapshot(manifest: dict) -> object:
    """Call the LLM builder to generate a snapshot spec."""
    model = os.environ.get("OPENRANGE_BUILDER_MODEL", "azure/gpt-5.2-codex")
    print(f"\n{'='*60}")
    print(f"  BUILDER: Generating Tier 1 snapshot")
    print(f"  Model:   {model}")
    print(f"  API:     {os.environ.get('AZURE_API_BASE', 'not set')}")
    print(f"{'='*60}\n")

    # Codex models don't support temperature
    temp = None if "codex" in model.lower() else 0.7
    builder = LLMSnapshotBuilder(
        model=model,
        temperature=temp,
        max_retries=2,
        max_tokens=32768,
    )

    context = BuildContext(
        seed=42,
        tier=1,
        previous_vuln_classes=[],
        solve_rates={},
        weak_areas=[],
    )

    t0 = time.time()
    snapshot = await builder.build(manifest, context)
    elapsed = time.time() - t0

    print(f"Snapshot generated in {elapsed:.1f}s")
    print(f"  Topology hosts: {snapshot.topology.get('hosts', [])}")
    print(f"  Vulns:          {len(snapshot.truth_graph.vulns)}")
    for v in snapshot.truth_graph.vulns:
        print(f"    - {v.id}: {v.type} on {v.host} ({v.service})")
    print(f"  Flags:          {len(snapshot.flags)}")
    for f in snapshot.flags:
        print(f"    - {f.id}: {f.value[:30]}... @ {f.host}:{f.path}")
    print(f"  Golden path:    {len(snapshot.golden_path)} steps")
    for gp in snapshot.golden_path:
        print(f"    Step {gp.step}: {gp.command[:60]}")
    print(f"  Files:          {len(snapshot.files)} entries")
    for key in sorted(snapshot.files.keys()):
        size = len(snapshot.files[key])
        print(f"    - {key} ({size} chars)")
    print(f"  NPC personas:   {len(snapshot.npc_personas)}")
    print(f"  Task red:       {snapshot.task.red_briefing[:80]}...")
    print(f"  Task blue:      {snapshot.task.blue_briefing[:80]}...")

    return snapshot


def run_episode(snapshot, docker_mode: bool = False) -> dict:
    """Run a scripted episode against the generated snapshot."""
    print(f"\n{'='*60}")
    print(f"  EPISODE: Running against generated snapshot")
    print(f"  Docker:  {'yes' if docker_mode else 'mock mode'}")
    print(f"{'='*60}\n")

    env = RangeEnvironment(
        docker_available=docker_mode,
        max_steps=50,
    )

    # Reset with the LLM-generated snapshot
    obs = env.reset(snapshot=snapshot, episode_id="llm-tier1-test")
    print(f"[RESET] {obs.stdout[:200]}")
    print()

    # Use the golden path as a scripted Red agent
    golden_path = snapshot.golden_path
    if not golden_path:
        print("No golden path steps — cannot run scripted episode")
        return {"outcome": "no_golden_path", "steps": 0}

    step = 0
    for gp in golden_path:
        step += 1
        action = RangeAction(command=gp.command, mode="red")
        result = env.step(action)
        reward = result.reward if result.reward is not None else 0.0

        status = ""
        if result.flags_captured:
            status = f" FLAGS={result.flags_captured}"
        if result.done:
            status += " [DONE]"

        print(f"  [{step:2d}] RED >> {gp.command[:60]}")
        if docker_mode:
            # Show actual output in docker mode
            stdout_preview = result.stdout[:120].replace('\n', ' ')
            print(f"       stdout: {stdout_preview}")
        else:
            print(f"       expect: {gp.expect_in_stdout[:60]}")
        print(f"       reward={reward:.4f}{status}")

        if result.done:
            break

    # Final state
    state = env.state
    print(f"\n{'='*60}")
    print(f"  RESULT")
    print(f"{'='*60}")
    print(f"  Steps:       {state.step_count}")
    print(f"  Flags found: {state.flags_found}")
    print(f"  Tier:        {state.tier}")
    print(f"  Episode:     {state.episode_id}")
    print(f"{'='*60}\n")

    return {
        "outcome": "flag_captured" if state.flags_found else "no_flag",
        "steps": state.step_count,
        "flags_found": list(state.flags_found),
    }


def save_snapshot(snapshot, path: str = "snapshots/llm_tier1_test.json"):
    """Save the generated snapshot to disk for reuse."""
    out = Path(__file__).resolve().parent.parent / path
    out.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "topology": snapshot.topology,
        "truth_graph": {
            "vulns": [
                {
                    "id": v.id,
                    "type": v.type,
                    "host": v.host,
                    "service": v.service,
                    "injection_point": v.injection_point,
                    "vulnerable_code": v.vulnerable_code,
                    "root_cause": v.root_cause,
                    "blast_radius": v.blast_radius,
                    "remediation": v.remediation,
                }
                for v in snapshot.truth_graph.vulns
            ],
            "exploit_chain": [
                {"vuln_id": ec.vuln_id, "command": ec.command, "description": ec.description}
                for ec in snapshot.truth_graph.exploit_chain
            ],
        },
        "flags": [
            {"id": f.id, "value": f.value, "path": f.path, "host": f.host}
            for f in snapshot.flags
        ],
        "golden_path": [
            {
                "step": gp.step,
                "cmd": gp.command,
                "expect_stdout": gp.expect_in_stdout,
                "description": gp.description,
            }
            for gp in snapshot.golden_path
        ],
        "task": {
            "red_briefing": snapshot.task.red_briefing,
            "blue_briefing": snapshot.task.blue_briefing,
        },
        "npc_personas": [
            {
                "name": p.name,
                "role": p.role,
                "department": p.department,
                "security_awareness": p.security_awareness,
            }
            for p in snapshot.npc_personas
        ],
        "files": snapshot.files,
    }

    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Snapshot saved to {out}")


async def main():
    # Verify Azure creds are set
    required = ["AZURE_API_KEY", "AZURE_API_BASE"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        print(f"ERROR: Missing env vars: {missing}")
        print("Set AZURE_API_KEY and AZURE_API_BASE before running.")
        sys.exit(1)

    # Default to azure/gpt-5.2 if not overridden
    if not os.environ.get("OPENRANGE_BUILDER_MODEL"):
        os.environ["OPENRANGE_BUILDER_MODEL"] = "azure/gpt-5.2-codex"

    # Load manifest
    manifest = load_manifest()
    print(f"Loaded manifest: {manifest['name']} (tier {manifest['tier']})")
    print(f"  Bug families: {len(manifest['bug_families'])}")
    print(f"  Hosts: {[h['name'] for h in manifest['topology']['hosts']]}")

    # Build snapshot via LLM
    snapshot = await build_snapshot(manifest)

    # Save snapshot for reuse
    save_snapshot(snapshot)

    # Check if Docker compose stack is running
    docker_mode = False
    try:
        import docker
        client = docker.from_env()
        containers = client.containers.list()
        range_containers = [c for c in containers if "openrange" in c.name.lower() or "open-range" in c.name.lower()]
        if range_containers:
            print(f"\nFound {len(range_containers)} running range containers:")
            for c in range_containers:
                print(f"  - {c.name} ({c.status})")
            docker_mode = True
        else:
            print("\nNo range containers running — using mock mode")
            print("To run with Docker: docker compose up -d")
        client.close()
    except Exception:
        print("\nDocker SDK unavailable — using mock mode")

    # Run episode
    result = run_episode(snapshot, docker_mode=docker_mode)
    print(f"Final result: {json.dumps(result, indent=2)}")


if __name__ == "__main__":
    asyncio.run(main())
