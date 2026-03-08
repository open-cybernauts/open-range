"""OpenRange CLI -- production command-line interface for the cybersecurity gymnasium.

Usage::

    openrange build -m manifests/tier1_basic.yaml
    openrange render -s snapshots/spec.json -o output/
    openrange validate -s snapshots/spec.json
    openrange deploy -s snapshots/spec.json
    openrange server --port 8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import click
import yaml

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%H:%M:%S"


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        stream=sys.stderr,
    )
    # Quiet noisy third-party loggers unless in verbose mode
    if not verbose:
        for name in ("httpx", "httpcore", "litellm", "urllib3", "docker"):
            logging.getLogger(name).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from synchronous Click context."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Shouldn't happen in a CLI, but be safe.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def _load_manifest(path: str) -> dict[str, Any]:
    """Load and return a YAML manifest as a dict."""
    p = Path(path)
    if not p.exists():
        click.echo(f"Error: manifest not found: {p}", err=True)
        sys.exit(1)
    with open(p) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        click.echo(f"Error: manifest must be a YAML mapping, got {type(data).__name__}", err=True)
        sys.exit(1)
    return data


def _load_snapshot(path: str) -> "SnapshotSpec":
    """Load a snapshot JSON file into a SnapshotSpec."""
    from open_range.protocols import SnapshotSpec

    p = Path(path)
    if not p.exists():
        click.echo(f"Error: snapshot not found: {p}", err=True)
        sys.exit(1)
    with open(p) as f:
        data = json.load(f)
    try:
        return SnapshotSpec.model_validate(data)
    except Exception as exc:
        click.echo(f"Error: invalid snapshot JSON: {exc}", err=True)
        sys.exit(1)


def _write_snapshot(spec: "SnapshotSpec", output_dir: Path) -> Path:
    """Write a SnapshotSpec to spec.json inside output_dir. Returns the file path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    dest = output_dir / "spec.json"
    dest.write_text(json.dumps(spec.model_dump(), indent=2, default=str))
    return dest


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
@click.version_option(package_name="openenv-open-range", prog_name="openrange")
def cli(verbose: bool) -> None:
    """OpenRange -- multi-agent cybersecurity gymnasium.

    Generate, validate, deploy, and serve Docker-based cyber ranges
    for adversarial Red/Blue agent training.
    """
    _configure_logging(verbose)


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


@cli.command()
@click.option("-m", "--manifest", required=True, type=click.Path(exists=True), help="Path to manifest YAML.")
@click.option("-o", "--output", default="./snapshots", type=click.Path(), help="Output directory for snapshot.")
@click.option("--model", default=None, help="LLM model (default: $OPENRANGE_BUILDER_MODEL or azure/gpt-5.2).")
@click.option("--tier", default=1, type=click.IntRange(1, 5), help="Tier level 1-5.")
@click.option("--seed", default=None, type=int, help="Random seed for reproducibility.")
@click.option("--template-only", is_flag=True, default=False, help="Skip LLM, use deterministic template builder.")
@click.option("--max-tokens", default=16384, type=int, help="Max tokens for LLM generation.")
def build(
    manifest: str,
    output: str,
    model: str | None,
    tier: int,
    seed: int | None,
    template_only: bool,
    max_tokens: int,
) -> None:
    """Generate a snapshot from a manifest YAML.

    Uses the LLM builder by default. Pass --template-only for a deterministic
    snapshot without any LLM calls (useful for testing).
    """
    from open_range.builder.builder import LLMSnapshotBuilder, TemplateOnlyBuilder
    from open_range.protocols import BuildContext

    manifest_data = _load_manifest(manifest)
    context = BuildContext(seed=seed, tier=tier)

    if template_only:
        builder = TemplateOnlyBuilder()
        click.echo(f"Building snapshot (template-only, tier {tier}) ...")
    else:
        resolved_model = model or os.environ.get("OPENRANGE_BUILDER_MODEL", "azure/gpt-5.2")
        builder = LLMSnapshotBuilder(model=resolved_model, max_tokens=max_tokens)
        click.echo(f"Building snapshot (model={resolved_model}, tier {tier}) ...")

    t0 = time.monotonic()
    try:
        spec = _run_async(builder.build(manifest_data, context))
    except Exception as exc:
        click.echo(f"Error: build failed: {exc}", err=True)
        sys.exit(1)
    elapsed = time.monotonic() - t0

    output_path = Path(output)
    dest = _write_snapshot(spec, output_path)

    n_vulns = len(spec.truth_graph.vulns)
    n_steps = len(spec.golden_path)
    n_flags = len(spec.flags)

    click.echo(f"Snapshot written to {dest}")
    click.echo(f"  Vulnerabilities: {n_vulns}")
    click.echo(f"  Golden path steps: {n_steps}")
    click.echo(f"  Flags: {n_flags}")
    click.echo(f"  Elapsed: {elapsed:.1f}s")


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


@cli.command()
@click.option("-s", "--snapshot", required=True, type=click.Path(exists=True), help="Path to snapshot JSON.")
@click.option("-o", "--output", required=True, type=click.Path(), help="Output directory for Docker artifacts.")
def render(snapshot: str, output: str) -> None:
    """Render a snapshot JSON into Docker artifacts (Dockerfiles, compose, configs)."""
    from open_range.builder.renderer import SnapshotRenderer

    spec = _load_snapshot(snapshot)
    renderer = SnapshotRenderer()
    output_path = Path(output)

    click.echo(f"Rendering snapshot to {output_path} ...")
    try:
        renderer.render(spec, output_path)
    except Exception as exc:
        click.echo(f"Error: render failed: {exc}", err=True)
        sys.exit(1)

    # List produced files
    if output_path.exists():
        artifacts = sorted(p.name for p in output_path.iterdir() if p.is_file())
        click.echo(f"Produced {len(artifacts)} artifacts:")
        for name in artifacts:
            click.echo(f"  {name}")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

# Canonical name -> check class. The order matches the 10-check pipeline.
_CHECK_REGISTRY: dict[str, str] = {
    "build_boot": "open_range.validator.build_boot.BuildBootCheck",
    "exploitability": "open_range.validator.exploitability.ExploitabilityCheck",
    "patchability": "open_range.validator.patchability.PatchabilityCheck",
    "evidence": "open_range.validator.evidence.EvidenceCheck",
    "reward_grounding": "open_range.validator.reward_grounding.RewardGroundingCheck",
    "isolation": "open_range.validator.isolation.IsolationCheck",
    "task_feasibility": "open_range.validator.task_feasibility.TaskFeasibilityCheck",
    "difficulty": "open_range.validator.difficulty.DifficultyCheck",
    "npc_consistency": "open_range.validator.npc_consistency.NPCConsistencyCheck",
    "realism_review": "open_range.validator.realism_review.RealismReviewCheck",
}

# Checks that require running Docker containers.
_DOCKER_CHECKS = {"build_boot", "exploitability", "patchability", "evidence"}


def _import_check(dotted: str) -> Any:
    """Import a check class by dotted path."""
    module_path, class_name = dotted.rsplit(".", 1)
    import importlib

    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


@cli.command()
@click.option("-s", "--snapshot", required=True, type=click.Path(exists=True), help="Path to snapshot JSON.")
@click.option("--checks", default=None, help="Comma-separated check names (default: all applicable).")
@click.option("--docker/--no-docker", default=False, help="Include Docker-dependent checks (requires running containers).")
def validate(snapshot: str, checks: str | None, docker: bool) -> None:
    """Run validator checks against a snapshot.

    By default runs only offline checks (no Docker required). Use --docker
    to include checks that need live containers.

    Available checks: build_boot, exploitability, patchability, evidence,
    reward_grounding, isolation, task_feasibility, difficulty,
    npc_consistency, realism_review.
    """
    from open_range.protocols import ContainerSet
    from open_range.validator.validator import ValidatorGate

    spec = _load_snapshot(snapshot)

    # Determine which checks to run
    if checks:
        names = [n.strip() for n in checks.split(",")]
        unknown = [n for n in names if n not in _CHECK_REGISTRY]
        if unknown:
            click.echo(f"Error: unknown checks: {', '.join(unknown)}", err=True)
            click.echo(f"Available: {', '.join(_CHECK_REGISTRY)}", err=True)
            sys.exit(1)
    else:
        if docker:
            names = list(_CHECK_REGISTRY)
        else:
            names = [n for n in _CHECK_REGISTRY if n not in _DOCKER_CHECKS]

    if not names:
        click.echo("No checks selected.")
        sys.exit(0)

    # Instantiate checks
    check_instances = []
    for name in names:
        cls = _import_check(_CHECK_REGISTRY[name])
        check_instances.append(cls())

    # Containers stub for offline mode, real discovery for docker mode
    containers = ContainerSet()

    gate = ValidatorGate(check_instances)
    click.echo(f"Running {len(check_instances)} checks ...")

    result = _run_async(gate.validate(spec, containers))

    # Print results
    for cr in result.checks:
        status = "PASS" if cr.passed else ("ADVISORY" if cr.advisory else "FAIL")
        line = f"  [{status}] {cr.name}"
        if cr.time_s > 0:
            line += f" ({cr.time_s:.2f}s)"
        click.echo(line)
        if cr.error:
            click.echo(f"         {cr.error}")

    click.echo("")
    if result.passed:
        click.echo(f"Validation PASSED ({result.total_time_s:.2f}s)")
    else:
        click.echo(f"Validation FAILED ({result.total_time_s:.2f}s)")
        sys.exit(1)


# ---------------------------------------------------------------------------
# deploy
# ---------------------------------------------------------------------------


@cli.command()
@click.option("-s", "--snapshot", required=True, type=click.Path(exists=True), help="Path to snapshot JSON.")
@click.option("--compose-dir", default=None, type=click.Path(), help="Directory containing docker-compose.yml (default: render into temp dir).")
def deploy(snapshot: str, compose_dir: str | None) -> None:
    """Deploy a snapshot to running Docker containers.

    Renders the snapshot into Docker artifacts and runs docker compose up.
    If --compose-dir is given, uses that directory; otherwise renders into
    a temporary directory alongside the snapshot.
    """
    import subprocess

    from open_range.builder.renderer import SnapshotRenderer

    spec = _load_snapshot(snapshot)

    if compose_dir:
        target = Path(compose_dir)
    else:
        target = Path(snapshot).parent / "deploy"

    # Render artifacts
    renderer = SnapshotRenderer()
    click.echo(f"Rendering Docker artifacts to {target} ...")
    try:
        renderer.render(spec, target)
    except Exception as exc:
        click.echo(f"Error: render failed: {exc}", err=True)
        sys.exit(1)

    compose_file = target / "docker-compose.yml"
    if not compose_file.exists():
        click.echo(f"Error: no docker-compose.yml found in {target}", err=True)
        sys.exit(1)

    click.echo("Starting containers with docker compose ...")
    try:
        proc = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d", "--build"],
            cwd=str(target),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        click.echo("Error: docker command not found. Is Docker installed and in PATH?", err=True)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        click.echo("Error: docker compose up timed out after 300s.", err=True)
        sys.exit(1)

    if proc.returncode != 0:
        click.echo(f"Error: docker compose up failed (exit {proc.returncode}):", err=True)
        if proc.stderr:
            click.echo(proc.stderr, err=True)
        sys.exit(1)

    click.echo("Containers started.")

    # Show running container status
    try:
        ps = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "ps", "--format", "table"],
            cwd=str(target),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if ps.stdout:
            click.echo(ps.stdout)
    except Exception:
        pass  # Non-critical


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind.")
@click.option("--port", default=8000, type=int, help="Port to listen on.")
@click.option("--mock/--no-mock", default=False, help="Use mock mode (no Docker required).")
def server(host: str, port: int, mock: bool) -> None:
    """Start the OpenEnv server.

    In mock mode, the environment simulates container interactions without
    requiring a running Docker stack.
    """
    import uvicorn

    if mock:
        os.environ["OPENRANGE_MOCK"] = "1"
        click.echo(f"Starting OpenRange server in MOCK mode on {host}:{port} ...")
    else:
        click.echo(f"Starting OpenRange server on {host}:{port} ...")

    try:
        uvicorn.run(
            "open_range.server.app:app",
            host=host,
            port=port,
            log_level="info",
        )
    except Exception as exc:
        click.echo(f"Error: server failed: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
