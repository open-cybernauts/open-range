"""Helpers for packaging OpenRange app bundles for external deployment."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

_SPACE_ID_ENV_VARS = ("OPENRANGE_HF_SPACE", "HF_SPACE")
_HF_TOKEN_ENV_VARS = (
    "HF_TOKEN",
    "HUGGINGFACEHUB_API_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
)
_IGNORE_PATTERNS = (
    ".git",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "*.pyc",
    ".DS_Store",
    "htmlcov",
    "build",
    "dist",
    "snapshots",
)


def resolve_space_id(space_id: str | None = None) -> str:
    """Resolve the target Hugging Face Space repo id."""
    resolved = (space_id or "").strip()
    if resolved:
        return resolved
    for env_name in _SPACE_ID_ENV_VARS:
        value = os.getenv(env_name, "").strip()
        if value:
            return value
    raise RuntimeError(
        "No Hugging Face Space configured. Pass --hf-space or set OPENRANGE_HF_SPACE."
    )


def resolve_hf_token(token: str | None = None) -> str:
    """Resolve an HF token from args or standard environment variables."""
    resolved = (token or "").strip()
    if resolved:
        return resolved
    for env_name in _HF_TOKEN_ENV_VARS:
        value = os.getenv(env_name, "").strip()
        if value:
            return value
    raise RuntimeError(
        "No Hugging Face token configured. Pass --hf-token or set HF_TOKEN."
    )


def stage_space_bundle(
    snapshot_path: str | Path,
    *,
    source_root: str | Path | None = None,
) -> Path:
    """Create a clean temporary Space bundle containing the validated snapshot."""
    snapshot_file = Path(snapshot_path).resolve()
    if not snapshot_file.exists():
        raise FileNotFoundError(f"Snapshot not found: {snapshot_file}")

    root = (
        Path(source_root).resolve()
        if source_root is not None
        else Path(__file__).resolve().parents[2]
    )
    bundle_dir = Path(tempfile.mkdtemp(prefix="openrange-hf-space-"))
    shutil.copytree(
        root,
        bundle_dir,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(*_IGNORE_PATTERNS),
    )

    target_snapshot = bundle_dir / SPACE_SNAPSHOT_PATH
    target_snapshot.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(snapshot_file, target_snapshot)
    return bundle_dir


def deploy_validated_snapshot_to_space(
    snapshot_path: str | Path,
    *,
    space_id: str | None = None,
    token: str | None = None,
    create_repo: bool = True,
    private: bool | None = None,
    commit_message: str | None = None,
) -> Any:
    """Reject direct HF snapshot deployment for Docker-only OpenRange."""
    raise RuntimeError(
        "Direct Hugging Face snapshot deployment is unsupported. "
        "OpenRange now requires Docker-backed execution and no longer "
        "ships the fixed-snapshot subprocess fallback. Deploy a proxy/UI "
        "to HF or use a Docker-capable backend instead."
    )
