"""OpenEnv app entrypoint expected by ``openenv.yaml``.

Thin wrapper that delegates to the real app factory in
``open_range.server.app``. This file lives at the repo root
so the Dockerfile CMD ``cd /app/env && uvicorn server.app:app``
resolves correctly inside HF Spaces.
"""

from __future__ import annotations

from open_range.server.app import create_app as _create_app

app = _create_app()


def main() -> None:
    """Run the repository-level server entrypoint via uvicorn."""
    import uvicorn

    uvicorn.run("server.app:app", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
