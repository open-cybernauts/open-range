"""FastAPI application for OpenRange."""

from __future__ import annotations

import logging
import os
from types import SimpleNamespace

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create the OpenRange app.

    Production startup is fail-closed:
    - managed runtime initialization errors propagate
    - OpenEnv app factory errors propagate
    - mock mode must be explicitly requested via ``OPENRANGE_MOCK=1``
    """
    from open_range.server.environment import RangeEnvironment
    from open_range.server.models import RangeAction, RangeObservation

    mock_mode = os.getenv("OPENRANGE_MOCK", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    runtime = None
    if not mock_mode:
        from open_range.server.runtime import ManagedSnapshotRuntime

        runtime = ManagedSnapshotRuntime.from_env()

    def env_factory() -> RangeEnvironment:
        if mock_mode:
            return RangeEnvironment(docker_available=False)
        return RangeEnvironment(runtime=runtime)

    from openenv.core.env_server import create_app as create_openenv_app

    fastapp = create_openenv_app(
        env_factory,
        RangeAction,
        RangeObservation,
        env_name="open_range",
    )

    fastapp.state.env = env_factory()
    fastapp.state.openenv_server = SimpleNamespace(
        _env_factory=env_factory,
        _sessions={},
        _session_info={},
        active_sessions=0,
    )
    if runtime is not None:
        fastapp.state.runtime = runtime
        fastapp.add_event_handler("startup", runtime.start)
        fastapp.add_event_handler("shutdown", runtime.stop)

    try:
        from open_range.server.console import console_router
        fastapp.include_router(console_router)
    except Exception:
        pass  # Console router is optional

    return fastapp


def main() -> None:
    """Run the installed package entrypoint via uvicorn."""
    import uvicorn
    uvicorn.run("open_range.server.app:app", host="0.0.0.0", port=8000)


app = create_app()


if __name__ == "__main__":
    main()
