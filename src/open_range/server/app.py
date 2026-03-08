"""FastAPI application for OpenRange.

Uses the OpenEnv app factory when openenv is installed, otherwise
creates a standalone FastAPI app with equivalent endpoints.
"""

from __future__ import annotations

import logging
import sys
import traceback

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create the OpenRange app.

    Tries the OpenEnv factory first; falls back to a standalone
    FastAPI app if openenv is not installed or if the runtime
    fails to initialise (e.g. missing manifest on HF Spaces).
    """
    from open_range.server.environment import RangeEnvironment
    from open_range.server.models import RangeAction, RangeObservation

    # Try to create the managed runtime (snapshot pool, validator, etc.)
    runtime = None
    try:
        from open_range.server.runtime import ManagedSnapshotRuntime
        runtime = ManagedSnapshotRuntime.from_env()
    except Exception:
        logger.warning(
            "ManagedSnapshotRuntime.from_env() failed — running without managed snapshots:\n%s",
            traceback.format_exc(),
        )

    def env_factory() -> RangeEnvironment:
        return RangeEnvironment(runtime=runtime)

    # Try OpenEnv factory first
    try:
        from openenv.core.env_server import create_app as create_openenv_app
        fastapp = create_openenv_app(
            env_factory,
            RangeAction,
            RangeObservation,
            env_name="open_range",
        )
    except Exception:
        logger.warning(
            "OpenEnv create_app failed — creating standalone FastAPI:\n%s",
            traceback.format_exc(),
        )
        fastapp = _create_standalone_app(env_factory)

    fastapp.state.env = env_factory()
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


def _create_standalone_app(
    env_factory: object,
) -> FastAPI:
    """Standalone FastAPI app with OpenEnv-compatible endpoints.

    Used when the openenv package is not available.
    """
    from open_range.server.models import RangeAction, RangeObservation

    fastapp = FastAPI(title="OpenRange", version="0.1.0")
    _env_holder: dict = {}

    def _get_env():
        if "env" not in _env_holder:
            _env_holder["env"] = env_factory()  # type: ignore[operator]
        return _env_holder["env"]

    @fastapp.get("/health")
    def health():
        return {"status": "healthy"}

    @fastapp.get("/metadata")
    def metadata():
        env = _get_env()
        return env.get_metadata()

    @fastapp.post("/reset")
    def reset(seed: int | None = None, episode_id: str | None = None):
        env = _get_env()
        obs = env.reset(seed=seed, episode_id=episode_id)
        return {"observation": obs.model_dump()}

    @fastapp.post("/step")
    def step(action: RangeAction):
        env = _get_env()
        obs = env.step(action)
        return {
            "observation": obs.model_dump(),
            "reward": obs.reward,
            "done": obs.done,
        }

    @fastapp.get("/state")
    def state():
        env = _get_env()
        return env.state.model_dump()

    return fastapp


def main() -> None:
    """Run the installed package entrypoint via uvicorn."""
    import uvicorn
    uvicorn.run("open_range.server.app:app", host="0.0.0.0", port=8000)


# Module-level app creation with error reporting
try:
    app = create_app()
except Exception:
    # If create_app fails entirely, print the error and create a minimal
    # health-only app so HF Spaces doesn't show "no logs".
    traceback.print_exc()
    print("[app.py] FATAL: create_app() failed. Creating minimal health endpoint.", file=sys.stderr)
    app = FastAPI(title="OpenRange (degraded)")

    @app.get("/health")
    def _health():
        return {"status": "degraded", "error": "App failed to initialize"}


if __name__ == "__main__":
    main()
