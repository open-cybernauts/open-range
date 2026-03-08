"""Typed OpenEnv client for OpenRange.

Falls back to lightweight stubs if openenv is not installed.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

try:
    from openenv.core.client_types import StepResult
    from openenv.core.env_client import EnvClient
except ImportError:
    from dataclasses import dataclass, field

    _A = TypeVar("_A")
    _O = TypeVar("_O")
    _S = TypeVar("_S")

    @dataclass
    class StepResult(Generic[_O]):  # type: ignore[no-redef]
        """Minimal stub matching openenv.core.client_types.StepResult."""

        observation: Any = None
        reward: float | int | None = None
        done: bool = False
        metadata: dict[str, Any] = field(default_factory=dict)

    class EnvClient(Generic[_A, _O, _S]):  # type: ignore[no-redef]
        """Minimal stub matching openenv.core.env_client.EnvClient."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

from open_range.server.models import RangeAction, RangeObservation, RangeState


class OpenRangeEnv(EnvClient[RangeAction, RangeObservation, RangeState]):
    """Typed OpenEnv client that speaks the standard reset/step/state contract."""

    def sync(self) -> "OpenRangeEnv":
        """Compatibility wrapper matching the documented OpenEnv sync pattern."""
        return self

    def _step_payload(self, action: RangeAction) -> dict:
        return {"command": action.command, "mode": action.mode}

    def _parse_result(self, payload: dict) -> StepResult[RangeObservation]:
        obs = RangeObservation(**payload.get("observation", {}))
        return StepResult(
            observation=obs,
            reward=payload.get("reward"),
            done=bool(payload.get("done", False)),
        )

    def _parse_state(self, payload: dict) -> RangeState:
        return RangeState(**payload)
