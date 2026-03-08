"""OpenEnv-compatible models for OpenRange.

RangeAction, RangeObservation, and RangeState extend the OpenEnv base
types. Falls back to Pydantic stubs if openenv is not installed.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

try:
    from openenv.core.env_server.types import Action, Observation, State
except ImportError:
    from pydantic import BaseModel, ConfigDict

    class Action(BaseModel):  # type: ignore[no-redef]
        model_config = ConfigDict(extra="forbid", validate_assignment=True)
        metadata: dict[str, Any] = Field(default_factory=dict)

    class Observation(BaseModel):  # type: ignore[no-redef]
        model_config = ConfigDict(extra="forbid", validate_assignment=True)
        done: bool = False
        reward: bool | int | float | None = None
        metadata: dict[str, Any] = Field(default_factory=dict)

    class State(BaseModel):  # type: ignore[no-redef]
        model_config = ConfigDict(extra="allow")
        episode_id: str | None = None
        step_count: int = Field(default=0, ge=0)


class RangeAction(Action):
    command: str
    mode: Literal["red", "blue"]


class RangeObservation(Observation):
    # done and reward inherited from Observation
    stdout: str = ""
    stderr: str = ""
    flags_captured: list[str] = Field(default_factory=list)
    alerts: list[str] = Field(default_factory=list)


class RangeState(State):
    # episode_id and step_count inherited from State
    mode: str = ""
    flags_found: list[str] = Field(default_factory=list)
    services_status: dict[str, Any] = Field(default_factory=dict)
    tier: int = 1
    # Auth scenario (#25): session tracking
    active_sessions: dict[str, str] = Field(default_factory=dict)  # host -> username
    auth_attempts: list[dict[str, Any]] = Field(default_factory=list)
    # Pivot mechanics (#26): access and lateral movement tracking
    access_grants: list[str] = Field(default_factory=list)  # ["host:service", ...]
    pivot_history: list[dict[str, str]] = Field(default_factory=list)  # [{from: "web", to: "db", via: "credential_reuse"}]
    # Task engine (#17): milestone tracking
    milestones_completed: list[str] = Field(default_factory=list)
