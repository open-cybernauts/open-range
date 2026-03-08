"""Guardrail tests for OpenEnv contract compatibility."""

from __future__ import annotations

import importlib
from typing import Any

from fastapi import FastAPI
import openenv.core.env_server as openenv_env_server
import pytest
from pydantic import ValidationError

from open_range.client.client import OpenRangeEnv
from open_range.models import RangeAction, RangeObservation, RangeState
from open_range.server.environment import RangeEnvironment


class TestModelContract:
    def test_models_do_not_redeclare_inherited_openenv_fields(self):
        # These fields must stay inherited from OpenEnv base models.
        assert "metadata" not in RangeAction.__annotations__
        assert "done" not in RangeObservation.__annotations__
        assert "reward" not in RangeObservation.__annotations__
        assert "metadata" not in RangeObservation.__annotations__
        assert "episode_id" not in RangeState.__annotations__
        assert "step_count" not in RangeState.__annotations__

    def test_models_expose_inherited_openenv_fields(self):
        assert "metadata" in RangeAction.model_fields
        assert "done" in RangeObservation.model_fields
        assert "reward" in RangeObservation.model_fields
        assert "metadata" in RangeObservation.model_fields
        assert "episode_id" in RangeState.model_fields
        assert "step_count" in RangeState.model_fields

    def test_action_and_observation_reject_unknown_fields(self):
        with pytest.raises(ValidationError):
            RangeAction(command="whoami", mode="red", unknown_field="x")
        with pytest.raises(ValidationError):
            RangeObservation(stdout="ok", extra_field="x")

    def test_state_allows_unknown_fields(self):
        state = RangeState(step_count=1, extra_field="ok")
        assert state.extra_field == "ok"
        dumped = state.model_dump()
        assert dumped["extra_field"] == "ok"


class TestAppFactoryContract:
    def test_create_app_wires_openenv_factory_with_expected_types(self, monkeypatch):
        captured: dict[str, Any] = {}

        def fake_create_app(env_factory, action_type, observation_type, *, env_name):
            captured["env_factory"] = env_factory
            captured["action_type"] = action_type
            captured["observation_type"] = observation_type
            captured["env_name"] = env_name
            return FastAPI()

        monkeypatch.delenv("OPENRANGE_ENABLE_MANAGED_RUNTIME", raising=False)
        monkeypatch.delenv("OPENRANGE_RUNTIME_MANIFEST", raising=False)
        monkeypatch.setattr(openenv_env_server, "create_app", fake_create_app)

        app_module = importlib.import_module("open_range.server.app")

        app = app_module.create_app()

        assert isinstance(app, FastAPI)
        assert captured["action_type"] is RangeAction
        assert captured["observation_type"] is RangeObservation
        assert captured["env_name"] == "open_range"
        assert callable(captured["env_factory"])
        assert isinstance(captured["env_factory"](), RangeEnvironment)
        assert isinstance(app.state.env, RangeEnvironment)

    def test_create_app_exposes_required_openenv_routes(self, monkeypatch):
        monkeypatch.delenv("OPENRANGE_ENABLE_MANAGED_RUNTIME", raising=False)
        monkeypatch.delenv("OPENRANGE_RUNTIME_MANIFEST", raising=False)
        app_module = importlib.import_module("open_range.server.app")

        app = app_module.create_app()
        paths = {route.path for route in app.router.routes}
        required_paths = {"/health", "/metadata", "/schema", "/reset", "/step", "/state", "/ws"}
        assert required_paths.issubset(paths)


class TestClientContract:
    def test_step_payload_matches_server_contract(self):
        client = OpenRangeEnv(base_url="http://localhost:8000")
        payload = client._step_payload(
            RangeAction(command="nmap -sV web", mode="red", metadata={"source": "test"})
        )
        assert payload == {"command": "nmap -sV web", "mode": "red"}

    def test_parse_result_uses_observation_and_top_level_done_reward(self):
        client = OpenRangeEnv(base_url="http://localhost:8000")
        result = client._parse_result(
            {
                "observation": {
                    "stdout": "ok",
                    "stderr": "",
                    "done": False,
                    "reward": 0.1,
                    "flags_captured": ["FLAG{a}"],
                },
                "done": 1,
                "reward": 0.75,
            }
        )
        assert isinstance(result.observation, RangeObservation)
        assert result.observation.stdout == "ok"
        assert result.observation.flags_captured == ["FLAG{a}"]
        assert result.done is True
        assert result.reward == 0.75

    def test_parse_state_round_trips_openenv_and_extended_state_fields(self):
        client = OpenRangeEnv(base_url="http://localhost:8000")
        state = client._parse_state(
            {
                "episode_id": "ep-123",
                "step_count": 4,
                "mode": "red",
                "tier": 2,
                "custom_key": "value",
            }
        )
        assert isinstance(state, RangeState)
        assert state.episode_id == "ep-123"
        assert state.step_count == 4
        assert state.mode == "red"
        assert state.tier == 2
        assert state.custom_key == "value"
