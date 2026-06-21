"""Event-grounded reward logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from open_range.runtime_types import Action


_RED_MILESTONES = frozenset(
    {
        "InitialAccess",
        "CredentialObtained",
        "CrossZoneTraversal",
        "SensitiveAssetRead",
    }
)

# Objective predicates emitted exclusively by the email social-engineering
# channel.  Matched against linked_objective_predicates for bonus shaping.
_EMAIL_CHANNEL_PREDICATES = frozenset({"initial_access_via_email"})


@dataclass
class RewardEngine:
    """Terminal-first reward shaping with event-grounded updates."""

    red_tick_cost: float = -0.01
    continuity_penalty_scale: float = 0.2
    red_paid_milestones: set[str] = field(default_factory=set)
    blue_detected_events: set[str] = field(default_factory=set)
    blue_contained_targets: set[str] = field(default_factory=set)

    def reset(self) -> None:
        self.red_paid_milestones.clear()
        self.blue_detected_events.clear()
        self.blue_contained_targets.clear()

    def on_red_action(
        self,
        action: Action,
        emitted: tuple[Any, ...],
        *,
        shaping_enabled: bool = True,
        hallucination_penalty_enabled: bool = True,
    ) -> float:
        reward = self.red_tick_cost if shaping_enabled else 0.0
        claim = str(action.payload.get("claim_objective", ""))
        if claim and hallucination_penalty_enabled:
            objective_hit = any(
                claim in event.linked_objective_predicates for event in emitted
            )
            if not objective_hit:
                reward -= 0.3
        for event in emitted:
            if (
                shaping_enabled
                and event.event_type in _RED_MILESTONES
                and event.event_type not in self.red_paid_milestones
            ):
                self.red_paid_milestones.add(event.event_type)
                reward += 0.1
            # Extra +0.05 shaping bonus when the InitialAccess came via the
            # email channel — rewards red for using social engineering.
            if shaping_enabled and event.event_type == "InitialAccess":
                for pred in getattr(event, "linked_objective_predicates", ()):
                    pred_name = pred.split("(")[0]
                    if pred_name in _EMAIL_CHANNEL_PREDICATES:
                        reward += 0.05
                        break
        return reward

    def on_blue_detection(
        self,
        malicious_event: Any | None,
        *,
        shaping_enabled: bool = True,
        false_positive_penalty_enabled: bool = True,
    ) -> float:
        if not shaping_enabled:
            return 0.0
        if malicious_event is None:
            return -0.1 if false_positive_penalty_enabled else 0.0
        key = malicious_event.id
        if key in self.blue_detected_events:
            return 0.0
        self.blue_detected_events.add(key)
        return 0.1

    def on_blue_containment(
        self,
        *,
        target: str,
        path_broken: bool,
        continuity_before: float,
        continuity_after: float,
        shaping_enabled: bool = True,
    ) -> float:
        reward = 0.0
        if (
            shaping_enabled
            and path_broken
            and target not in self.blue_contained_targets
        ):
            self.blue_contained_targets.add(target)
            reward += 0.2
        continuity_drop = max(0.0, continuity_before - continuity_after)
        reward -= continuity_drop * self.continuity_penalty_scale
        return reward

    @staticmethod
    def terminal_rewards(*, winner: str, done: bool) -> tuple[float, float]:
        if not done:
            return 0.0, 0.0
        if winner == "red":
            return 1.0, -1.0
        if winner == "blue":
            return -1.0, 1.0
        if winner in {"timeout", "failure"}:
            return -1.0, -1.0
        return -1.0, -1.0
