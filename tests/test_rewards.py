"""Tests for reward components -- Red and Blue operators."""

import pytest

from open_range.models import RangeAction, RangeObservation, RangeState
from open_range.protocols import SnapshotSpec
from open_range.server.rewards import (
    AvailabilityReward,
    ComplexityBonus,
    CompositeBlueReward,
    CompositeRedReward,
    DetectionReward,
    EfficiencyReward,
    FalsePositiveReward,
    FlagReward,
    HallucinationPenalty,
    PatchReward,
    StealthReward,
)


# ---------------------------------------------------------------------------
# Red rewards
# ---------------------------------------------------------------------------


class TestFlagReward:
    def test_correct_flag(self):
        r = FlagReward()
        assert r.score("FLAG{abc}", {"FLAG{abc}", "FLAG{def}"}) == 1.0

    def test_wrong_flag(self):
        r = FlagReward()
        assert r.score("FLAG{wrong}", {"FLAG{abc}"}) == 0.0

    def test_empty_submission(self):
        r = FlagReward()
        assert r.score("", {"FLAG{abc}"}) == 0.0


class TestHallucinationPenalty:
    def test_one_fake_flag(self):
        p = HallucinationPenalty()
        assert p.score(1) == -0.3

    def test_zero_hallucinations(self):
        p = HallucinationPenalty()
        assert p.score(0) == 0.0

    def test_multiple_hallucinations(self):
        p = HallucinationPenalty()
        assert p.score(3) == pytest.approx(-0.9)

    def test_penalty_value(self):
        assert HallucinationPenalty.PENALTY == -0.3


class TestEfficiencyReward:
    def test_step_zero(self):
        r = EfficiencyReward(gamma=0.95)
        assert r.score(0) == 1.0

    def test_decays_with_steps(self):
        r = EfficiencyReward(gamma=0.95)
        assert r.score(1) == pytest.approx(0.95)
        assert r.score(10) == pytest.approx(0.95 ** 10)

    def test_more_steps_less_reward(self):
        r = EfficiencyReward(gamma=0.95)
        assert r.score(5) > r.score(10) > r.score(20)


class TestStealthReward:
    def test_zero_detections_full_stealth(self):
        r = StealthReward()
        assert r.score(0, 10) == 1.0

    def test_all_detected_zero_stealth(self):
        r = StealthReward()
        assert r.score(10, 10) == 0.0

    def test_half_detected(self):
        r = StealthReward()
        assert r.score(5, 10) == pytest.approx(0.5)

    def test_no_actions(self):
        r = StealthReward()
        assert r.score(0, 0) == 1.0


class TestComplexityBonus:
    def test_tier_multipliers(self):
        b = ComplexityBonus()
        assert b.multiplier(1) == 1.0
        assert b.multiplier(2) == 1.5
        assert b.multiplier(3) == 2.0
        assert b.multiplier(4) == 2.5
        assert b.multiplier(5) == 3.0

    def test_unknown_tier_defaults_to_1(self):
        b = ComplexityBonus()
        assert b.multiplier(99) == 1.0


class TestCompositeRedReward:
    def test_positive_score_at_step_zero(self):
        r = CompositeRedReward()
        # At step 0, efficiency=1.0; no flag, no stealth coupling
        score = r.score(step_count=0, tier=1)
        assert score > 0

    def test_hallucination_reduces_score(self):
        r = CompositeRedReward()
        s_clean = r.score(step_count=0, tier=1, hallucinated_count=0)
        s_dirty = r.score(step_count=0, tier=1, hallucinated_count=1)
        assert s_dirty < s_clean

    def test_tier_scales_reward(self):
        r = CompositeRedReward()
        s1 = r.score(step_count=5, tier=1)
        s2 = r.score(step_count=5, tier=2)
        assert s2 > s1

    def test_compute_hallucination_penalty_is_step_scoped(self):
        r = CompositeRedReward()
        snapshot = SnapshotSpec()
        action = RangeAction(command="submit_flag FLAG{fake}", mode="red")
        obs = RangeObservation(stdout="Invalid flag")

        step1_state = RangeState(step_count=1, tier=1)
        step1_clean = r.compute(
            action,
            obs,
            step1_state,
            snapshot,
            {"red_history": [], "blue_history": [], "npc_traffic_log": []},
        )
        step1_with_halluc = r.compute(
            action,
            obs,
            step1_state,
            snapshot,
            {
                "red_history": [
                    {"step": 1, "type": "hallucinated_flag", "value": "FLAG{fake}"},
                ],
                "blue_history": [],
                "npc_traffic_log": [],
            },
        )
        assert step1_with_halluc - step1_clean == pytest.approx(HallucinationPenalty.PENALTY)

        step2_state = RangeState(step_count=2, tier=1)
        step2_base = r.compute(
            RangeAction(command="nmap web", mode="red"),
            RangeObservation(stdout=""),
            step2_state,
            snapshot,
            {
                "red_history": [
                    {"step": 2, "command": "nmap web", "cmd_name": "nmap"},
                ],
                "blue_history": [],
                "npc_traffic_log": [],
            },
        )
        step2_with_old_halluc = r.compute(
            RangeAction(command="nmap web", mode="red"),
            RangeObservation(stdout=""),
            step2_state,
            snapshot,
            {
                "red_history": [
                    {"step": 1, "type": "hallucinated_flag", "value": "FLAG{fake}"},
                    {"step": 2, "command": "nmap web", "cmd_name": "nmap"},
                ],
                "blue_history": [],
                "npc_traffic_log": [],
            },
        )
        assert step2_with_old_halluc == pytest.approx(step2_base)


# ---------------------------------------------------------------------------
# Blue rewards
# ---------------------------------------------------------------------------


class TestDetectionReward:
    def test_perfect_detection(self):
        d = DetectionReward()
        assert d.score(10, 10) == 1.0

    def test_no_detection(self):
        d = DetectionReward()
        assert d.score(0, 10) == 0.0

    def test_partial_detection(self):
        d = DetectionReward()
        assert d.score(3, 10) == pytest.approx(0.3)

    def test_no_red_actions_returns_zero(self):
        """With no Red actions, detection is 0.0 (nothing to detect)."""
        d = DetectionReward()
        assert d.score(0, 0) == 0.0


class TestPatchReward:
    def test_exploit_blocked(self):
        p = PatchReward()
        assert p.score(True) == 1.0

    def test_exploit_not_blocked(self):
        p = PatchReward()
        assert p.score(False) == 0.0


class TestAvailabilityReward:
    def test_all_healthy(self):
        a = AvailabilityReward()
        assert a.score(8, 8) == 1.0

    def test_half_healthy(self):
        a = AvailabilityReward()
        assert a.score(4, 8) == pytest.approx(0.5)

    def test_none_healthy(self):
        a = AvailabilityReward()
        assert a.score(0, 8) == 0.0

    def test_no_services(self):
        a = AvailabilityReward()
        assert a.score(0, 0) == 1.0


class TestFalsePositiveReward:
    def test_no_false_positives(self):
        f = FalsePositiveReward()
        assert f.score(0) == 0.0

    def test_one_false_positive(self):
        f = FalsePositiveReward()
        assert f.score(1) == -0.2

    def test_multiple_false_positives(self):
        f = FalsePositiveReward()
        assert f.score(3) == pytest.approx(-0.6)


class TestCompositeBlueReward:
    def test_perfect_defense(self):
        r = CompositeBlueReward()
        score = r.score(
            true_positives=10,
            total_red_actions=10,
            exploit_blocked=True,
            healthy_services=8,
            total_services=8,
            false_positives=0,
            tier=1,
        )
        assert score > 0

    def test_tier_scales_blue_reward(self):
        r = CompositeBlueReward()
        s1 = r.score(true_positives=5, total_red_actions=10, tier=1)
        s2 = r.score(true_positives=5, total_red_actions=10, tier=2)
        assert s2 > s1

    def test_false_positives_reduce_reward(self):
        r = CompositeBlueReward()
        s_clean = r.score(true_positives=5, total_red_actions=10, false_positives=0)
        s_noisy = r.score(true_positives=5, total_red_actions=10, false_positives=5)
        assert s_noisy < s_clean

    def test_compute_detection_ignores_ungrounded_findings(self):
        r = CompositeBlueReward()
        action = RangeAction(command="submit_finding attack found", mode="blue")
        obs = RangeObservation(stdout="")
        state = RangeState(step_count=2, tier=1, services_status={"web": "healthy"})
        snapshot = SnapshotSpec()
        red_history = [{"step": 1, "command": "nmap -sV web", "cmd_name": "nmap", "target": "attacker"}]

        ungrounded = r.compute(
            action,
            obs,
            state,
            snapshot,
            {
                "red_history": red_history,
                "blue_history": [{"type": "finding", "content": "attack found", "grounded": False}],
                "npc_traffic_log": [],
            },
        )
        grounded = r.compute(
            action,
            obs,
            state,
            snapshot,
            {
                "red_history": red_history,
                "blue_history": [{"type": "finding", "content": "nmap scan on web", "grounded": True}],
                "npc_traffic_log": [],
            },
        )
        assert grounded > ungrounded

    def test_compute_patch_requires_validation_signal(self):
        r = CompositeBlueReward()
        action = RangeAction(command="patch -p1 < fix.diff", mode="blue")
        obs = RangeObservation(stdout="")
        state = RangeState(step_count=3, tier=1, services_status={"web": "healthy"})
        snapshot = SnapshotSpec()

        baseline = r.compute(
            action,
            obs,
            state,
            snapshot,
            {"red_history": [], "blue_history": [], "npc_traffic_log": []},
        )
        patch_cmd_only = r.compute(
            action,
            obs,
            state,
            snapshot,
            {
                "red_history": [],
                "blue_history": [{"cmd_name": "patch", "command": "patch -p1 < fix.diff"}],
                "npc_traffic_log": [],
            },
        )
        validated = r.compute(
            action,
            obs,
            state,
            snapshot,
            {
                "red_history": [],
                "blue_history": [{"cmd_name": "patch", "command": "patch -p1 < fix.diff"}],
                "npc_traffic_log": [],
                "patch_validated": True,
            },
        )

        assert patch_cmd_only == pytest.approx(baseline)
        assert validated > patch_cmd_only
