"""Tests for population-guided mutation selection policy."""

from __future__ import annotations

import asyncio
import json
import os
import random
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from open_range.builder.mutation_policy import (
    MutationPolicySettings,
    PopulationMutationPolicy,
    load_mutation_policy_settings,
)
from open_range.builder.snapshot_store import SnapshotStore
from open_range.protocols import BuildContext, MutationOp


def test_policy_selects_structural_and_security_when_both_available(sample_snapshot_spec):
    policy = PopulationMutationPolicy()
    structural = [
        MutationOp(
            mutation_id="add_service_web",
            op_type="add_service",
            target_selector={"host": "web"},
            params={"service": "redis"},
        )
    ]
    security = [
        MutationOp(
            mutation_id="seed_sqli",
            op_type="seed_vuln",
            target_selector={"host": "web"},
            params={"vuln_type": "sqli"},
        ),
        MutationOp(
            mutation_id="noise1",
            op_type="add_benign_noise",
            target_selector={"location": "siem:noise.log"},
            params={"location": "siem:noise.log"},
        ),
    ]

    ops, _score, _breakdown = policy.choose_mutations(
        structural_candidates=structural,
        security_candidates=security,
        snapshot=sample_snapshot_spec,
        context=BuildContext(seed=1, tier=1),
        rng=random.Random(7),
    )

    op_types = {op.op_type for op in ops}
    assert "add_service" in op_types
    assert op_types.intersection({"seed_vuln", "add_benign_noise"})


def test_policy_best_effort_when_only_security_available(sample_snapshot_spec):
    policy = PopulationMutationPolicy()
    security = [
        MutationOp(
            mutation_id="seed_sqli",
            op_type="seed_vuln",
            target_selector={"host": "web"},
            params={"vuln_type": "sqli"},
        ),
        MutationOp(
            mutation_id="noise1",
            op_type="add_benign_noise",
            target_selector={"location": "siem:noise.log"},
            params={"location": "siem:noise.log"},
        ),
    ]

    ops, _score, _breakdown = policy.choose_mutations(
        structural_candidates=[],
        security_candidates=security,
        snapshot=sample_snapshot_spec,
        context=BuildContext(seed=1, tier=1),
        rng=random.Random(11),
    )

    assert len(ops) == 1
    assert ops[0].op_type == "seed_vuln"


def test_policy_prefers_seed_vuln_over_benign_noise_when_available(sample_snapshot_spec):
    settings = MutationPolicySettings(
        profile_name="noise_biased",
        mutation={
            "curriculum_weight": 0.0,
            "novelty_weight": 0.0,
            "structural_gain_weight": 1.0,
            "lineage_weight": 0.0,
        },
        structural_gains={
            "add_service": 0.2,
            "add_dependency_edge": 0.2,
            "add_trust_edge": 0.2,
            "add_user": 0.2,
            "seed_vuln": 0.1,
            "add_benign_noise": 2.5,
            "default_gain": 0.0,
        },
    )
    policy = PopulationMutationPolicy(settings=settings)
    security = [
        MutationOp(
            mutation_id="seed_sqli",
            op_type="seed_vuln",
            target_selector={"host": "web"},
            params={"vuln_type": "sqli"},
        ),
        MutationOp(
            mutation_id="noise1",
            op_type="add_benign_noise",
            target_selector={"location": "siem:noise.log"},
            params={"location": "siem:noise.log"},
        ),
    ]

    ops, _score, _breakdown = policy.choose_mutations(
        structural_candidates=[],
        security_candidates=security,
        snapshot=sample_snapshot_spec,
        context=BuildContext(seed=1, tier=1),
        rng=random.Random(11),
    )

    assert len(ops) == 1
    assert ops[0].op_type == "seed_vuln"


def test_policy_best_effort_when_only_structural_available(sample_snapshot_spec):
    policy = PopulationMutationPolicy()
    structural = [
        MutationOp(
            mutation_id="add_trust_edge_1",
            op_type="add_trust_edge",
            target_selector={"source": "alice", "target": "bob"},
            params={"type": "delegation"},
        ),
        MutationOp(
            mutation_id="add_dep_1",
            op_type="add_dependency_edge",
            target_selector={"source": "web", "target": "db"},
            params={},
        ),
    ]

    ops, _score, _breakdown = policy.choose_mutations(
        structural_candidates=structural,
        security_candidates=[],
        snapshot=sample_snapshot_spec,
        context=BuildContext(seed=1, tier=1),
        rng=random.Random(21),
    )

    assert len(ops) == 1
    assert ops[0].op_type in {"add_trust_edge", "add_dependency_edge"}


def test_load_policy_settings_from_yaml(tmp_path: Path):
    settings_path = tmp_path / "policy.yaml"
    settings_path.write_text(
        "\n".join(
            [
                "profile_name: tuned_policy",
                "parent:",
                "  frontier_weight: 0.5",
                "mutation:",
                "  structural_gain_weight: 0.6",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_mutation_policy_settings(settings_path)

    assert settings.profile_name == "tuned_policy"
    assert settings.parent.frontier_weight == 0.5
    assert settings.mutation.structural_gain_weight == 0.6
    assert settings.structural_gains.add_service == 1.0


def test_parent_scores_expose_weighted_contributions(sample_snapshot_spec):
    policy = PopulationMutationPolicy()
    snapshot = sample_snapshot_spec.model_copy(deep=True)
    snapshot.lineage.root_snapshot_id = "root_a"
    entry = SimpleNamespace(snapshot_id="snap_a", snapshot=snapshot)

    score = policy.score_parents(
        [entry],
        context=BuildContext(seed=1, tier=1, weak_areas=["sqli"]),
        snapshot_stats={
            "snap_a": {
                "plays": 2,
                "plays_recent": 1,
                "red_solve_rate": 0.5,
                "blue_detect_rate": 0.25,
            }
        },
    )[0]

    assert score.weights["frontier"] == pytest.approx(
        policy.settings.parent.frontier_weight
    )
    assert score.contributions["frontier"] == pytest.approx(
        score.signals["frontier"] * score.weights["frontier"],
        rel=1e-3,
    )
    assert score.total == pytest.approx(sum(score.contributions.values()), rel=1e-3)


def test_custom_settings_change_candidate_ranking(sample_snapshot_spec):
    settings = MutationPolicySettings(
        profile_name="structural_gain_only",
        mutation={
            "curriculum_weight": 0.0,
            "novelty_weight": 0.0,
            "structural_gain_weight": 1.0,
            "lineage_weight": 0.0,
        },
        structural_gains={
            "add_service": 0.2,
            "add_dependency_edge": 0.2,
            "add_trust_edge": 0.2,
            "add_user": 0.2,
            "seed_vuln": 0.1,
            "add_benign_noise": 2.5,
            "default_gain": 0.0,
        },
    )
    policy = PopulationMutationPolicy(settings=settings)
    ranked = policy._rank_candidates(
        [
            MutationOp(
                mutation_id="seed_sqli",
                op_type="seed_vuln",
                target_selector={"host": "web"},
                params={"vuln_type": "sqli"},
            ),
            MutationOp(
                mutation_id="noise_1",
                op_type="add_benign_noise",
                target_selector={"location": "siem:noise.log"},
                params={"location": "siem:noise.log"},
            ),
        ],
        snapshot=sample_snapshot_spec,
        context=BuildContext(seed=1, tier=1),
    )

    assert ranked[0].op.op_type == "add_benign_noise"
    assert ranked[0].contributions["structural_gain"] == pytest.approx(
        ranked[0].total,
        rel=1e-3,
    )


def test_calibration_script_compares_default_and_custom_settings(
    tmp_path: Path,
    sample_snapshot_spec,
):
    store_dir = tmp_path / "snapshots"
    asyncio.run(SnapshotStore(str(store_dir)).store(sample_snapshot_spec, "snap_demo"))

    stats_path = tmp_path / "snapshot_stats.json"
    stats_path.write_text(
        json.dumps(
            {
                "snap_demo": {
                    "plays": 3,
                    "plays_recent": 1,
                    "red_solve_rate": 0.5,
                    "blue_detect_rate": 0.0,
                }
            }
        ),
        encoding="utf-8",
    )
    context_path = tmp_path / "context.json"
    context_path.write_text(
        BuildContext(seed=7, tier=2, weak_areas=["sqli"]).model_dump_json(indent=2),
        encoding="utf-8",
    )
    settings_path = tmp_path / "tuned.json"
    settings_path.write_text(
        MutationPolicySettings(
            profile_name="tuned",
            parent={"frontier_weight": 0.5},
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/calibrate_mutation_policy.py",
            "--store-dir",
            str(store_dir),
            "--stats",
            str(stats_path),
            "--context",
            str(context_path),
            "--settings",
            f"tuned={settings_path}",
        ],
        capture_output=True,
        check=False,
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONPATH": "src"},
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["snapshot_count"] == 1
    assert [policy["label"] for policy in payload["policies"]] == ["default", "tuned"]
    assert payload["policies"][0]["top_parents"][0]["snapshot_id"] == "snap_demo"
