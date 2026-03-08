"""Population-aware parent and mutation selection policy.

The scoring settings live in :class:`MutationPolicySettings` so the runtime can
audit, tune, and swap heuristic weight sets without rewriting policy logic.
See ``docs/mutation_policy.md`` and ``scripts/calibrate_mutation_policy.py``.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from open_range.protocols import BuildContext, MutationOp, SnapshotSpec
from open_range.validator.graphs import compile_snapshot_graphs


class ParentScoreSettings(BaseModel):
    """Weights and shaping constants for parent selection.

    Each ``*_weight`` field controls how much that signal contributes to the
    final parent score. The remaining fields shape the raw signals before the
    weighted sum is applied.
    """

    model_config = ConfigDict(extra="forbid")

    frontier_weight: float = Field(
        default=0.28,
        description="Prefer snapshots near the current red/blue frontier.",
    )
    replay_weight: float = Field(
        default=0.18,
        description="Prefer under-played snapshots so the curriculum keeps exploring.",
    )
    novelty_weight: float = Field(
        default=0.16,
        description="Prefer rarer vulnerability mixes in the stored population.",
    )
    weak_overlap_weight: float = Field(
        default=0.18,
        description="Prefer parents that overlap the curriculum's known weak areas.",
    )
    lineage_balance_weight: float = Field(
        default=0.08,
        description="Avoid over-sampling a single root lineage.",
    )
    depth_balance_weight: float = Field(
        default=0.04,
        description="Prevent deep descendant chains from dominating parent choice.",
    )
    recency_weight: float = Field(
        default=0.04,
        description="De-prioritize parents used repeatedly in the recent window.",
    )
    complexity_weight: float = Field(
        default=0.04,
        description="Slightly prefer parents with richer structure to mutate from.",
    )
    minimum_total: float = Field(
        default=0.05,
        description="Lower bound used when sampling among low-scoring parents.",
    )
    unplayed_frontier_score: float = Field(
        default=0.40,
        description="Frontier score used before any play statistics exist.",
    )
    empty_vuln_novelty_score: float = Field(
        default=0.25,
        description="Novelty fallback for snapshots with no typed vulnerabilities.",
    )
    preferred_generation_depth: float = Field(
        default=3.0,
        description="Depth after which descendants start incurring a balance penalty.",
    )
    complexity_vuln_factor: float = Field(
        default=0.25,
        description="Complexity contribution per planted vulnerability.",
    )
    complexity_golden_path_factor: float = Field(
        default=0.03,
        description="Complexity contribution per golden-path step.",
    )
    complexity_dependency_edge_factor: float = Field(
        default=0.02,
        description="Complexity contribution per dependency edge.",
    )
    complexity_trust_edge_factor: float = Field(
        default=0.02,
        description="Complexity contribution per trust edge.",
    )
    complexity_cap: float = Field(
        default=1.0,
        description="Upper bound for the normalized complexity signal.",
    )

    def weights(self) -> dict[str, float]:
        return {
            "frontier": self.frontier_weight,
            "replay": self.replay_weight,
            "novelty": self.novelty_weight,
            "weak_overlap": self.weak_overlap_weight,
            "lineage_balance": self.lineage_balance_weight,
            "depth_balance": self.depth_balance_weight,
            "recency": self.recency_weight,
            "complexity": self.complexity_weight,
        }


class MutationScoreSettings(BaseModel):
    """Weights and sampling floor for mutation-op choice."""

    model_config = ConfigDict(extra="forbid")

    curriculum_weight: float = Field(
        default=0.38,
        description="Bias toward ops that target the current curriculum weakness.",
    )
    novelty_weight: float = Field(
        default=0.24,
        description="Bias toward ops that open new exploit surfaces.",
    )
    structural_gain_weight: float = Field(
        default=0.28,
        description="Bias toward ops that materially expand the scenario graph.",
    )
    lineage_weight: float = Field(
        default=0.10,
        description="Slightly favor mutations closer to the root lineage.",
    )
    minimum_total: float = Field(
        default=0.05,
        description="Lower bound used when sampling among low-scoring ops.",
    )

    def weights(self) -> dict[str, float]:
        return {
            "curriculum": self.curriculum_weight,
            "novelty": self.novelty_weight,
            "structural_gain": self.structural_gain_weight,
            "lineage": self.lineage_weight,
        }


class NoveltyBonusSettings(BaseModel):
    """Raw novelty bonuses applied before mutation weighting."""

    model_config = ConfigDict(extra="forbid")

    base_bonus: float = Field(
        default=0.40,
        description="Baseline novelty score for every candidate mutation.",
    )
    new_vuln_class_bonus: float = Field(
        default=1.0,
        description="Bonus when seeding a vulnerability class not seen recently.",
    )
    new_noise_surface_bonus: float = Field(
        default=0.50,
        description="Bonus when benign noise targets a new recent surface.",
    )
    structural_op_bonus: float = Field(
        default=0.40,
        description="Bonus for non-security ops that expand the topology or process graph.",
    )


class CurriculumBonusSettings(BaseModel):
    """Raw curriculum bonuses applied before mutation weighting."""

    model_config = ConfigDict(extra="forbid")

    base_bonus: float = Field(
        default=0.35,
        description="Baseline curriculum score for every candidate mutation.",
    )
    weak_area_bonus: float = Field(
        default=1.50,
        description="Bonus when a seeded vulnerability matches a weak area.",
    )
    new_vuln_bonus: float = Field(
        default=0.40,
        description="Bonus when a seeded vulnerability is new to this parent snapshot.",
    )
    chain_length_bonus: float = Field(
        default=0.60,
        description="Bonus for dependency/trust edges when longer exploit chains are required.",
    )
    focus_identity_bonus: float = Field(
        default=0.50,
        description="Bonus for identity-layer ops when curriculum focus is identity.",
    )
    focus_infra_bonus: float = Field(
        default=0.50,
        description="Bonus for infra-layer ops when curriculum focus is infra.",
    )
    focus_process_bonus: float = Field(
        default=0.40,
        description="Bonus for benign-noise ops when curriculum focus is process realism.",
    )


class StructuralGainSettings(BaseModel):
    """Normalized gain assigned to each mutation op type before weighting."""

    model_config = ConfigDict(extra="forbid")

    add_service: float = Field(
        default=1.0,
        description="Largest structural gain: introduces a new service node.",
    )
    add_dependency_edge: float = Field(
        default=0.90,
        description="High structural gain: adds an application/service dependency edge.",
    )
    add_trust_edge: float = Field(
        default=0.85,
        description="High structural gain: adds an identity or trust relationship.",
    )
    add_user: float = Field(
        default=0.80,
        description="Moderate structural gain: introduces a new principal into the graph.",
    )
    seed_vuln: float = Field(
        default=0.70,
        description="Security gain without changing topology shape dramatically.",
    )
    add_benign_noise: float = Field(
        default=0.30,
        description="Low structural gain: improves realism and observability noise.",
    )
    default_gain: float = Field(
        default=0.20,
        description="Fallback gain for unknown mutation op types.",
    )

    def gain_for(self, op_type: str) -> float:
        mapping = self.model_dump(exclude={"default_gain"})
        return float(mapping.get(op_type, self.default_gain))


class MutationPolicySettings(BaseModel):
    """Complete settings model for :class:`PopulationMutationPolicy`."""

    model_config = ConfigDict(extra="forbid")

    profile_name: str = Field(
        default="population_guided_v1",
        description="Human-readable policy profile name used in logs and metadata.",
    )
    parent: ParentScoreSettings = Field(default_factory=ParentScoreSettings)
    mutation: MutationScoreSettings = Field(default_factory=MutationScoreSettings)
    novelty: NoveltyBonusSettings = Field(default_factory=NoveltyBonusSettings)
    curriculum: CurriculumBonusSettings = Field(default_factory=CurriculumBonusSettings)
    structural_gains: StructuralGainSettings = Field(default_factory=StructuralGainSettings)


def load_mutation_policy_settings(path: str | Path) -> MutationPolicySettings:
    """Load policy settings from JSON or YAML."""
    settings_path = Path(path)
    raw_text = settings_path.read_text(encoding="utf-8")
    if settings_path.suffix.lower() in {".yaml", ".yml"}:
        payload = yaml.safe_load(raw_text) or {}
    else:
        payload = json.loads(raw_text)
    if not isinstance(payload, dict):
        raise ValueError(f"settings file must decode to an object: {settings_path}")
    return MutationPolicySettings.model_validate(payload)


@dataclass(frozen=True, slots=True)
class ParentPolicyScore:
    snapshot_id: str
    total: float
    signals: dict[str, float]
    weights: dict[str, float]
    contributions: dict[str, float]

    def log_payload(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "total": self.total,
            "signals": self.signals,
            "weights": self.weights,
            "contributions": self.contributions,
        }


@dataclass(frozen=True, slots=True)
class MutationChoice:
    op: MutationOp
    total: float
    signals: dict[str, float]
    weights: dict[str, float]
    contributions: dict[str, float]

    def log_payload(self) -> dict[str, Any]:
        return {
            "mutation_id": self.op.mutation_id,
            "op_type": self.op.op_type,
            "total": self.total,
            "signals": self.signals,
            "weights": self.weights,
            "contributions": self.contributions,
        }


class PopulationMutationPolicy:
    """Population-guided policy with explicit, swappable scoring settings."""

    def __init__(self, settings: MutationPolicySettings | None = None) -> None:
        self.settings = settings or MutationPolicySettings()

    @property
    def name(self) -> str:
        return self.settings.profile_name

    def settings_dict(self) -> dict[str, Any]:
        """Return the active settings as a plain dict for logging or serialization."""
        return self.settings.model_dump(mode="json")

    def select_parent(
        self,
        entries: list[Any],
        *,
        context: BuildContext,
        snapshot_stats: dict[str, dict[str, Any]],
        rng: random.Random,
    ) -> tuple[Any, ParentPolicyScore]:
        scores = self.score_parents(
            entries,
            context=context,
            snapshot_stats=snapshot_stats,
        )
        if not scores:
            raise ValueError("No parent candidates available")
        ordered = sorted(scores, key=lambda score: score.total, reverse=True)
        top = ordered[: min(3, len(ordered))]
        weights = [max(score.total, self.settings.parent.minimum_total) for score in top]
        chosen_score = rng.choices(top, weights=weights, k=1)[0]
        chosen_entry = next(
            entry for entry in entries if entry.snapshot_id == chosen_score.snapshot_id
        )
        return chosen_entry, chosen_score

    def score_parents(
        self,
        entries: list[Any],
        *,
        context: BuildContext,
        snapshot_stats: dict[str, dict[str, Any]],
    ) -> list[ParentPolicyScore]:
        if not entries:
            return []

        parent_settings = self.settings.parent
        parent_weights = parent_settings.weights()
        root_counts = Counter(
            entry.snapshot.lineage.root_snapshot_id or entry.snapshot_id
            for entry in entries
        )
        vuln_frequency = Counter()
        for entry in entries:
            vuln_frequency.update(v.type for v in entry.snapshot.truth_graph.vulns if v.type)

        scores: list[ParentPolicyScore] = []
        for entry in entries:
            snapshot = entry.snapshot
            stat = snapshot_stats.get(entry.snapshot_id, {})
            vuln_types = {v.type for v in snapshot.truth_graph.vulns if v.type}
            compiled = compile_snapshot_graphs(snapshot)

            plays = float(stat.get("plays", 0))
            red_rate = float(stat.get("red_solve_rate", 0.0))
            blue_rate = float(stat.get("blue_detect_rate", 0.0))
            frontier = (
                parent_settings.unplayed_frontier_score
                if plays == 0
                else (
                    self._frontier_score(red_rate)
                    + self._frontier_score(blue_rate)
                )
                / 2.0
            )
            replay = 1.0 / (plays + 1.0)
            novelty = (
                1.0 / (1.0 + sum(vuln_frequency[vuln] for vuln in vuln_types))
                if vuln_types
                else parent_settings.empty_vuln_novelty_score
            )
            weak_overlap = float(len(vuln_types.intersection(context.weak_areas)))
            root_id = snapshot.lineage.root_snapshot_id or entry.snapshot_id
            lineage_balance = 1.0 / max(root_counts[root_id], 1)
            depth = float(snapshot.lineage.generation_depth)
            depth_balance = 1.0 / (
                1.0 + max(depth - parent_settings.preferred_generation_depth, 0.0)
            )
            recency = 1.0 / (1.0 + float(stat.get("plays_recent", 0)))
            complexity = min(
                (
                    len(snapshot.truth_graph.vulns) * parent_settings.complexity_vuln_factor
                    + len(snapshot.golden_path) * parent_settings.complexity_golden_path_factor
                    + len(compiled.dependency_edges)
                    * parent_settings.complexity_dependency_edge_factor
                    + len(compiled.trust_edges)
                    * parent_settings.complexity_trust_edge_factor
                ),
                parent_settings.complexity_cap,
            )

            signals = {
                "frontier": frontier,
                "replay": replay,
                "novelty": novelty,
                "weak_overlap": weak_overlap,
                "lineage_balance": lineage_balance,
                "depth_balance": depth_balance,
                "recency": recency,
                "complexity": complexity,
            }
            contributions = self._weighted_contributions(signals, parent_weights)
            total = round(
                max(sum(contributions.values()), parent_settings.minimum_total),
                4,
            )
            scores.append(
                ParentPolicyScore(
                    snapshot_id=entry.snapshot_id,
                    total=total,
                    signals=self._round_dict(signals),
                    weights=self._round_dict(parent_weights),
                    contributions=self._round_dict(contributions),
                )
            )
        return scores

    def choose_mutations(
        self,
        *,
        structural_candidates: list[MutationOp],
        security_candidates: list[MutationOp],
        snapshot: SnapshotSpec,
        context: BuildContext,
        rng: random.Random,
    ) -> tuple[list[MutationOp], float, dict[str, float]]:
        structural = self._select_candidate(
            structural_candidates,
            snapshot=snapshot,
            context=context,
            rng=rng,
        )

        security = self._select_candidate(
            security_candidates,
            snapshot=snapshot,
            context=context,
            rng=rng,
        )
        seed_security_candidates = [
            candidate
            for candidate in security_candidates
            if candidate.op_type == "seed_vuln"
        ]
        if (
            seed_security_candidates
            and (security is None or security.op.op_type != "seed_vuln")
        ):
            forced_seed = self._select_candidate(
                seed_security_candidates,
                snapshot=snapshot,
                context=context,
                rng=rng,
                deterministic=True,
            )
            if forced_seed is not None:
                security = forced_seed

        selected: list[MutationChoice] = []
        if structural is not None:
            selected.append(structural)
        if security is not None:
            selected.append(security)

        if not selected and structural_candidates:
            fallback = self._select_candidate(
                structural_candidates,
                snapshot=snapshot,
                context=context,
                rng=rng,
                deterministic=True,
            )
            if fallback is not None:
                selected.append(fallback)
        if not selected and security_candidates:
            fallback = self._select_candidate(
                security_candidates,
                snapshot=snapshot,
                context=context,
                rng=rng,
                deterministic=True,
            )
            if fallback is not None:
                selected.append(fallback)

        ops = [choice.op for choice in selected]
        if not ops:
            return [], 0.0, {}

        breakdown = {
            "curriculum": round(sum(c.contributions["curriculum"] for c in selected), 4),
            "novelty": round(sum(c.contributions["novelty"] for c in selected), 4),
            "structural_gain": round(sum(c.contributions["structural_gain"] for c in selected), 4),
            "lineage": round(sum(c.contributions["lineage"] for c in selected), 4),
        }
        total = round(sum(choice.total for choice in selected), 4)
        return ops, total, breakdown

    def _select_candidate(
        self,
        candidates: list[MutationOp],
        *,
        snapshot: SnapshotSpec,
        context: BuildContext,
        rng: random.Random,
        deterministic: bool = False,
    ) -> MutationChoice | None:
        ranked = self._rank_candidates(
            candidates,
            snapshot=snapshot,
            context=context,
        )
        if not ranked:
            return None
        if deterministic or len(ranked) == 1:
            return ranked[0]
        top = ranked[: min(3, len(ranked))]
        weights = [max(choice.total, self.settings.mutation.minimum_total) for choice in top]
        return rng.choices(top, weights=weights, k=1)[0]

    def _rank_candidates(
        self,
        candidates: list[MutationOp],
        *,
        snapshot: SnapshotSpec,
        context: BuildContext,
    ) -> list[MutationChoice]:
        ranked: list[MutationChoice] = []
        existing_vulns = {v.type for v in snapshot.truth_graph.vulns if v.type}
        mutation_weights = self.settings.mutation.weights()
        for candidate in candidates:
            curriculum = self._curriculum_bonus(candidate, context, existing_vulns)
            novelty = self._novelty_bonus(candidate, context)
            structural_gain = self._structural_gain(candidate)
            lineage = 1.0 / (1.0 + snapshot.lineage.generation_depth)
            signals = {
                "curriculum": curriculum,
                "novelty": novelty,
                "structural_gain": structural_gain,
                "lineage": lineage,
            }
            contributions = self._weighted_contributions(signals, mutation_weights)
            total = round(
                max(sum(contributions.values()), self.settings.mutation.minimum_total),
                4,
            )
            ranked.append(
                MutationChoice(
                    op=candidate,
                    total=total,
                    signals=self._round_dict(signals),
                    weights=self._round_dict(mutation_weights),
                    contributions=self._round_dict(contributions),
                )
            )
        ranked.sort(key=lambda choice: choice.total, reverse=True)
        return ranked

    @staticmethod
    def _frontier_score(rate: float) -> float:
        return max(0.0, 1.0 - abs(rate - 0.5) * 2.0)

    def _structural_gain(self, op: MutationOp) -> float:
        return self.settings.structural_gains.gain_for(op.op_type) * max(op.magnitude, 1)

    def _novelty_bonus(self, op: MutationOp, context: BuildContext) -> float:
        novelty = self.settings.novelty
        bonus = novelty.base_bonus
        if op.op_type == "seed_vuln":
            vuln_type = str(op.params.get("vuln_type", "")).strip()
            if vuln_type and vuln_type not in context.previous_vuln_classes:
                bonus += novelty.new_vuln_class_bonus
        if op.op_type == "add_benign_noise":
            location = str(op.params.get("location", "")).strip()
            if location and location not in context.recent_attack_surfaces:
                bonus += novelty.new_noise_surface_bonus
        if op.op_type not in {"seed_vuln", "add_benign_noise"}:
            bonus += novelty.structural_op_bonus
        return bonus

    def _curriculum_bonus(
        self,
        op: MutationOp,
        context: BuildContext,
        existing_vulns: set[str],
    ) -> float:
        curriculum = self.settings.curriculum
        bonus = curriculum.base_bonus
        if op.op_type == "seed_vuln":
            vuln_type = str(op.params.get("vuln_type", "")).strip()
            if vuln_type in context.weak_areas:
                bonus += curriculum.weak_area_bonus
            if vuln_type and vuln_type not in existing_vulns:
                bonus += curriculum.new_vuln_bonus
        if op.op_type in {"add_dependency_edge", "add_trust_edge"} and context.require_chain_length > 1:
            bonus += curriculum.chain_length_bonus
        if context.focus_layer == "identity" and op.op_type in {"add_user", "add_trust_edge"}:
            bonus += curriculum.focus_identity_bonus
        if context.focus_layer == "infra" and op.op_type in {"add_service", "add_dependency_edge"}:
            bonus += curriculum.focus_infra_bonus
        if context.focus_layer == "process" and op.op_type == "add_benign_noise":
            bonus += curriculum.focus_process_bonus
        return bonus

    @staticmethod
    def _weighted_contributions(
        signals: dict[str, float],
        weights: dict[str, float],
    ) -> dict[str, float]:
        return {
            name: float(signals.get(name, 0.0)) * float(weight)
            for name, weight in weights.items()
        }

    @staticmethod
    def _round_dict(values: dict[str, float]) -> dict[str, float]:
        return {key: round(float(value), 4) for key, value in values.items()}
