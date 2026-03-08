"""Population-aware parent and mutation selection policy."""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass
from typing import Any

from open_range.protocols import BuildContext, MutationOp, SnapshotSpec
from open_range.validator.graphs import compile_snapshot_graphs


@dataclass(frozen=True, slots=True)
class ParentPolicyScore:
    snapshot_id: str
    total: float
    components: dict[str, float]


@dataclass(frozen=True, slots=True)
class MutationChoice:
    op: MutationOp
    total: float
    components: dict[str, float]


class PopulationMutationPolicy:
    """Simple population-guided policy for parent and op selection.

    This is intentionally heuristic rather than learned. It gives the runtime
    an explicit place to score parents and mutation candidates using curriculum,
    replay, novelty, and lineage signals instead of relying on raw RNG.
    """

    name = "population_guided_v1"

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
        weights = [max(score.total, 0.05) for score in top]
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
                0.4
                if plays == 0
                else (
                    self._frontier_score(red_rate)
                    + self._frontier_score(blue_rate)
                )
                / 2.0
            )
            replay = 1.0 / (plays + 1.0)
            novelty = 1.0 / (
                1.0 + sum(vuln_frequency[vuln] for vuln in vuln_types)
            ) if vuln_types else 0.25
            weak_overlap = float(len(vuln_types.intersection(context.weak_areas)))
            root_id = snapshot.lineage.root_snapshot_id or entry.snapshot_id
            lineage_balance = 1.0 / max(root_counts[root_id], 1)
            depth = float(snapshot.lineage.generation_depth)
            depth_balance = 1.0 / (1.0 + max(depth - 3.0, 0.0))
            recency = 1.0 / (1.0 + float(stat.get("plays_recent", 0)))
            complexity = min(
                (
                    len(snapshot.truth_graph.vulns) * 0.25
                    + len(snapshot.golden_path) * 0.03
                    + len(compiled.dependency_edges) * 0.02
                    + len(compiled.trust_edges) * 0.02
                ),
                1.0,
            )

            components = {
                "frontier": frontier,
                "replay": replay,
                "novelty": novelty,
                "weak_overlap": weak_overlap,
                "lineage_balance": lineage_balance,
                "depth_balance": depth_balance,
                "recency": recency,
                "complexity": complexity,
            }
            total = (
                frontier * 0.28
                + replay * 0.18
                + novelty * 0.16
                + weak_overlap * 0.18
                + lineage_balance * 0.08
                + depth_balance * 0.04
                + recency * 0.04
                + complexity * 0.04
            )
            scores.append(
                ParentPolicyScore(
                    snapshot_id=entry.snapshot_id,
                    total=round(max(total, 0.05), 4),
                    components={key: round(value, 4) for key, value in components.items()},
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
        selected: list[MutationChoice] = []

        structural = self._select_candidate(
            structural_candidates,
            snapshot=snapshot,
            context=context,
            rng=rng,
        )
        if structural is not None:
            selected.append(structural)

        security_pool = [
            choice
            for choice in (
                self._select_candidate(
                    security_candidates,
                    snapshot=snapshot,
                    context=context,
                    rng=rng,
                ),
            )
            if choice is not None
        ]
        selected.extend(security_pool)

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

        if not structural and len(security_candidates) > 1:
            ranked = self._rank_candidates(
                security_candidates,
                snapshot=snapshot,
                context=context,
            )
            for choice in ranked:
                if any(choice.op.mutation_id == existing.op.mutation_id for existing in selected):
                    continue
                selected.append(choice)
                break

        ops = [choice.op for choice in selected]
        if not ops:
            return [], 0.0, {}

        breakdown = {
            "curriculum": round(sum(c.components["curriculum"] for c in selected), 4),
            "novelty": round(sum(c.components["novelty"] for c in selected), 4),
            "structural_gain": round(sum(c.components["structural_gain"] for c in selected), 4),
            "lineage": round(sum(c.components["lineage"] for c in selected), 4),
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
        weights = [max(choice.total, 0.05) for choice in top]
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
        for candidate in candidates:
            curriculum = self._curriculum_bonus(candidate, context, existing_vulns)
            novelty = self._novelty_bonus(candidate, context)
            structural_gain = self._structural_gain(candidate)
            lineage = 1.0 / (1.0 + snapshot.lineage.generation_depth)
            components = {
                "curriculum": curriculum,
                "novelty": novelty,
                "structural_gain": structural_gain,
                "lineage": lineage,
            }
            total = (
                curriculum * 0.38
                + novelty * 0.24
                + structural_gain * 0.28
                + lineage * 0.10
            )
            ranked.append(
                MutationChoice(
                    op=candidate,
                    total=round(max(total, 0.05), 4),
                    components={key: round(value, 4) for key, value in components.items()},
                )
            )
        ranked.sort(key=lambda choice: choice.total, reverse=True)
        return ranked

    @staticmethod
    def _frontier_score(rate: float) -> float:
        return max(0.0, 1.0 - abs(rate - 0.5) * 2.0)

    @staticmethod
    def _structural_gain(op: MutationOp) -> float:
        mapping = {
            "add_service": 1.0,
            "add_dependency_edge": 0.9,
            "add_trust_edge": 0.85,
            "add_user": 0.8,
            "seed_vuln": 0.7,
            "add_benign_noise": 0.3,
        }
        return mapping.get(op.op_type, 0.2) * max(op.magnitude, 1)

    @staticmethod
    def _novelty_bonus(op: MutationOp, context: BuildContext) -> float:
        bonus = 0.4
        if op.op_type == "seed_vuln":
            vuln_type = str(op.params.get("vuln_type", "")).strip()
            if vuln_type and vuln_type not in context.previous_vuln_classes:
                bonus += 1.0
        if op.op_type == "add_benign_noise":
            location = str(op.params.get("location", "")).strip()
            if location and location not in context.recent_attack_surfaces:
                bonus += 0.5
        if op.op_type not in {"seed_vuln", "add_benign_noise"}:
            bonus += 0.4
        return bonus

    @staticmethod
    def _curriculum_bonus(
        op: MutationOp,
        context: BuildContext,
        existing_vulns: set[str],
    ) -> float:
        bonus = 0.35
        if op.op_type == "seed_vuln":
            vuln_type = str(op.params.get("vuln_type", "")).strip()
            if vuln_type in context.weak_areas:
                bonus += 1.5
            if vuln_type and vuln_type not in existing_vulns:
                bonus += 0.4
        if op.op_type in {"add_dependency_edge", "add_trust_edge"} and context.require_chain_length > 1:
            bonus += 0.6
        if context.focus_layer == "identity" and op.op_type in {"add_user", "add_trust_edge"}:
            bonus += 0.5
        if context.focus_layer == "infra" and op.op_type in {"add_service", "add_dependency_edge"}:
            bonus += 0.5
        if context.focus_layer == "process" and op.op_type == "add_benign_noise":
            bonus += 0.4
        return bonus
