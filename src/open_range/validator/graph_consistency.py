"""Graph-level consistency checks for compiled snapshot state."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec
from open_range.validator.graphs import compile_snapshot_graphs


class GraphConsistencyCheck:
    """Verify internal consistency of the canonical graph views."""

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        compiled = compile_snapshot_graphs(snapshot)
        issues: list[str] = []

        for source, target in compiled.dependency_edges:
            if source not in compiled.hosts or target not in compiled.hosts:
                issues.append(f"dependency edge '{source}->{target}' references unknown host")

        for source, target, _edge_type in compiled.trust_edges:
            if source not in compiled.users or target not in compiled.users:
                issues.append(f"trust edge '{source}->{target}' references unknown user")

        lineage = snapshot.lineage
        if lineage.generation_depth == 0 and lineage.parent_snapshot_id:
            issues.append("root snapshot must not have parent_snapshot_id")
        if lineage.generation_depth > 0 and not lineage.parent_snapshot_id:
            issues.append("child snapshot missing parent_snapshot_id")
        if snapshot.mutation_plan is not None:
            if snapshot.mutation_plan.parent_snapshot_id != lineage.parent_snapshot_id:
                issues.append("mutation plan parent does not match lineage parent")
            for op in snapshot.mutation_plan.ops:
                if op.op_type in {"add_service", "seed_vuln"}:
                    host = op.target_selector.get("host", "")
                    if host and host not in compiled.hosts:
                        issues.append(
                            f"mutation '{op.mutation_id}' targets unknown host '{host}'"
                        )
                if op.op_type == "add_dependency_edge":
                    source = op.target_selector.get("source", "")
                    target = op.target_selector.get("target", "")
                    if source and source not in compiled.hosts:
                        issues.append(
                            f"mutation '{op.mutation_id}' source host '{source}' missing"
                        )
                    if target and target not in compiled.hosts:
                        issues.append(
                            f"mutation '{op.mutation_id}' target host '{target}' missing"
                        )
                if op.op_type == "add_trust_edge":
                    source = op.target_selector.get("source", "")
                    target = op.target_selector.get("target", "")
                    if source and source not in compiled.users:
                        issues.append(
                            f"mutation '{op.mutation_id}' source user '{source}' missing"
                        )
                    if target and target not in compiled.users:
                        issues.append(
                            f"mutation '{op.mutation_id}' target user '{target}' missing"
                        )

        passed = len(issues) == 0
        return CheckResult(
            name="graph_consistency",
            passed=passed,
            details={
                "hosts": len(compiled.hosts),
                "users": len(compiled.users),
                "dependency_edges": len(compiled.dependency_edges),
                "trust_edges": len(compiled.trust_edges),
            },
            error="" if passed else "; ".join(issues),
        )
