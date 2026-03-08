"""Graph-native evidence sufficiency checks."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec
from open_range.validator.graphs import compile_snapshot_graphs


class GraphEvidenceSufficiencyCheck:
    """Verify that the compiled world exposes enough evidence for key facts."""

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        compiled = compile_snapshot_graphs(snapshot)
        evidence_hosts = {
            _location_host(location)
            for location in compiled.evidence_locations
            if _location_host(location)
        }
        issues: list[str] = []

        if not compiled.evidence_locations:
            return CheckResult(
                name="graph_evidence_sufficiency",
                passed=False,
                error="snapshot has no evidence locations",
            )

        for vuln in snapshot.truth_graph.vulns:
            supporting_hosts = {vuln.host, "siem"}
            if not evidence_hosts.intersection(supporting_hosts):
                issues.append(
                    f"vuln '{vuln.id}' on host '{vuln.host}' has no supporting evidence host"
                )

        for flag in snapshot.flags:
            supporting_hosts = {flag.host, "siem"}
            if not evidence_hosts.intersection(supporting_hosts):
                issues.append(
                    f"flag '{flag.id}' on host '{flag.host}' has no supporting evidence host"
                )

        passed = len(issues) == 0
        return CheckResult(
            name="graph_evidence_sufficiency",
            passed=passed,
            details={
                "evidence_hosts": sorted(evidence_hosts),
                "issues": issues,
            },
            error="" if passed else "; ".join(issues),
        )


def _location_host(location: str) -> str:
    if ":" not in location:
        return "siem"
    return location.split(":", 1)[0].strip()
