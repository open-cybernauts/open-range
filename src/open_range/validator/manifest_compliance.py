"""Manifest-bounded legality checks for candidate snapshots."""

from __future__ import annotations

from typing import Any

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec
from open_range.validator.graphs import compile_snapshot_graphs

_SUPPORTED_MUTATION_OPS = {
    "add_service",
    "add_user",
    "add_dependency_edge",
    "add_trust_edge",
    "seed_vuln",
    "add_benign_noise",
}

_SYSTEM_USERS = {"admin", "testuser"}


class ManifestComplianceCheck:
    """Ensure a candidate child stays inside the manifest-defined family."""

    def __init__(self, manifest: dict[str, Any]) -> None:
        self.manifest = manifest

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        compiled = compile_snapshot_graphs(snapshot)
        issues: list[str] = []

        manifest_hosts = _manifest_hosts(self.manifest)
        allowed_bug_families = set(str(v) for v in self.manifest.get("bug_families", []))
        allowed_users = set(_manifest_users(self.manifest))
        allowed_services = _manifest_services(self.manifest)
        allowed_dependency_edges = _manifest_dependency_edges(self.manifest)
        allowed_trust_edges = _manifest_trust_edges(self.manifest)

        unknown_hosts = compiled.hosts - manifest_hosts
        if unknown_hosts:
            issues.append(f"hosts outside manifest family: {sorted(unknown_hosts)}")

        illegal_users = {
            user
            for user in compiled.users
            if user not in allowed_users and user not in _SYSTEM_USERS and not user.startswith("svc_")
        }
        if illegal_users:
            issues.append(f"users outside manifest family: {sorted(illegal_users)}")

        for host, services in compiled.services_by_host.items():
            illegal = services - allowed_services.get(host, frozenset())
            if illegal:
                issues.append(
                    f"host '{host}' has services outside manifest family: {sorted(illegal)}"
                )

        for vuln in snapshot.truth_graph.vulns:
            if vuln.type and allowed_bug_families and vuln.type not in allowed_bug_families:
                issues.append(f"vuln '{vuln.id}' uses disallowed family '{vuln.type}'")
            if vuln.host and vuln.host not in manifest_hosts:
                issues.append(f"vuln '{vuln.id}' references host outside manifest '{vuln.host}'")

        plan = snapshot.mutation_plan
        if plan is not None:
            for op in plan.ops:
                if op.op_type not in _SUPPORTED_MUTATION_OPS:
                    issues.append(f"unsupported mutation op '{op.op_type}'")
                    continue

                if op.op_type == "add_service":
                    host = op.target_selector.get("host", "")
                    service = str(op.params.get("service", "")).strip()
                    if host not in manifest_hosts:
                        issues.append(f"add_service targets unknown host '{host}'")
                    elif service and service not in allowed_services.get(host, frozenset()):
                        issues.append(f"add_service introduces illegal service '{service}' on '{host}'")

                if op.op_type == "add_user":
                    username = str(op.params.get("username", "")).strip()
                    if username and username not in allowed_users:
                        issues.append(f"add_user introduces unknown manifest user '{username}'")

                if op.op_type == "add_dependency_edge":
                    source = op.target_selector.get("source", "")
                    target = op.target_selector.get("target", "")
                    if (source, target) not in allowed_dependency_edges:
                        issues.append(
                            f"add_dependency_edge introduces illegal edge '{source}->{target}'"
                        )

                if op.op_type == "add_trust_edge":
                    source = op.target_selector.get("source", "")
                    target = op.target_selector.get("target", "")
                    edge_type = str(op.params.get("type", "")).strip()
                    if (source, target, edge_type) not in allowed_trust_edges:
                        issues.append(
                            f"add_trust_edge introduces illegal trust edge "
                            f"'{source}->{target}' ({edge_type})"
                        )

                if op.op_type == "seed_vuln":
                    host = op.target_selector.get("host", "")
                    vuln_type = str(op.params.get("vuln_type", "")).strip()
                    if host not in manifest_hosts:
                        issues.append(f"seed_vuln targets unknown host '{host}'")
                    if vuln_type and vuln_type not in allowed_bug_families:
                        issues.append(f"seed_vuln uses illegal family '{vuln_type}'")

        passed = len(issues) == 0
        return CheckResult(
            name="manifest_compliance",
            passed=passed,
            details={
                "issue_count": len(issues),
                "manifest": self.manifest.get("name", ""),
            },
            error="" if passed else "; ".join(issues),
        )


def _manifest_hosts(manifest: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for raw in manifest.get("topology", {}).get("hosts", []):
        if isinstance(raw, dict):
            name = str(raw.get("name", "")).strip()
            if name:
                hosts.add(name)
    return hosts


def _manifest_users(manifest: dict[str, Any]) -> set[str]:
    users: set[str] = set()
    for raw in manifest.get("users", []):
        if isinstance(raw, dict):
            username = str(raw.get("username", "")).strip()
            if username:
                users.add(username)
    return users


def _manifest_services(manifest: dict[str, Any]) -> dict[str, frozenset[str]]:
    services: dict[str, frozenset[str]] = {}
    for raw in manifest.get("topology", {}).get("hosts", []):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name", "")).strip()
        if not name:
            continue
        raw_services = raw.get("services", [])
        if not isinstance(raw_services, list):
            raw_services = []
        services[name] = frozenset(str(service) for service in raw_services if service)
    return services


def _manifest_dependency_edges(manifest: dict[str, Any]) -> set[tuple[str, str]]:
    edges: set[tuple[str, str]] = set()
    for raw in manifest.get("topology", {}).get("hosts", []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("name", "")).strip()
        raw_targets = raw.get("connects_to", [])
        if not source or not isinstance(raw_targets, list):
            continue
        for raw_target in raw_targets:
            target = str(raw_target).strip()
            if target:
                edges.add((source, target))
    return edges


def _manifest_trust_edges(manifest: dict[str, Any]) -> set[tuple[str, str, str]]:
    edges: set[tuple[str, str, str]] = set()
    for raw in manifest.get("trust_relationships", []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source") or raw.get("from") or "").strip()
        target = str(raw.get("target") or raw.get("to") or "").strip()
        edge_type = str(raw.get("type", "")).strip()
        if source and target:
            edges.add((source, target, edge_type))
    return edges
