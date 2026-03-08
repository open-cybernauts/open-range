"""Compile SnapshotSpec into lightweight canonical graph views.

These helpers intentionally stay small and dependency-free. The validator uses
them to reason about host membership, dependency edges, trust edges, evidence
locations, and mutation targets before any live container checks run.
"""

from __future__ import annotations

from dataclasses import dataclass

from open_range.protocols import SnapshotSpec


@dataclass(frozen=True, slots=True)
class CompiledGraphs:
    """Canonical graph-like views derived from a snapshot."""

    hosts: frozenset[str]
    users: frozenset[str]
    services_by_host: dict[str, frozenset[str]]
    dependency_edges: frozenset[tuple[str, str]]
    trust_edges: frozenset[tuple[str, str, str]]
    vuln_ids: frozenset[str]
    evidence_locations: frozenset[str]


def compile_snapshot_graphs(snapshot: SnapshotSpec) -> CompiledGraphs:
    """Compile a snapshot into canonical graph views."""

    topology = snapshot.topology or {}
    hosts = _compile_hosts(topology)
    users = _compile_users(topology)
    services_by_host = _compile_services(topology, hosts)
    dependency_edges = _compile_dependency_edges(topology)
    trust_edges = _compile_trust_edges(topology)
    vuln_ids = frozenset(v.id for v in snapshot.truth_graph.vulns if v.id)
    evidence_locations = frozenset(item.location for item in snapshot.evidence_spec if item.location)

    return CompiledGraphs(
        hosts=hosts,
        users=users,
        services_by_host=services_by_host,
        dependency_edges=dependency_edges,
        trust_edges=trust_edges,
        vuln_ids=vuln_ids,
        evidence_locations=evidence_locations,
    )


def _compile_hosts(topology: dict[str, object]) -> frozenset[str]:
    raw_hosts = topology.get("hosts", [])
    hosts: set[str] = set()
    for raw in raw_hosts if isinstance(raw_hosts, list) else []:
        if isinstance(raw, dict):
            name = str(raw.get("name", "")).strip()
            if name:
                hosts.add(name)
        else:
            name = str(raw).strip()
            if name:
                hosts.add(name)
    return frozenset(hosts)


def _compile_users(topology: dict[str, object]) -> frozenset[str]:
    raw_users = topology.get("users", [])
    users: set[str] = set()
    for raw in raw_users if isinstance(raw_users, list) else []:
        if not isinstance(raw, dict):
            continue
        username = str(raw.get("username", "")).strip()
        if username:
            users.add(username)
    return frozenset(users)


def _compile_services(
    topology: dict[str, object],
    hosts: frozenset[str],
) -> dict[str, frozenset[str]]:
    host_details = topology.get("host_details", {})
    compiled: dict[str, frozenset[str]] = {}
    for host in hosts:
        detail = {}
        if isinstance(host_details, dict):
            raw_detail = host_details.get(host, {})
            if isinstance(raw_detail, dict):
                detail = raw_detail
        services = detail.get("services", [])
        if not isinstance(services, list):
            services = []
        compiled[host] = frozenset(str(service) for service in services if service)
    return compiled


def _compile_dependency_edges(topology: dict[str, object]) -> frozenset[tuple[str, str]]:
    raw_edges = topology.get("dependency_edges", [])
    edges: set[tuple[str, str]] = set()
    for raw in raw_edges if isinstance(raw_edges, list) else []:
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source", "")).strip()
        target = str(raw.get("target", "")).strip()
        if source and target:
            edges.add((source, target))
    return frozenset(edges)


def _compile_trust_edges(topology: dict[str, object]) -> frozenset[tuple[str, str, str]]:
    raw_edges = topology.get("trust_edges", [])
    edges: set[tuple[str, str, str]] = set()
    for raw in raw_edges if isinstance(raw_edges, list) else []:
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source", "")).strip()
        target = str(raw.get("target", "")).strip()
        edge_type = str(raw.get("type", "")).strip()
        if source and target:
            edges.add((source, target, edge_type))
    return frozenset(edges)
