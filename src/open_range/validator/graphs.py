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
    principals: frozenset[str]
    zones_by_host: dict[str, str]
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
    principals = _compile_principals(topology, users)
    zones_by_host = _compile_zones(topology, hosts)
    services_by_host = _compile_services(topology, hosts)
    dependency_edges = _compile_dependency_edges(topology)
    trust_edges = _compile_trust_edges(topology)
    vuln_ids = frozenset(v.id for v in snapshot.truth_graph.vulns if v.id)
    evidence_locations = frozenset(item.location for item in snapshot.evidence_spec if item.location)

    return CompiledGraphs(
        hosts=hosts,
        users=users,
        principals=principals,
        zones_by_host=zones_by_host,
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
    host_catalog = topology.get("host_catalog", {})
    compiled: dict[str, frozenset[str]] = {}
    for host in hosts:
        detail = {}
        if isinstance(host_details, dict):
            raw_detail = host_details.get(host, {})
            if isinstance(raw_detail, dict):
                detail = raw_detail
        if not detail and isinstance(host_catalog, dict):
            raw_catalog = host_catalog.get(host, {})
            if isinstance(raw_catalog, dict):
                detail = raw_catalog
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
    if edges:
        return frozenset(edges)

    host_details = topology.get("host_details", {})
    if isinstance(host_details, dict):
        for source, raw_detail in host_details.items():
            if not isinstance(raw_detail, dict):
                continue
            raw_targets = raw_detail.get("connects_to", [])
            if not isinstance(raw_targets, list):
                continue
            for raw_target in raw_targets:
                target = str(raw_target).strip()
                if source and target:
                    edges.add((str(source).strip(), target))
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


def _compile_principals(
    topology: dict[str, object],
    users: frozenset[str],
) -> frozenset[str]:
    principals = set(users)
    raw_catalog = topology.get("principal_catalog", {})
    if isinstance(raw_catalog, dict):
        for raw_name in raw_catalog:
            name = str(raw_name).strip()
            if name:
                principals.add(name)
    return frozenset(principals)


def _compile_zones(
    topology: dict[str, object],
    hosts: frozenset[str],
) -> dict[str, str]:
    zones_by_host: dict[str, str] = {}
    raw_zones = topology.get("zones", {})
    if isinstance(raw_zones, dict):
        for raw_zone, raw_hosts in raw_zones.items():
            zone = str(raw_zone).strip()
            if not zone or not isinstance(raw_hosts, list):
                continue
            for raw_host in raw_hosts:
                host = str(raw_host).strip()
                if host:
                    zones_by_host[host] = zone

    host_details = topology.get("host_details", {})
    if isinstance(host_details, dict):
        for raw_host, raw_detail in host_details.items():
            host = str(raw_host).strip()
            if not host or host not in hosts or not isinstance(raw_detail, dict):
                continue
            zone = str(raw_detail.get("zone", "")).strip()
            if zone and host not in zones_by_host:
                zones_by_host[host] = zone
    return zones_by_host
