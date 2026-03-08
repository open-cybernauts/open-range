"""Check 1: Build + boot — verify all deployed containers are healthy."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec

# Hosts that are replaced by K8s-native primitives and have no pod.
_K8S_VIRTUAL_HOSTS = frozenset({"firewall"})


class BuildBootCheck:
    """Verify every deployed host is running and healthy.

    Hosts that have no backing pod (e.g. ``firewall``, which is replaced
    by NetworkPolicies in Kind) are skipped automatically.
    """

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        topology = snapshot.topology
        hosts: list[str] = topology.get("hosts", [])
        host_names: list[str] = []
        for h in hosts:
            if isinstance(h, dict):
                host_names.append(h.get("name", ""))
            else:
                host_names.append(str(h))

        if not host_names:
            return CheckResult(
                name="build_boot",
                passed=False,
                error="no hosts defined in topology",
            )

        # Only check hosts that are actually deployed as pods.
        _ids = getattr(containers, "container_ids", None)
        deployed = set(_ids.keys()) if _ids else None
        skipped: list[str] = []
        checked: list[str] = []
        unhealthy: list[str] = []

        for name in host_names:
            # Skip hosts replaced by K8s primitives (no pod exists)
            if name in _K8S_VIRTUAL_HOSTS:
                skipped.append(name)
                continue
            # If we have a pod map, skip hosts not in it
            if deployed is not None and name not in deployed:
                skipped.append(name)
                continue

            checked.append(name)
            try:
                ok = await containers.is_healthy(name)
                if not ok:
                    unhealthy.append(name)
            except Exception as exc:  # noqa: BLE001
                unhealthy.append(f"{name} ({exc})")

        passed = len(unhealthy) == 0
        return CheckResult(
            name="build_boot",
            passed=passed,
            details={
                "unhealthy": unhealthy,
                "checked": checked,
                "skipped": skipped,
            },
            error="" if passed else f"unhealthy containers: {', '.join(unhealthy)}",
        )
