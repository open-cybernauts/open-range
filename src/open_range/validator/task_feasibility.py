"""Check 7: Task feasibility — golden path references real hosts, evidence targets exist."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec
from open_range.validator.graphs import compile_snapshot_graphs
from open_range.validator.path_solvability import build_host_adjacency, has_host_path


class TaskFeasibilityCheck:
    """Verify:
    1. Every golden-path step references a host that exists in the topology.
    2. Every evidence_spec item references a container that exists.
    3. Red's exploit chain references vulns that exist in truth_graph.
    """

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        issues: list[str] = []
        compiled = compile_snapshot_graphs(snapshot)
        adjacency = build_host_adjacency(snapshot, compiled)

        # Collect known host names from topology.
        topo_hosts: set[str] = set()
        raw_hosts = snapshot.topology.get("hosts", [])
        for h in raw_hosts:
            if isinstance(h, dict):
                topo_hosts.add(h.get("name", ""))
            else:
                topo_hosts.add(str(h))
        topo_hosts.discard("")

        # Fail early if topology has no hosts.
        if not topo_hosts:
            return CheckResult(
                name="task_feasibility",
                passed=False,
                details={"issues": ["Topology has no hosts defined"]},
                error="Topology has no hosts defined",
            )

        # 1. Golden-path hosts exist in topology.
        for step in snapshot.golden_path:
            host = getattr(step, "host", None) or "attacker"
            if host not in topo_hosts:
                issues.append(f"golden path step {step.step}: host '{host}' not in topology")

        # 2. Evidence targets reference existing containers.
        for item in snapshot.evidence_spec:
            loc = item.location
            if ":" in loc:
                host = loc.split(":")[0]
            else:
                host = "siem"
            if host not in topo_hosts:
                issues.append(f"evidence item '{item.type}' references unknown host '{host}'")

        # 3. Exploit chain vuln IDs exist in truth_graph.
        vuln_ids = {v.id for v in snapshot.truth_graph.vulns}
        for step in snapshot.truth_graph.exploit_chain:
            if step.vuln_id and step.vuln_id not in vuln_ids:
                issues.append(f"exploit chain references unknown vuln '{step.vuln_id}'")

        # 4. Flag hosts exist in topology.
        for flag in snapshot.flags:
            if flag.host not in topo_hosts:
                issues.append(f"flag '{flag.id}' references unknown host '{flag.host}'")

        vuln_by_id = {v.id: v for v in snapshot.truth_graph.vulns}
        flag_by_value = {flag.value: flag for flag in snapshot.flags}
        submit_steps = {
            step.command.removeprefix("submit_flag ").strip(): step
            for step in snapshot.golden_path
            if step.command.strip().startswith("submit_flag ")
        }
        exploit_steps = {step.vuln_id: step for step in snapshot.truth_graph.exploit_chain}

        plan = snapshot.mutation_plan
        if plan is not None:
            for op in plan.ops:
                if op.op_type != "seed_vuln":
                    continue

                vuln_id = str(op.params.get("instantiated_vuln_id", "")).strip()
                flag_value = str(op.params.get("instantiated_flag_value", "")).strip()
                exploit_command = str(op.params.get("instantiated_exploit_command", "")).strip()
                flag_host = str(op.params.get("instantiated_flag_host", "")).strip()

                vuln = vuln_by_id.get(vuln_id)
                if vuln is None:
                    issues.append(
                        f"seed_vuln mutation '{op.mutation_id}' did not materialize a vuln id"
                    )
                    continue

                flag = flag_by_value.get(flag_value)
                if flag is None:
                    issues.append(
                        f"seed_vuln mutation '{op.mutation_id}' did not materialize a flag"
                    )
                    continue

                if flag_host and flag.host != flag_host:
                    issues.append(
                        f"seed_vuln mutation '{op.mutation_id}' flag host mismatch "
                        f"('{flag.host}' != '{flag_host}')"
                    )

                if flag_value not in submit_steps:
                    issues.append(
                        f"seed_vuln mutation '{op.mutation_id}' missing submit_flag step for "
                        f"'{flag_value}'"
                    )

                exploit = exploit_steps.get(vuln_id)
                if exploit is None:
                    issues.append(
                        f"seed_vuln mutation '{op.mutation_id}' missing exploit_chain linkage"
                    )
                elif exploit_command and exploit.command != exploit_command:
                    issues.append(
                        f"seed_vuln mutation '{op.mutation_id}' exploit command mismatch"
                    )

                if exploit_command and not any(
                    exploit_command in step.command for step in snapshot.golden_path
                ):
                    issues.append(
                        f"seed_vuln mutation '{op.mutation_id}' missing golden-path exploit step"
                    )

                if flag.host != vuln.host and not has_host_path(vuln.host, flag.host, adjacency):
                    issues.append(
                        f"seed_vuln mutation '{op.mutation_id}' flag host '{flag.host}' "
                        f"is unreachable from vuln host '{vuln.host}'"
                    )

        passed = len(issues) == 0
        return CheckResult(
            name="task_feasibility",
            passed=passed,
            details={"issues": issues},
            error="" if passed else f"{len(issues)} feasibility issue(s)",
        )
