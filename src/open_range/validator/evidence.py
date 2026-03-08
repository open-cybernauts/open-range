"""Check 4: Evidence sufficiency — verify evidence artifacts exist in containers."""

from __future__ import annotations

import shlex

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec


class EvidenceCheck:
    """Verify all ``evidence_spec`` items exist in the running containers."""

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        items = snapshot.evidence_spec
        if not items:
            return CheckResult(
                name="evidence",
                passed=True,
                details={"note": "no evidence_spec defined — vacuously true"},
            )

        missing: list[dict] = []
        for item in items:
            loc = item.location
            pattern = item.pattern

            # Determine which container to check.  Location format:
            # "container:/path/to/file" or just "/path" (defaults to siem).
            if ":" in loc:
                host, path = loc.split(":", 1)
            else:
                host, path = "siem", loc

            try:
                safe_path = shlex.quote(path)
                if item.type in ("log_entry", "alert"):
                    if pattern:
                        result = await containers.exec_run(
                            host,
                            f"grep -c {shlex.quote(pattern)} {safe_path}",
                        )
                        output = result.stdout.strip()
                        if result.exit_code != 0:
                            missing.append({
                                "item": item.type,
                                "location": loc,
                                "pattern": pattern,
                                "error": result.combined_output
                                or f"evidence command failed (exit={result.exit_code})",
                            })
                        elif output in ("0", ""):
                            missing.append({
                                "item": item.type,
                                "location": loc,
                                "pattern": pattern,
                            })
                    else:
                        result = await containers.exec_run(host, f"test -f {safe_path}")
                        if result.exit_code != 0:
                            missing.append({
                                "item": item.type,
                                "location": loc,
                                "error": result.combined_output
                                or f"missing evidence file (exit={result.exit_code})",
                            })
                else:
                    result = await containers.exec_run(host, f"test -f {safe_path}")
                    if result.exit_code != 0:
                        missing.append({
                            "item": item.type,
                            "location": loc,
                            "error": result.combined_output
                            or f"missing evidence file (exit={result.exit_code})",
                        })
            except Exception as exc:  # noqa: BLE001
                missing.append({"item": item.type, "location": loc, "error": str(exc)})

        passed = len(missing) == 0
        return CheckResult(
            name="evidence",
            passed=passed,
            details={"missing": missing, "total": len(items)},
            error="" if passed else f"{len(missing)} evidence item(s) not found",
        )
