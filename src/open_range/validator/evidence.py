"""Check 4: Evidence sufficiency — verify evidence artifacts exist in containers."""

from __future__ import annotations

import shlex

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec

_RC_SENTINEL = "__OPENRANGE_RC__:"


def _with_exit_marker(command: str) -> str:
    """Wrap a shell command so output includes a parseable exit-code marker."""
    return f"{command}; rc=$?; echo {_RC_SENTINEL}$rc"


def _parse_marked_output(raw: str) -> tuple[str, int]:
    """Parse command output and recover the embedded exit code.

    Falls back to best-effort inference when the marker is absent (e.g., mocks).
    """
    lines = raw.splitlines()
    marker_idx = -1
    marker_rc: int | None = None

    for idx in range(len(lines) - 1, -1, -1):
        line = lines[idx].strip()
        if not line.startswith(_RC_SENTINEL):
            continue
        value = line[len(_RC_SENTINEL):].strip()
        if value.isdigit():
            marker_idx = idx
            marker_rc = int(value)
            break

    if marker_rc is not None:
        payload = "\n".join(lines[:marker_idx] + lines[marker_idx + 1:]).strip()
        return payload, marker_rc

    # Fallback for test doubles that return a plain string without marker.
    payload = raw.strip()
    if payload == "" or payload.isdigit():
        return payload, 0
    return payload, 1


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
                    # grep for pattern in the file
                    base_cmd = (
                        f"grep -c {shlex.quote(pattern)} {safe_path}"
                        if pattern
                        else f"test -f {safe_path} && echo ok"
                    )
                    output, rc = _parse_marked_output(
                        await containers.exec(host, _with_exit_marker(base_cmd))
                    )
                    if pattern and output.strip() in ("0", ""):
                        missing.append({"item": item.type, "location": loc, "pattern": pattern})
                    elif rc != 0:
                        missing.append({
                            "item": item.type,
                            "location": loc,
                            "pattern": pattern,
                            "error": output or f"evidence command failed (exit={rc})",
                        })
                else:
                    # file existence check
                    base_cmd = f"test -f {safe_path} && echo exists"
                    output, rc = _parse_marked_output(
                        await containers.exec(host, _with_exit_marker(base_cmd))
                    )
                    if rc != 0 or "exists" not in output:
                        detail = {"item": item.type, "location": loc}
                        if rc != 0 and output:
                            detail["error"] = output
                        missing.append(detail)
            except Exception as exc:  # noqa: BLE001
                missing.append({"item": item.type, "location": loc, "error": str(exc)})

        passed = len(missing) == 0
        return CheckResult(
            name="evidence",
            passed=passed,
            details={"missing": missing, "total": len(items)},
            error="" if passed else f"{len(missing)} evidence item(s) not found",
        )
