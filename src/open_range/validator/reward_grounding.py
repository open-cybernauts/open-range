"""Check 5: Reward grounding — verify flag values exist at expected paths."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec


def _parse_db_path(path: str) -> tuple[str, str, str] | None:
    """Parse a DB flag path like ``db:database.table.column``.

    Returns ``(database, table, column)`` or *None* if the path is not a
    valid DB reference.
    """
    prefix = path.split(":", 1)
    if len(prefix) != 2:
        return None
    scheme, rest = prefix
    if scheme not in ("db", "mysql"):
        return None
    parts = rest.split(".")
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


class RewardGroundingCheck:
    """For every declared flag, verify its value exists at the expected
    location.  File-based flags are checked via ``cat``.  DB-stored flags
    (``db:<database>.<table>.<column>``) are verified via a MySQL query.
    """

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        flags = snapshot.flags
        if not flags:
            return CheckResult(
                name="reward_grounding",
                passed=False,
                error="no flags defined in snapshot",
            )

        bad: list[dict] = []
        for flag in flags:
            host = flag.host
            path = flag.path

            # --- DB-stored flags -------------------------------------------
            if path.startswith(("db:", "mysql:")):
                # Deployment artifacts like "db:sql" are not flag locations.
                db_ref = _parse_db_path(path)
                if db_ref is None:
                    # Unparseable DB path (e.g. "db:sql") — skip silently.
                    continue

                database, table, column = db_ref
                mysql_cmd = (
                    f'mysql -u root -p$MYSQL_ROOT_PASSWORD -N '
                    f'-e "SELECT {column} FROM {database}.{table} LIMIT 1"'
                )
                try:
                    output = await containers.exec(host, mysql_cmd)
                    output = output.strip()
                except Exception as exc:  # noqa: BLE001
                    bad.append({"flag": flag.id, "error": str(exc)})
                    continue

                if flag.value not in output:
                    bad.append({
                        "flag": flag.id,
                        "expected": flag.value,
                        "got_snippet": output[:200],
                    })
                continue

            # --- Filesystem flags ------------------------------------------
            if "/" not in path:
                # Non-filesystem, non-DB flag path we don't understand.
                bad.append({
                    "flag": flag.id,
                    "error": f"unknown flag path format: {path}",
                })
                continue

            try:
                output = await containers.exec(host, f"cat {path}")
                output = output.strip()
            except Exception as exc:  # noqa: BLE001
                bad.append({"flag": flag.id, "error": str(exc)})
                continue

            if flag.value not in output:
                bad.append({
                    "flag": flag.id,
                    "expected": flag.value,
                    "got_snippet": output[:200],
                })

        passed = len(bad) == 0
        return CheckResult(
            name="reward_grounding",
            passed=passed,
            details={"results": bad, "total_flags": len(flags)},
            error="" if passed else f"{len(bad)} flag(s) not found at expected location",
        )
