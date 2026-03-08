"""Helpers for executing golden-path steps during validation."""

from __future__ import annotations

from open_range.protocols import ContainerSet, ExecResult, SnapshotSpec


def _command_name(command: str) -> str:
    stripped = command.strip()
    if not stripped:
        return ""
    return stripped.split()[0]


def _ok(stdout: str) -> ExecResult:
    return ExecResult(stdout=stdout, exit_code=0)


async def execute_step_result(
    snapshot: SnapshotSpec,
    containers: ContainerSet,
    command: str,
    *,
    host: str = "attacker",
) -> ExecResult:
    """Execute a golden-path step and return structured command result."""
    cmd_name = _command_name(command)
    if cmd_name == "submit_flag":
        parts = command.strip().split(maxsplit=1)
        submitted = parts[1] if len(parts) > 1 else ""
        valid_flags = {flag.value for flag in snapshot.flags}
        if submitted in valid_flags:
            return _ok(f"Correct! Flag accepted: {submitted}")
        return _ok(f"Invalid flag: {submitted}")

    if cmd_name == "submit_evidence":
        return _ok("Evidence submitted and recorded.")

    if cmd_name == "submit_finding":
        return _ok("Finding submitted and recorded.")

    if cmd_name == "auth":
        parts = command.strip().split(maxsplit=3)
        if len(parts) < 4:
            return _ok("Usage: auth <host> <username> <password>")
        target_host, username, password = parts[1], parts[2], parts[3]
        for user in snapshot.topology.get("users", []):
            if (
                user.get("username") == username
                and user.get("password") == password
                and target_host in user.get("hosts", [])
            ):
                return _ok(f"Authenticated as {username} on {target_host}.")
        return _ok(f"Authentication failed for {username} on {target_host}.")

    if cmd_name == "logout":
        parts = command.strip().split(maxsplit=1)
        if len(parts) < 2:
            return _ok("Usage: logout <host>")
        return _ok(f"Logged out from {parts[1]}.")

    return await containers.exec_run(host, command)


async def execute_step(
    snapshot: SnapshotSpec,
    containers: ContainerSet,
    command: str,
    *,
    host: str = "attacker",
) -> str:
    """Execute a golden-path step, including environment meta-commands."""
    result = await execute_step_result(
        snapshot,
        containers,
        command,
        host=host,
    )
    return result.combined_output
