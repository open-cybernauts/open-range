"""Helpers for executing golden-path steps during validation."""

from __future__ import annotations

from open_range.protocols import ContainerSet, SnapshotSpec


def _command_name(command: str) -> str:
    stripped = command.strip()
    if not stripped:
        return ""
    return stripped.split()[0]


async def execute_step(
    snapshot: SnapshotSpec,
    containers: ContainerSet,
    command: str,
    *,
    host: str = "attacker",
) -> str:
    """Execute a golden-path step, including environment meta-commands."""
    cmd_name = _command_name(command)
    if cmd_name == "submit_flag":
        parts = command.strip().split(maxsplit=1)
        submitted = parts[1] if len(parts) > 1 else ""
        valid_flags = {flag.value for flag in snapshot.flags}
        if submitted in valid_flags:
            return f"Correct! Flag accepted: {submitted}"
        return f"Invalid flag: {submitted}"

    if cmd_name == "submit_evidence":
        return "Evidence submitted and recorded."

    if cmd_name == "submit_finding":
        return "Finding submitted and recorded."

    if cmd_name == "auth":
        parts = command.strip().split(maxsplit=3)
        if len(parts) < 4:
            return "Usage: auth <host> <username> <password>"
        target_host, username, password = parts[1], parts[2], parts[3]
        for user in snapshot.topology.get("users", []):
            if (
                user.get("username") == username
                and user.get("password") == password
                and target_host in user.get("hosts", [])
            ):
                return f"Authenticated as {username} on {target_host}."
        return f"Authentication failed for {username} on {target_host}."

    if cmd_name == "logout":
        parts = command.strip().split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: logout <host>"
        return f"Logged out from {parts[1]}."

    return await containers.exec(host, command)
