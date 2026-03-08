"""NPC traffic orchestrator.

Starts Level 0 shell-script traffic generators and (optionally) Level 1
LLM-driven NPC agents for a given snapshot.  Multimodal NPC channels
(chat, voice, document) are initialised at start and their activity logs
are available for SIEM consumption.

In **mock mode** (``mock_mode=True``), no Docker exec or LLM calls are
made.  Only synthetic chat traffic is generated from the
``chat_traffic`` module, so unit tests can exercise the NPC pipeline
without infrastructure.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from pathlib import Path
from typing import Any

from open_range.builder.npc.channels import ChatChannel, DocumentChannel, VoiceChannel
from open_range.protocols import ContainerSet, SnapshotSpec

logger = logging.getLogger(__name__)

_SCRIPT_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Service keyword mappings used to match script prefixes to topology hosts
# and to resolve well-known env-var roles from service lists.
# ---------------------------------------------------------------------------

# Map a script filename keyword to service keywords that indicate a host
# can run that script.  Order matters for priority within each entry.
_SCRIPT_SERVICE_KEYWORDS: dict[str, list[str]] = {
    "http": ["nginx", "apache", "httpd", "web", "php-fpm"],
    "db": ["mysql", "mariadb", "postgres", "postgresql", "mongodb", "redis"],
    "ssh": ["nmap", "hydra", "nikto", "ssh-client", "attacker", "sshd"],
    "smtp": ["postfix", "sendmail", "exim", "dovecot", "mail"],
}

# Map an env-var role (e.g. WEB_HOST) to service keywords that identify the
# host fulfilling that role.
_ROLE_SERVICE_KEYWORDS: dict[str, list[str]] = {
    "WEB_HOST": ["nginx", "apache", "httpd", "web", "php-fpm"],
    "DB_HOST": ["mysql", "mariadb", "postgres", "postgresql", "mongodb"],
    "MAIL_HOST": ["postfix", "sendmail", "dovecot", "mail"],
    "LDAP_HOST": ["openldap", "ldap", "slapd"],
    "SIEM_HOST": ["rsyslog", "elasticsearch", "siem", "splunk"],
}


def _hosts_from_topology(topology: dict[str, Any]) -> list[dict[str, Any]]:
    """Return normalized host dicts for compiled or manifest-style topology.

    ``compile_manifest_topology()`` canonicalizes ``topology["hosts"]`` to a
    list of host names and keeps the richer metadata in ``host_catalog`` /
    ``host_details``. NPC helpers need the richer dict shape, so normalize the
    compiled form back into ``{"name": ..., "services": ...}`` records here.
    """
    raw_hosts = topology.get("hosts") or []
    host_catalog = topology.get("host_catalog")
    if not isinstance(host_catalog, dict):
        host_catalog = {}
    host_details = topology.get("host_details")
    if not isinstance(host_details, dict):
        host_details = {}

    hosts: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _append_host(raw_host: Any) -> None:
        if isinstance(raw_host, dict):
            name = str(raw_host.get("name", "")).strip()
        else:
            name = str(raw_host).strip()
        if not name or name in seen:
            return

        merged: dict[str, Any] = {}
        catalog_detail = host_catalog.get(name)
        if isinstance(catalog_detail, dict):
            merged.update(catalog_detail)
        detailed_detail = host_details.get(name)
        if isinstance(detailed_detail, dict):
            merged.update(detailed_detail)
        if isinstance(raw_host, dict):
            merged.update(raw_host)

        merged["name"] = name
        services = merged.get("services")
        merged["services"] = list(services) if isinstance(services, list) else []
        seen.add(name)
        hosts.append(merged)

    if isinstance(raw_hosts, list):
        for raw_host in raw_hosts:
            _append_host(raw_host)

    for name in host_catalog:
        _append_host(name)

    for name in host_details:
        _append_host(name)

    return hosts


def _host_matches_keywords(host: dict[str, Any], keywords: list[str]) -> bool:
    """Return True if the host's name or any of its services match *keywords*."""
    host_name = (host.get("name") or "").lower()
    services = [s.lower() for s in (host.get("services") or [])]
    for kw in keywords:
        kw_lower = kw.lower()
        if kw_lower in host_name or any(kw_lower in svc for svc in services):
            return True
    return False


def _container_for_script(script_name: str, topology: dict[str, Any]) -> str:
    """Pick the container a shell script runs in.

    Each script needs tools installed on the target container (mysql
    client on db, sshpass on the SSH source, etc.).  The scripts
    themselves target remote hosts by hostname via env vars so the
    traffic still appears in service logs for Blue.
    """
    hosts = _hosts_from_topology(topology)
    for prefix, keywords in _SCRIPT_SERVICE_KEYWORDS.items():
        if prefix in script_name.lower():
            for host in hosts:
                if _host_matches_keywords(host, keywords):
                    return host["name"]
            break
    return hosts[0].get("name", "web") if hosts else "web"


def _resolve_env_vars(topology: dict[str, Any], rate_lambda: float) -> dict[str, str]:
    """Build environment variables by resolving roles and credentials from topology.

    Resolves host roles (WEB_HOST, DB_HOST, etc.) and credentials (DB_USER,
    DB_PASS, SSH_USER, SSH_PASS) from the topology so shell scripts don't
    need hardcoded values.
    """
    hosts = _hosts_from_topology(topology)
    env: dict[str, str] = {"RATE_LAMBDA": str(int(rate_lambda))}

    for role, keywords in _ROLE_SERVICE_KEYWORDS.items():
        for host in hosts:
            if _host_matches_keywords(host, keywords):
                env[role] = host["name"]
                break

    # Pass DB and SSH credentials from topology to shell scripts
    users = topology.get("users", [])
    for user in users:
        if not isinstance(user, dict):
            continue
        hosts_list = user.get("hosts", [])
        if "db" in hosts_list and "DB_USER" not in env:
            env["DB_USER"] = user.get("username", "app_user")
            env["DB_PASS"] = user.get("password", "AppUs3r!2024")
        if any(h in hosts_list for h in ("web", "files", "ldap", "siem")):
            role = user.get("role", "")
            if role in ("admin", "sysadmin", "root") and "SSH_USER" not in env:
                env["SSH_USER"] = user.get("username", "admin")
                env["SSH_PASS"] = user.get("password", "Adm1n!2024")

    return env


def _derive_scripts_from_topology(topology: dict[str, Any]) -> list[str]:
    """Derive available NPC scripts from topology services.

    Scans the topology hosts and checks which script prefixes have a
    matching host.  Only returns scripts that actually exist on disk.
    """
    hosts = _hosts_from_topology(topology)
    scripts: list[str] = []

    for prefix, keywords in _SCRIPT_SERVICE_KEYWORDS.items():
        for host in hosts:
            if _host_matches_keywords(host, keywords):
                candidate = f"{prefix}_traffic.sh"
                if (_SCRIPT_DIR / candidate).exists():
                    scripts.append(candidate)
                break  # one match per prefix is enough

    return scripts


class NPCManager:
    """Start and stop NPC background traffic for a snapshot.

    Args:
        mock_mode: When True, skip Docker exec and LLM calls (unit tests).
        model: LiteLLM model string for Level 1 NPC agents.
            Defaults to ``OPENRANGE_NPC_MODEL`` env var, then
            ``azure/gpt-5.2-codex``.  Any LiteLLM-supported model works
            (e.g. ``openai/gpt-4o``, ``anthropic/claude-haiku-4-5-20251001``,
            ``ollama/llama3``).
    """

    def __init__(self, mock_mode: bool = False, model: str | None = None) -> None:
        self._mock_mode = mock_mode
        self._model = model  # passed to LLMNPCAgent
        self._processes: list[asyncio.subprocess.Process] = []
        self._tasks: list[asyncio.Task[Any]] = []
        self._running = False
        self._npc_agents: list[Any] = []  # LLMNPCAgent instances

        # Containers where scripts were deployed (for cleanup)
        self._script_containers: list[str] = []
        self._containers: ContainerSet | None = None

        # Multimodal NPC communication channels
        self.channels: dict[str, ChatChannel | VoiceChannel | DocumentChannel] = {
            "chat": ChatChannel(),
            "voice": VoiceChannel(),
            "document": DocumentChannel(),
        }

    # -----------------------------------------------------------------
    # Async start / stop (used when an event loop is available)
    # -----------------------------------------------------------------

    async def start(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet | None = None,
    ) -> None:
        """Start NPC traffic generators.

        Level 0: shell scripts (http, ssh, db traffic loops).
        Level 1: LLM NPC agents (deferred to npc_agent.py).

        In mock mode, only synthetic chat traffic is generated.
        """
        if self._running:
            await self.stop()

        self._running = True
        self._containers = containers

        self._init_channels_and_chat(snapshot)

        # In mock mode, skip Docker exec and LLM agent loops
        if self._mock_mode:
            logger.info("NPC manager running in mock mode (no Docker/LLM)")
            return

        if containers is not None:
            await self._deploy_live_npcs(snapshot, containers)

    # -----------------------------------------------------------------
    # Shared helpers (used by both async start and sync inner start)
    # -----------------------------------------------------------------

    def _init_channels_and_chat(self, snapshot: SnapshotSpec) -> None:
        """Re-initialise channels and generate Level 0 chat traffic."""
        self.channels = {
            "chat": ChatChannel(),
            "voice": VoiceChannel(),
            "document": DocumentChannel(),
        }

        if snapshot.npc_personas and len(snapshot.npc_personas) >= 2:
            from open_range.builder.npc.chat_traffic import generate_chat_traffic

            chat_ch = self.channels["chat"]
            assert isinstance(chat_ch, ChatChannel)
            msg_count = snapshot.npc_traffic.chat_message_count
            generate_chat_traffic(
                personas=snapshot.npc_personas,
                channel=chat_ch,
                num_messages=msg_count,
            )
            logger.info(
                "Generated %d chat messages for %d personas",
                len(chat_ch.get_channel_log()),
                len(snapshot.npc_personas),
            )

    async def _deploy_live_npcs(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet,
    ) -> None:
        """Deploy shell scripts into containers and spawn LLM NPC agent loops.

        This is the async work that requires a running event loop.  It is
        called directly from :meth:`start` and scheduled as a background
        task from :meth:`_start_sync_inner` when an event loop is already
        running (e.g. inside FastAPI/uvicorn).
        """
        topology = snapshot.topology
        npc_cfg = snapshot.npc_traffic

        # Determine which scripts to run -- derive from topology when
        # the snapshot does not specify scripts explicitly.
        scripts = npc_cfg.scripts or _derive_scripts_from_topology(topology)

        # Resolve environment variables (WEB_HOST, DB_HOST, etc.) from
        # the topology instead of hardcoding host names.
        env_vars = _resolve_env_vars(topology, npc_cfg.rate_lambda)

        for script_name in scripts:
            script_path = _SCRIPT_DIR / script_name
            if not script_path.exists():
                logger.warning("NPC script not found: %s", script_path)
                continue

            # Each script runs on the container that has its tools
            # (mysql client on db, sshpass on ssh host, etc.).
            target = _container_for_script(script_name, topology)

            logger.info(
                "Starting NPC script: %s on %s (rate=%s)",
                script_name, target, npc_cfg.rate_lambda,
            )

            try:
                script_content = script_path.read_text()
                encoded = base64.b64encode(script_content.encode()).decode()
                env_prefix = " ".join(
                    f"{k}={v}" for k, v in env_vars.items()
                )
                await containers.exec(
                    target,
                    f"echo {encoded} | base64 -d > /tmp/{script_name} "
                    f"&& chmod +x /tmp/{script_name} "
                    f"&& {env_prefix} nohup bash /tmp/{script_name} "
                    f"> /dev/null 2>&1 &",
                )
                self._script_containers.append(target)
            except Exception as exc:
                logger.warning(
                    "Failed to start NPC script %s in %s: %s",
                    script_name, target, exc,
                )

        # Level 1 LLM NPCs -- start async agent loops if personas are present.
        # Respect max_concurrent_agents to prevent LLM API floods at high tiers.
        if npc_cfg.level >= 1 and snapshot.npc_personas:
            from open_range.builder.npc.npc_agent import LLMNPCAgent

            max_agents = npc_cfg.max_concurrent_agents
            agent_model = npc_cfg.model or self._model
            personas_to_run = snapshot.npc_personas[:max_agents]
            if len(snapshot.npc_personas) > max_agents:
                logger.info(
                    "Capping NPC agents to %d/%d (max_concurrent_agents)",
                    max_agents,
                    len(snapshot.npc_personas),
                )

            for persona in personas_to_run:
                agent = LLMNPCAgent(model=agent_model)
                task = asyncio.create_task(
                    agent.run_loop(persona, containers, snapshot),
                    name=f"npc_{persona.name}",
                )
                self._tasks.append(task)
                self._npc_agents.append(agent)
                logger.info("Started LLM NPC agent: %s", persona.name)

    async def stop(self) -> None:
        """Stop all NPC traffic generators and agents."""
        # Cancel async NPC agent tasks
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._npc_agents.clear()

        # Terminate shell script processes (host-mode fallback)
        for proc in self._processes:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
        self._processes.clear()

        # Kill background scripts inside containers
        if self._containers is not None:
            for container in set(self._script_containers):
                try:
                    await self._containers.exec(
                        container,
                        "pkill -f 'npc.*traffic' 2>/dev/null || true",
                    )
                except Exception:
                    pass
        self._script_containers.clear()
        self._containers = None

        # Clear channel state
        for ch in self.channels.values():
            ch.clear()

        self._running = False
        logger.info("All NPC traffic stopped.")

    # -----------------------------------------------------------------
    # Synchronous wrappers (for callers without an event loop)
    # -----------------------------------------------------------------

    def start_sync(self, snapshot: SnapshotSpec, containers: ContainerSet | None = None) -> None:
        """Synchronous wrapper around :meth:`start`.

        Uses the running event loop if available, otherwise creates a new one.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # We're inside an async context -- schedule and return.
            # Since we can't await here, run the coroutine eagerly using
            # loop.run_until_complete which won't work if a loop is running.
            # Instead, just call the sync-safe parts directly.
            self._start_sync_inner(snapshot, containers)
        else:
            asyncio.run(self.start(snapshot, containers))

    def stop_sync(self) -> None:
        """Synchronous wrapper around :meth:`stop`."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            self._stop_sync_inner()
        else:
            asyncio.run(self.stop())

    def _start_sync_inner(self, snapshot: SnapshotSpec, containers: ContainerSet | None = None) -> None:
        """Synchronous start that works inside a running event loop.

        Generates chat traffic synchronously (available immediately for
        the first step), then schedules shell script deployment and LLM
        agent spawning as a background task on the running event loop.
        """
        if self._running:
            self._stop_sync_inner()

        self._running = True
        self._containers = containers

        self._init_channels_and_chat(snapshot)

        if self._mock_mode:
            logger.info("NPC manager running in mock mode (no Docker/LLM)")
            return

        # Schedule the async container-side work (scripts + LLM agents)
        # on the running event loop.  Chat traffic is already available
        # so agents have NPC noise from step 1 even if this task hasn't
        # finished yet.
        if containers is not None:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(
                    self._deploy_live_npcs(snapshot, containers),
                    name="npc_live_deploy",
                )
                logger.info(
                    "Scheduled NPC live deployment (scripts + LLM agents) on event loop"
                )
            except RuntimeError:
                logger.warning(
                    "No event loop available — NPC live scripts not started"
                )

    def _stop_sync_inner(self) -> None:
        """Synchronous stop for mock mode (no async cleanup needed)."""
        # Cancel any asyncio tasks that may exist
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        self._npc_agents.clear()
        self._processes.clear()
        self._script_containers.clear()
        self._containers = None

        for ch in self.channels.values():
            ch.clear()

        self._running = False

    # -----------------------------------------------------------------
    # Traffic log for reward computation
    # -----------------------------------------------------------------

    def get_traffic_log(self) -> list[dict[str, Any]]:
        """Return all NPC activity for reward computation.

        Combines SIEM channel logs with LLM NPC agent action logs.
        """
        logs = self.get_siem_log()

        # Append LLM NPC agent actions
        for agent in self._npc_agents:
            try:
                logs.extend(agent.get_actions())
            except Exception:
                pass

        logs.sort(key=lambda e: e.get("timestamp", 0))
        return logs

    @property
    def running(self) -> bool:
        """Whether NPC traffic is currently active."""
        return self._running

    def get_siem_log(self) -> list[dict[str, Any]]:
        """Aggregate activity logs from all channels for SIEM consumption."""
        logs: list[dict[str, Any]] = []
        chat_ch = self.channels.get("chat")
        if isinstance(chat_ch, ChatChannel):
            logs.extend(chat_ch.get_channel_log())
        voice_ch = self.channels.get("voice")
        if isinstance(voice_ch, VoiceChannel):
            logs.extend(voice_ch.get_call_log())
        doc_ch = self.channels.get("document")
        if isinstance(doc_ch, DocumentChannel):
            logs.extend(doc_ch.get_document_log())
        # Sort by timestamp
        logs.sort(key=lambda e: e.get("timestamp", 0))
        return logs
