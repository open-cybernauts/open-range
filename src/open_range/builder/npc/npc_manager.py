"""NPC traffic orchestrator.

Starts Level 0 shell-script traffic generators and (optionally) Level 1
LLM-driven NPC agents for a given snapshot.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from open_range.builder.npc.traffic_scripts import (
    generate_db_traffic_script,
    generate_http_traffic_script,
    generate_ssh_traffic_script,
)
from open_range.protocols import ContainerSet, NPCPersona, SnapshotSpec

logger = logging.getLogger(__name__)


class NPCManager:
    """Start and stop NPC background traffic for a snapshot.

    Manages:
    - Level 0: shell-script traffic generators (HTTP, SSH, DB loops)
    - Level 1: LLM NPC agents with persona-driven decision loops

    NPC actions are collected into an internal log that can be drained
    via ``get_npc_actions()`` for SIEM log generation and FP scoring.
    """

    def __init__(self) -> None:
        self._processes: list[asyncio.subprocess.Process] = []
        self._tasks: list[asyncio.Task[Any]] = []
        self._running = False
        self._action_log: list[dict[str, Any]] = []
        self._personas: list[NPCPersona] = []
        self._llm_agent: Any = None  # LLMNPCAgent if Level 1+

    async def start(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet,
    ) -> None:
        """Start NPC traffic generators for a snapshot.

        Level 0: Generates shell scripts for HTTP/SSH/DB traffic and injects
        them into the appropriate containers via ``docker exec``.

        Level 1: Starts async LLM NPC agent loops for each persona defined
        in the snapshot.

        Args:
            snapshot: The snapshot spec containing NPC traffic config and personas.
            containers: Handle to live Docker containers.
        """
        if self._running:
            await self.stop()

        self._running = True
        self._action_log = []
        self._personas = list(snapshot.npc_personas)

        npc_cfg = snapshot.npc_traffic
        rate = int(npc_cfg.rate_lambda)

        # --- Level 0: Shell script traffic generators ---
        await self._start_traffic_scripts(rate, containers)

        # --- Level 1: LLM NPC agents ---
        if npc_cfg.level >= 1 and snapshot.npc_personas:
            from open_range.builder.npc.npc_agent import LLMNPCAgent

            self._llm_agent = LLMNPCAgent()
            for persona in snapshot.npc_personas:
                task = asyncio.create_task(
                    self._llm_agent.run_loop(persona, containers),
                    name=f"npc_{persona.name}",
                )
                self._tasks.append(task)
                logger.info("Started LLM NPC agent: %s", persona.name)

    async def _start_traffic_scripts(
        self,
        rate: int,
        containers: ContainerSet,
    ) -> None:
        """Generate and inject Level 0 traffic scripts into containers."""
        # HTTP traffic into the web container
        if containers.container_ids.get("web"):
            http_script = generate_http_traffic_script(rate)
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", "-d",
                    containers.container_ids["web"],
                    "sh", "-c", http_script,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                self._processes.append(proc)
                logger.info("Started HTTP traffic script (rate=%d req/min)", rate)
            except OSError as exc:
                logger.warning("Failed to start HTTP traffic: %s", exc)

        # SSH traffic -- only if an SSH service is available
        if containers.container_ids.get("web"):
            ssh_script = generate_ssh_traffic_script(max(1, rate // 5))
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", "-d",
                    containers.container_ids["web"],
                    "sh", "-c", ssh_script,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                self._processes.append(proc)
                logger.info("Started SSH traffic script")
            except OSError as exc:
                logger.warning("Failed to start SSH traffic: %s", exc)

        # DB traffic into the db container
        if containers.container_ids.get("db"):
            db_script = generate_db_traffic_script(max(1, rate // 3))
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", "-d",
                    containers.container_ids["db"],
                    "sh", "-c", db_script,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                self._processes.append(proc)
                logger.info("Started DB traffic script")
            except OSError as exc:
                logger.warning("Failed to start DB traffic: %s", exc)

    async def stop(self) -> None:
        """Stop all NPC traffic generators and agents.

        Cancels async LLM NPC tasks and terminates shell script processes.
        Drains remaining actions from the LLM agent before shutdown.
        """
        # Drain remaining LLM agent actions
        if self._llm_agent is not None:
            remaining = self._llm_agent.drain_actions()
            self._action_log.extend(remaining)
            self._llm_agent = None

        # Cancel async NPC agent tasks
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        # Terminate shell script processes
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

        self._running = False
        self._personas = []
        logger.info("All NPC traffic stopped.")

    def get_npc_actions(self) -> list[dict[str, Any]]:
        """Return and clear NPC decisions since last query.

        These actions can be fed into SIEM logs for Blue agent training.
        The FP scoring system uses these to distinguish NPC traffic from
        real attacks.

        Returns:
            List of action dicts with keys: timestamp, npc_name, npc_role,
            stimulus_type, stimulus_sender, action, side_effects.
        """
        # Collect from LLM agent if still running
        if self._llm_agent is not None:
            new_actions = self._llm_agent.drain_actions()
            self._action_log.extend(new_actions)

        # Drain and return
        actions = self._action_log
        self._action_log = []
        return actions

    def record_action(
        self,
        npc_name: str,
        action: str,
        stimulus_type: str = "traffic",
        **extra: Any,
    ) -> None:
        """Manually record an NPC action (e.g., from Level 0 traffic).

        This allows the environment to log Level 0 traffic events
        alongside Level 1 LLM-driven actions for unified FP scoring.
        """
        self._action_log.append({
            "timestamp": time.time(),
            "npc_name": npc_name,
            "npc_role": "traffic_generator",
            "stimulus_type": stimulus_type,
            "stimulus_sender": "",
            "action": action,
            "side_effects": [],
            **extra,
        })

    @property
    def running(self) -> bool:
        """Whether NPC traffic is currently active."""
        return self._running

    @property
    def personas(self) -> list[NPCPersona]:
        """Return the list of active NPC personas."""
        return list(self._personas)
