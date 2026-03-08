"""LLM-driven NPC agent (Level 1).

Each NPC has a persona card and polls for incoming stimuli (emails, chat
messages) on a configurable interval. The agent decides how to respond
using an LLM call via LiteLLM.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any

import litellm

from open_range.protocols import ContainerSet, NPCAction, NPCPersona, Stimulus

logger = logging.getLogger(__name__)

# Valid NPC actions
VALID_ACTIONS = frozenset({
    "click_link",
    "open_attachment",
    "reply",
    "share_credentials",
    "ignore",
    "report_to_IT",
    "forward",
})

NPC_SYSTEM_PROMPT_TEMPLATE = """\
You are simulating {name}, a {role} in the {department} department at a \
corporate company. Your communication style is: {communication_style}.

Your security awareness level is {awareness_level} ({awareness_score}/1.0).
{susceptibility_description}

When you receive an incoming message (email, chat, etc.), decide how to respond \
based on your persona. Consider:
1. Is this sender someone you know or trust?
2. Does the request seem plausible for your role?
3. Are there any red flags (urgency, unusual requests, suspicious links)?
4. Would someone with your security awareness level notice these red flags?

Return ONLY valid JSON:
{{
  "action": "<click_link|open_attachment|reply|share_credentials|ignore|report_to_IT|forward>",
  "response_content": "<your reply text if action is reply/forward, empty string otherwise>",
  "side_effects": ["<description of side effect>"]
}}

Guidelines:
- Stay in character as {name} at all times.
- Never reveal that you are an AI or break character.
- Your response style should match: {communication_style}.
"""


def _build_system_prompt(persona: NPCPersona) -> str:
    """Build a persona-specific system prompt from the NPC card."""
    if persona.security_awareness > 0.7:
        awareness_level = "HIGH"
    elif persona.security_awareness > 0.4:
        awareness_level = "MODERATE"
    else:
        awareness_level = "LOW"

    # Build susceptibility description
    susc_parts = []
    for attack_type, score in persona.susceptibility.items():
        readable = attack_type.replace("_", " ")
        if score > 0.6:
            susc_parts.append(f"- You are HIGHLY susceptible to {readable} attacks")
        elif score > 0.3:
            susc_parts.append(f"- You have MODERATE resistance to {readable} attacks")
        else:
            susc_parts.append(f"- You are VERY RESISTANT to {readable} attacks")

    susceptibility_description = "\n".join(susc_parts) if susc_parts else ""

    return NPC_SYSTEM_PROMPT_TEMPLATE.format(
        name=persona.name,
        role=persona.role or "employee",
        department=persona.department or "General",
        communication_style=persona.communication_style or "neutral",
        awareness_level=awareness_level,
        awareness_score=persona.security_awareness,
        susceptibility_description=susceptibility_description,
    )


def _build_stimulus_message(persona: NPCPersona, stimulus: Stimulus) -> str:
    """Build the user message describing the stimulus for the LLM."""
    parts = [f"You ({persona.name}) have received the following {stimulus.type}:"]

    if stimulus.sender:
        parts.append(f"From: {stimulus.sender}")
    if stimulus.subject:
        parts.append(f"Subject: {stimulus.subject}")
    if stimulus.content:
        parts.append(f"\n--- Message ---\n{stimulus.content}\n--- End ---")
    if stimulus.attachments:
        parts.append(f"Attachments: {', '.join(stimulus.attachments)}")

    parts.append("\nHow do you respond?")
    return "\n".join(parts)


class LLMNPCAgent:
    """Async LLM NPC agent that responds to stimuli based on persona.

    Uses persona-specific system prompts shaped by security_awareness and
    susceptibility profiles to produce realistic NPC decisions.
    """

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.3,
    ) -> None:
        self.model = model or os.environ.get(
            "OPENRANGE_NPC_MODEL", "anthropic/claude-haiku-4-5-20251001"
        )
        self.temperature = temperature
        self._action_log: list[dict[str, Any]] = []

    @property
    def action_log(self) -> list[dict[str, Any]]:
        """Return a copy of the recorded NPC actions."""
        return list(self._action_log)

    def drain_actions(self) -> list[dict[str, Any]]:
        """Return and clear all recorded NPC actions since last drain."""
        actions = self._action_log
        self._action_log = []
        return actions

    async def decide(
        self,
        persona: NPCPersona,
        stimulus: Stimulus,
    ) -> NPCAction:
        """Decide how an NPC responds to a stimulus via LLM.

        This satisfies the NPCBehavior protocol. The system prompt is
        dynamically shaped by the persona's security_awareness and
        susceptibility profile to produce realistic decisions.
        """
        system_prompt = _build_system_prompt(persona)
        user_message = _build_stimulus_message(persona, stimulus)

        try:
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                response_format={"type": "json_object"},
                temperature=self.temperature,
            )

            raw = json.loads(response.choices[0].message.content)
            action_str = raw.get("action", "ignore")

            # Validate the action is known; fall back to ignore
            if action_str not in VALID_ACTIONS:
                logger.warning(
                    "NPC %s returned unknown action %r, defaulting to ignore",
                    persona.name,
                    action_str,
                )
                action_str = "ignore"

            npc_action = NPCAction(
                action=action_str,
                response_content=raw.get("response_content", ""),
                side_effects=raw.get("side_effects", []),
            )

        except Exception as exc:
            logger.warning(
                "NPC %s LLM decision failed, defaulting to ignore: %s",
                persona.name,
                exc,
            )
            npc_action = NPCAction(action="ignore")

        # Record the action for SIEM log generation
        self._action_log.append({
            "timestamp": time.time(),
            "npc_name": persona.name,
            "npc_role": persona.role,
            "stimulus_type": stimulus.type,
            "stimulus_sender": stimulus.sender,
            "stimulus_subject": stimulus.subject,
            "action": npc_action.action,
            "side_effects": npc_action.side_effects,
        })

        return npc_action

    async def run_loop(
        self,
        persona: NPCPersona,
        containers: ContainerSet,
    ) -> None:
        """Run the NPC agent loop, polling for stimuli on the persona's schedule.

        This loop runs as an asyncio task, checking for incoming emails
        and processing them according to the persona's schedule.
        """
        interval = persona.routine.get("email_check_interval_min", 15)
        interval_s = interval * 60

        logger.info(
            "NPC %s starting loop (check every %d min)",
            persona.name,
            interval,
        )

        while True:
            try:
                await asyncio.sleep(interval_s)

                # Check for new emails in the persona's mailbox via container
                email = persona.accounts.get("email", "")
                if email and containers.container_ids.get("mail"):
                    # Attempt to read new mail from dovecot/postfix
                    result = await containers.exec(
                        "mail",
                        f"doveadm fetch -u {email} 'hdr.from hdr.subject text' UNSEEN 2>/dev/null || true",
                        timeout=10.0,
                    )
                    if result.strip() and result != "<timeout>":
                        # Parse email into stimulus and decide
                        stimulus = Stimulus(
                            type="email",
                            sender="unknown",
                            subject="New email",
                            content=result[:2000],  # Truncate for safety
                            plausibility=0.5,
                        )
                        action = await self.decide(persona, stimulus)
                        logger.info(
                            "NPC %s decided: %s for email stimulus",
                            persona.name,
                            action.action,
                        )
                    else:
                        logger.debug(
                            "NPC %s checked mailbox (no new stimuli)",
                            persona.name,
                        )
                else:
                    logger.debug(
                        "NPC %s checked mailbox (no new stimuli)",
                        persona.name,
                    )

            except asyncio.CancelledError:
                logger.info("NPC %s loop cancelled", persona.name)
                break
            except Exception as exc:
                logger.warning("NPC %s loop error: %s", persona.name, exc)
                await asyncio.sleep(30)  # back off on error


class NullNPCBehavior:
    """No-op NPC behavior for Level 0 (shell scripts handle everything)."""

    async def decide(
        self,
        persona: NPCPersona,
        stimulus: Stimulus,
    ) -> NPCAction:
        """Always ignore -- Level 0 NPCs don't process stimuli."""
        return NPCAction(action="ignore")


class RuleBasedNPCBehavior:
    """Heuristic NPC decisions based on susceptibility scores. No LLM calls.

    Decision logic:
    - High security_awareness (>0.7): report suspicious stimuli unless
      the combined score (plausibility * susceptibility) is very high.
    - Low security_awareness (<0.3): act on stimuli readily based on
      susceptibility score.
    - Medium: balanced -- ignore low-quality stimuli, act on convincing ones.
    """

    async def decide(
        self,
        persona: NPCPersona,
        stimulus: Stimulus,
    ) -> NPCAction:
        """Decide based on persona susceptibility and stimulus plausibility."""
        # Get the susceptibility score for this stimulus type
        susceptibility = persona.susceptibility.get(
            stimulus.type,
            persona.susceptibility.get("phishing_email", 0.5),
        )
        score = stimulus.plausibility * susceptibility

        # High security awareness: report unless very convincing
        if persona.security_awareness > 0.7:
            if score > 0.8:
                # Even security-aware people can be fooled by very convincing attacks
                return NPCAction(
                    action="click_link",
                    side_effects=["clicked link despite high awareness (very convincing)"],
                )
            return NPCAction(
                action="report_to_IT",
                side_effects=["reported suspicious message to IT security"],
            )

        # Low security awareness: susceptible to most attacks
        if persona.security_awareness < 0.3:
            if score > 0.4:
                # Determine action type based on stimulus
                if stimulus.attachments:
                    return NPCAction(
                        action="open_attachment",
                        side_effects=["opened attachment from email"],
                    )
                if "password" in stimulus.content.lower() or "credential" in stimulus.content.lower():
                    return NPCAction(
                        action="share_credentials",
                        side_effects=["shared credentials in reply"],
                    )
                return NPCAction(
                    action="click_link",
                    side_effects=["clicked link in email"],
                )
            if score > 0.2:
                return NPCAction(action="ignore")
            return NPCAction(
                action="ignore",
                side_effects=["dismissed as irrelevant"],
            )

        # Medium security awareness: balanced decisions
        if score > 0.6:
            return NPCAction(
                action="click_link",
                side_effects=["clicked link in email"],
            )
        if score > 0.3:
            return NPCAction(action="ignore")
        return NPCAction(
            action="report_to_IT",
            side_effects=["forwarded suspicious email to security team"],
        )
