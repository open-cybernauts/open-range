"""Email-with-attachments social engineering channel.

Red agent sends a crafted email (optionally with a malicious attachment) to a
target NPC mailbox.  The NPC evaluates the message against its persona
(awareness, susceptibility) and either:
  - clicks / opens the attachment  → InitialAccess event
  - ignores / reports the message → DetectionAlertRaised event

Attachment types understood by the channel
------------------------------------------
pdf, docx, image   — document-style lures delivered via svc-email
link               — embedded hyperlink lure (no attachment)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from open_range.runtime_types import Action, RuntimeEvent

if TYPE_CHECKING:
    from open_range.world_ir import GreenPersona

# Attachment types that carry a slightly higher click rate due to perceived
# legitimacy (recipients expect to receive these in normal business flow).
_HIGH_LEGITIMACY_ATTACHMENTS = {"pdf", "docx", "image"}

# Base susceptibility when the persona has no explicit social_engineering key.
_DEFAULT_SUSCEPTIBILITY = 0.4


@dataclass(frozen=True, slots=True)
class EmailChannel:
    """Descriptor for a single red→NPC email interaction."""

    sender: str
    recipient_mailbox: str
    subject: str
    body: str
    attachment_type: str = ""   # "pdf" | "docx" | "image" | "link" | ""
    lure_pretext: str = ""      # human-readable pretext label for SIEM / audit


# ──────────────────────────────────────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────────────────────────────────────

def build_email_action(
    actor_id: str,
    recipient_mailbox: str,
    subject: str,
    body: str,
    *,
    attachment_type: str = "",
    lure_pretext: str = "generic_lure",
    target_service: str = "svc-email",
) -> Action:
    """Return an Action that delivers a phishing email via svc-email."""
    return Action(
        actor_id=actor_id,
        role="red",
        kind="mail",
        payload={
            "channel": "email",
            "target": target_service,
            "to": recipient_mailbox,
            "from": f"{actor_id}@attacker.local",
            "subject": subject,
            "body": body,
            "attachment_type": attachment_type,
            "lure_pretext": lure_pretext,
        },
    )


def handle_email_action(
    action: Action,
    *,
    personas: tuple[GreenPersona, ...],
    emit_event: Callable[..., RuntimeEvent],
    service_surfaces: Callable[[str], tuple[str, ...]],
) -> tuple[RuntimeEvent, ...]:
    """Evaluate an email action and return the resulting runtime events.

    The NPC's *susceptibility* to social engineering and its overall *awareness*
    jointly determine whether the lure succeeds:

        click_probability = base_susceptibility * (1 - awareness * 0.5)

    A successful click produces an InitialAccess event.
    A failed (detected) delivery produces a DetectionAlertRaised event.
    """
    payload = action.payload
    target_service = str(payload.get("target", "svc-email"))
    recipient = str(payload.get("to", ""))
    attachment_type = str(payload.get("attachment_type", ""))
    lure_pretext = str(payload.get("lure_pretext", "generic_lure"))

    persona = _find_persona_by_mailbox(recipient, personas)
    surfaces = service_surfaces(target_service)

    if persona is None:
        # Undeliverable — mailbox not found; benign no-op in SIEM
        return (
            emit_event(
                event_type="BenignUserAction",
                actor="red",
                source_entity=action.actor_id,
                target_entity=target_service,
                malicious=False,
                observability_surfaces=surfaces,
            ),
        )

    click_prob = _click_probability(persona, attachment_type)
    # Deterministic: use hash of (actor, recipient, pretext) so replays are
    # reproducible without storing per-episode RNG state.
    seed_val = hash((action.actor_id, recipient, lure_pretext)) % 1000 / 1000.0
    clicked = seed_val < click_prob

    if clicked:
        return (
            emit_event(
                event_type="InitialAccess",
                actor="red",
                source_entity=action.actor_id,
                target_entity=target_service,
                malicious=True,
                observability_surfaces=surfaces,
                linked_objective_predicates=(
                    f"initial_access_via_email({lure_pretext})",
                ),
            ),
        )

    # Persona noticed the lure and flagged it
    return (
        emit_event(
            event_type="DetectionAlertRaised",
            actor="green",
            source_entity=persona.id,
            target_entity=target_service,
            malicious=False,
            observability_surfaces=("svc-siem",),
        ),
    )

def _find_persona_by_mailbox(
    mailbox: str, personas: tuple[GreenPersona, ...]
) -> GreenPersona | None:
    for p in personas:
        if p.mailbox and p.mailbox.lower() == mailbox.lower():
            return p
    return None


def _click_probability(persona: GreenPersona, attachment_type: str) -> float:
    """Compute the probability that this persona clicks the lure."""
    base = persona.susceptibility.get(
        "social_engineering",
        persona.susceptibility.get("initial_access", _DEFAULT_SUSCEPTIBILITY),
    )
    # High-legitimacy attachment types boost the click rate slightly
    if attachment_type in _HIGH_LEGITIMACY_ATTACHMENTS:
        base = min(1.0, base + 0.1)
    # Higher awareness reduces click probability
    adjusted = base * (1.0 - persona.awareness * 0.5)
    return max(0.0, min(1.0, adjusted))
