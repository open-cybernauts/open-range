"""Multimodal social-engineering channels for red agent interactions."""

from open_range.channels.email import EmailChannel, handle_email_action

__all__ = [
    "EmailChannel",
    "handle_email_action",
]
