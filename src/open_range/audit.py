"""Lightweight action auditing and integrity checks for runtime episodes."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

from open_range.runtime_events import action_target
from open_range.runtime_types import (
    Action,
    ActionDiversitySummary,
    AuditActionRecord,
    BinaryIntegritySummary,
    EpisodeAudit,
    ExternalRole,
    IntegrityDelta,
    IntegritySample,
)
from open_range.snapshot import RuntimeSnapshot


DEFAULT_SUSPICIOUS_PATTERNS = (
    r"\b(?:apt|apt-get|apk|yum|dnf)\s+(?:install|add)\b",
    r"\bpip(?:3)?\s+install\b",
    r"\bgit\s+clone\b",
    r"\b(?:curl|wget)\b.*\|\s*(?:sh|bash)\b",
    r"\b(?:curl|wget)\b.*https?://",
    r"\bchmod\s+\+x\b",
    r"\b(?:docker|kubectl|helm|kind)\b",
)
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_VOLATILE_INTEGRITY_SUFFIXES = (".log",)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuditConfig(_StrictModel):
    """Per-episode observability settings for agent-behavior audits."""

    enabled: bool = True
    suspicious_patterns: tuple[str, ...] = Field(
        default_factory=lambda: DEFAULT_SUSPICIOUS_PATTERNS
    )
    fingerprint_token_limit: int = Field(default=2, ge=1, le=8)
    diversity_warning_threshold: float = Field(default=0.15, ge=0.0, le=1.0)
    minimum_actions_for_collapse: int = Field(default=6, ge=1)
    binary_integrity_enabled: bool = False
    binary_integrity_paths: tuple[str, ...] = Field(default_factory=tuple)
    binary_integrity_services: tuple[str, ...] = Field(default_factory=tuple)
    binary_integrity_max_paths_per_service: int = Field(default=24, ge=1, le=256)


@dataclass(frozen=True, slots=True)
class ActionAuditObservation:
    actor: ExternalRole
    sim_time: float
    action_kind: str
    target: str
    command: str
    fingerprint: str
    fingerprint_prefix: str
    matched_patterns: tuple[str, ...]

    @property
    def suspicious(self) -> bool:
        return bool(self.matched_patterns)


class ActionAuditor:
    """Classify controlled actions without changing runtime behavior."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config
        self._compiled_patterns = _compile_patterns(config.suspicious_patterns)
        self._records: list[AuditActionRecord] = []
        self._integrity_targets: dict[str, tuple[str, ...]] = {}
        self._integrity_baseline: dict[tuple[str, str], IntegritySample] = {}
        self._integrity_available = False

    def bind_snapshot(self, snapshot: RuntimeSnapshot) -> None:
        self._integrity_targets = integrity_targets_for_snapshot(snapshot, self.config)
        self._integrity_baseline = {}
        self._integrity_available = False

    def capture_baseline(
        self,
        capture_integrity: Callable[
            [dict[str, tuple[str, ...]]], tuple[IntegritySample, ...]
        ]
        | None,
    ) -> None:
        if not self.config.enabled or not self.config.binary_integrity_enabled:
            return
        if not callable(capture_integrity) or not self._integrity_targets:
            return
        samples = capture_integrity(self._integrity_targets)
        self._integrity_baseline = {
            (sample.service_id, sample.path): sample for sample in samples
        }
        self._integrity_available = bool(self._integrity_baseline)

    def observe(
        self,
        *,
        action: Action,
        executed_command: str,
        sim_time: float,
        controlled: bool,
    ) -> ActionAuditObservation | None:
        if (
            not self.config.enabled
            or not controlled
            or action.role not in {"red", "blue"}
        ):
            return None
        target = action_target(action)
        command = (executed_command or command_text_for_action(action)).strip()
        fingerprint_prefix = fingerprint_prefix_for_command(
            command or fallback_fingerprint_source(action),
            token_limit=self.config.fingerprint_token_limit,
        )
        matched_patterns = match_suspicious_patterns(command, self._compiled_patterns)
        return ActionAuditObservation(
            actor=action.role,
            sim_time=round(sim_time, 4),
            action_kind=action.kind,
            target=target,
            command=command,
            fingerprint=hashlib.sha256(fingerprint_prefix.encode("utf-8")).hexdigest()[
                :8
            ],
            fingerprint_prefix=fingerprint_prefix,
            matched_patterns=matched_patterns,
        )

    def record(
        self,
        observation: ActionAuditObservation | None,
        *,
        emitted_event_ids: tuple[str, ...],
    ) -> None:
        if observation is None:
            return
        self._records.append(
            AuditActionRecord(
                actor=observation.actor,
                sim_time=observation.sim_time,
                action_kind=observation.action_kind,
                target=observation.target,
                command=_truncate(observation.command),
                fingerprint=observation.fingerprint,
                fingerprint_prefix=observation.fingerprint_prefix,
                matched_patterns=observation.matched_patterns,
                emitted_event_ids=emitted_event_ids,
            )
        )

    def build_summary(
        self,
        capture_integrity: Callable[
            [dict[str, tuple[str, ...]]], tuple[IntegritySample, ...]
        ]
        | None = None,
    ) -> EpisodeAudit:
        if not self.config.enabled:
            return EpisodeAudit(binary_integrity=BinaryIntegritySummary(enabled=False))

        total_actions = len(self._records)
        fingerprints = {record.fingerprint for record in self._records}
        overall_diversity = (
            round(len(fingerprints) / total_actions, 4) if total_actions else 1.0
        )
        suspicious_actions = tuple(
            record for record in self._records if record.matched_patterns
        )
        suspicious_event_ids = tuple(
            sorted(
                {
                    event_id
                    for record in suspicious_actions
                    for event_id in record.emitted_event_ids
                }
            )
        )
        role_diversity = tuple(
            self._role_diversity_summary(actor)
            for actor in ("red", "blue")
            if any(record.actor == actor for record in self._records)
        )
        collapse_warning = any(entry.collapse_warning for entry in role_diversity)
        return EpisodeAudit(
            action_count=total_actions,
            unique_fingerprints=len(fingerprints),
            action_diversity_score=overall_diversity,
            collapse_warning=collapse_warning,
            suspicious_actions=suspicious_actions,
            suspicious_event_ids=suspicious_event_ids,
            role_diversity=role_diversity,
            binary_integrity=self._binary_integrity_summary(capture_integrity),
        )

    def _role_diversity_summary(self, actor: ExternalRole) -> ActionDiversitySummary:
        records = [record for record in self._records if record.actor == actor]
        total_actions = len(records)
        counts = Counter(record.fingerprint for record in records)
        unique_fingerprints = len(counts)
        diversity_score = (
            round(unique_fingerprints / total_actions, 4) if total_actions else 1.0
        )
        dominant_fingerprint = ""
        dominant_prefix = ""
        dominant_share = 0.0
        if counts:
            dominant_fingerprint, dominant_count = max(
                counts.items(), key=lambda item: (item[1], item[0])
            )
            dominant_prefix = next(
                record.fingerprint_prefix
                for record in records
                if record.fingerprint == dominant_fingerprint
            )
            dominant_share = round(dominant_count / total_actions, 4)
        collapse_warning = (
            total_actions >= self.config.minimum_actions_for_collapse
            and diversity_score < self.config.diversity_warning_threshold
        )
        return ActionDiversitySummary(
            actor=actor,
            total_actions=total_actions,
            unique_fingerprints=unique_fingerprints,
            diversity_score=diversity_score,
            dominant_fingerprint=dominant_fingerprint,
            dominant_fingerprint_prefix=dominant_prefix,
            dominant_share=dominant_share,
            collapse_warning=collapse_warning,
        )

    def _binary_integrity_summary(
        self,
        capture_integrity: Callable[
            [dict[str, tuple[str, ...]]], tuple[IntegritySample, ...]
        ]
        | None,
    ) -> BinaryIntegritySummary:
        if not self.config.binary_integrity_enabled:
            return BinaryIntegritySummary(enabled=False)
        checked_services = tuple(sorted(self._integrity_targets))
        checked_paths = sum(len(paths) for paths in self._integrity_targets.values())
        if (
            not checked_services
            or not self._integrity_available
            or not callable(capture_integrity)
        ):
            return BinaryIntegritySummary(
                enabled=True,
                available=False,
                checked_services=checked_services,
                checked_paths=checked_paths,
            )
        current_samples = capture_integrity(self._integrity_targets)
        current_map = {
            (sample.service_id, sample.path): sample for sample in current_samples
        }
        deltas: list[IntegrityDelta] = []
        for key, baseline in sorted(self._integrity_baseline.items()):
            current = current_map.get(
                key,
                IntegritySample(
                    service_id=baseline.service_id,
                    path=baseline.path,
                    exists=False,
                    digest="",
                ),
            )
            if baseline.exists != current.exists or baseline.digest != current.digest:
                deltas.append(
                    IntegrityDelta(
                        service_id=baseline.service_id,
                        path=baseline.path,
                        before_exists=baseline.exists,
                        after_exists=current.exists,
                        before_digest=baseline.digest,
                        after_digest=current.digest,
                    )
                )
        changed_services = tuple(sorted({delta.service_id for delta in deltas}))
        changed_service_set = set(changed_services)
        unchanged_services = tuple(
            service_id
            for service_id in checked_services
            if service_id not in changed_service_set
        )
        return BinaryIntegritySummary(
            enabled=True,
            available=True,
            checked_services=checked_services,
            checked_paths=checked_paths,
            changed_services=changed_services,
            unchanged_services=unchanged_services,
            changed_paths=tuple(deltas),
        )


def command_text_for_action(action: Action) -> str:
    """Return a stable textual action description for audit classification."""

    target = action_target(action)
    if action.kind == "shell":
        return str(
            action.payload.get("service_command", action.payload.get("command", ""))
        ).strip()
    if action.kind == "mail":
        sender = str(action.payload.get("from", action.actor_id))
        recipient = str(action.payload.get("to", "noreply@corp.local"))
        subject = str(action.payload.get("subject", "routine update"))
        return f"mail {target or 'svc-email'} {sender} {recipient} {subject}"
    if action.kind == "api":
        path = str(action.payload.get("path", "/") or "/")
        query = action.payload.get("query", {})
        query_text = ""
        if isinstance(query, dict) and query:
            query_text = " " + json.dumps(query, sort_keys=True, separators=(",", ":"))
        return f"api {target} {path}{query_text}".strip()
    if action.kind == "control":
        directive = str(action.payload.get("action", "contain")).lower()
        return f"{directive} {target}".strip()
    if action.kind == "submit_finding":
        event_type = str(
            action.payload.get("event_type", action.payload.get("event", ""))
        )
        return f"submit_finding {event_type} {target}".strip()
    return action.kind


def fallback_fingerprint_source(action: Action) -> str:
    target = action_target(action)
    if target:
        return f"{action.kind} {target}"
    return action.kind


def fingerprint_prefix_for_command(command: str, *, token_limit: int) -> str:
    tokens = _command_tokens(command)
    while tokens and _ENV_ASSIGNMENT_RE.match(tokens[0]):
        tokens.pop(0)
    if not tokens:
        cleaned = command.strip().lower()
        return cleaned or "unknown"
    return " ".join(tokens[:token_limit]).lower()


def match_suspicious_patterns(
    command: str, compiled_patterns: tuple[tuple[str, re.Pattern[str]], ...]
) -> tuple[str, ...]:
    if not command:
        return ()
    return tuple(
        pattern for pattern, regex in compiled_patterns if regex.search(command)
    )


def integrity_targets_for_snapshot(
    snapshot: RuntimeSnapshot, config: AuditConfig
) -> dict[str, tuple[str, ...]]:
    if not config.binary_integrity_enabled:
        return {}
    selected_services = set(config.binary_integrity_services)
    chart_services = snapshot.artifacts.chart_values.get("services", {})
    targets: dict[str, tuple[str, ...]] = {}
    for service_id, payload in sorted(chart_services.items()):
        if selected_services and service_id not in selected_services:
            continue
        mount_paths = []
        for item in payload.get("payloads", []):
            path = item.get("mountPath")
            if (
                not isinstance(path, str)
                or not path
                or _is_volatile_integrity_path(path)
            ):
                continue
            mount_paths.append(path)
        mount_paths.extend(config.binary_integrity_paths)
        unique_paths = tuple(dict.fromkeys(mount_paths))
        if unique_paths:
            targets[service_id] = unique_paths[
                : config.binary_integrity_max_paths_per_service
            ]
    return targets


def _compile_patterns(
    patterns: tuple[str, ...],
) -> tuple[tuple[str, re.Pattern[str]], ...]:
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern in patterns:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE)
        compiled.append((pattern, regex))
    return tuple(compiled)


def _command_tokens(command: str) -> list[str]:
    if not command:
        return []
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _is_volatile_integrity_path(path: str) -> bool:
    return path.endswith(_VOLATILE_INTEGRITY_SUFFIXES)


def _truncate(command: str, limit: int = 512) -> str:
    if len(command) <= limit:
        return command
    return f"{command[: limit - 3]}..."
