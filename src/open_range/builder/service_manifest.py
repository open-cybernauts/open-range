"""Generate ServiceSpec metadata from snapshot service instances.

The lifecycle knowledge for known service families lives in
``service_catalog.py``. This module stays as the compatibility adapter that
turns explicit or inferred service instances into ``ServiceSpec`` entries for
rendering, validation, and orchestration metadata.
"""

from __future__ import annotations

import logging
from typing import Any

from open_range.builder.service_catalog import (
    infer_service_instances,
    legacy_host_hints,
    legacy_image_hints,
    resolve_service_archetype,
)
from open_range.protocols import ReadinessCheck, ServiceInstance, ServiceSpec

logger = logging.getLogger(__name__)

_LegacyHint = tuple[str, list[str], list[str], str, ReadinessCheck]

_IMAGE_SERVICE_HINTS: dict[str, _LegacyHint] = legacy_image_hints()
_HOST_NAME_HINTS: dict[str, str] = legacy_host_hints()
_DEFAULT_LOG_DIR = "/var/log/siem"


def generate_service_specs(
    compose: dict[str, Any],
    topology: dict[str, Any],
    *,
    service_instances: list[ServiceInstance] | None = None,
) -> list[ServiceSpec]:
    """Generate ServiceSpec entries from explicit or inferred service instances."""
    instances = infer_service_instances(
        compose=compose,
        topology=topology,
        existing=service_instances,
    )
    specs: list[ServiceSpec] = []
    seen_identities: set[tuple[str, str]] = set()

    for instance in instances:
        spec = _service_spec_from_instance(instance)
        if spec is None:
            logger.debug(
                "No service archetype for instance %r on host %r",
                instance.service_name or instance.instance_id,
                instance.host,
            )
            continue
        identity = (spec.host, spec.daemon)
        if identity in seen_identities:
            continue
        seen_identities.add(identity)
        specs.append(spec)

    return specs


def _match_image_hint(image: str) -> _LegacyHint | None:
    """Legacy image-hint adapter retained for compatibility/tests."""
    archetype = resolve_service_archetype(image=image)
    return archetype.to_legacy_hint() if archetype is not None else None


def _service_spec_from_instance(instance: ServiceInstance) -> ServiceSpec | None:
    archetype = resolve_service_archetype(
        image=instance.image,
        service_name=instance.service_name or instance.archetype,
        host_name=instance.host,
    )
    if archetype is None:
        return None

    startup_contract = instance.startup_contract if isinstance(instance.startup_contract, dict) else {}
    log_dir = str(startup_contract.get("log_dir", _DEFAULT_LOG_DIR)).strip() or _DEFAULT_LOG_DIR
    spec = archetype.build_service_spec(
        host=instance.host,
        log_dir=log_dir,
        env_vars=dict(instance.env_vars),
    )

    readiness_raw = startup_contract.get("readiness")
    readiness = spec.readiness
    if isinstance(readiness_raw, dict):
        readiness = ReadinessCheck(**readiness_raw)
    elif isinstance(readiness_raw, ReadinessCheck):
        readiness = readiness_raw.model_copy()

    packages = _coerce_str_list(startup_contract.get("packages")) or spec.packages
    init_commands = _coerce_str_list(startup_contract.get("init_commands")) or spec.init_commands
    start_command = str(startup_contract.get("start_command", "")).strip() or spec.start_command
    env_overrides = startup_contract.get("env_vars")
    if not isinstance(env_overrides, dict):
        env_overrides = {}

    return spec.model_copy(
        update={
            "packages": packages,
            "init_commands": init_commands,
            "start_command": start_command,
            "readiness": readiness,
            "log_dir": log_dir,
            "env_vars": {**spec.env_vars, **{str(k): str(v) for k, v in env_overrides.items()}},
        }
    )


def _coerce_str_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if str(item).strip()]
