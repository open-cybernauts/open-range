from __future__ import annotations

from pathlib import Path

from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.admit import LocalAdmissionController
from open_range.audit import ActionAuditor, AuditConfig, integrity_targets_for_snapshot
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.execution import ActionExecution
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.runtime_types import Action, IntegritySample
from open_range.store import FileSnapshotStore
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _snapshot(tmp_path: Path):
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(manifest_payload())
    )
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_BUILD_CONFIG
    )
    store = FileSnapshotStore(tmp_path / "snapshots")
    return hydrate_runtime_snapshot(
        store, store.create(world, artifacts, reference_bundle, report, synth=synth)
    )


def test_action_auditor_flags_suspicious_commands_and_normalizes_prefixes() -> None:
    auditor = ActionAuditor(
        AuditConfig(
            suspicious_patterns=(r"\bgit\s+clone\b",), fingerprint_token_limit=2
        )
    )
    action = Action(
        actor_id="red",
        role="red",
        kind="shell",
        payload={
            "command": "GIT_SSH_COMMAND='ssh -v' git clone https://example.com/repo"
        },
    )

    observation = auditor.observe(
        action=action,
        executed_command=ActionExecution(
            executed_command=action.payload["command"]
        ).executed_command,
        sim_time=3.25,
        controlled=True,
    )
    auditor.record(observation, emitted_event_ids=())
    summary = auditor.build_summary()

    assert observation is not None
    assert observation.matched_patterns == (r"\bgit\s+clone\b",)
    assert observation.fingerprint_prefix == "git clone"
    assert summary.suspicious_actions[0].command.endswith("https://example.com/repo")
    assert summary.suspicious_actions[0].fingerprint_prefix == "git clone"


def test_action_auditor_warns_when_controlled_actions_collapse() -> None:
    auditor = ActionAuditor(
        AuditConfig(
            diversity_warning_threshold=0.5,
            minimum_actions_for_collapse=3,
        )
    )
    action = Action(
        actor_id="red",
        role="red",
        kind="shell",
        payload={"command": "nmap -sV svc-web"},
    )

    for index in range(4):
        observation = auditor.observe(
            action=action,
            executed_command=action.payload["command"],
            sim_time=float(index),
            controlled=True,
        )
        auditor.record(observation, emitted_event_ids=())

    summary = auditor.build_summary()
    assert summary.action_count == 4
    assert summary.unique_fingerprints == 1
    assert summary.action_diversity_score == 0.25
    assert summary.collapse_warning is True
    assert summary.role_diversity[0].collapse_warning is True
    assert summary.role_diversity[0].dominant_fingerprint_prefix == "nmap -sv"


def test_action_auditor_compares_integrity_snapshots(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    config = AuditConfig(
        binary_integrity_enabled=True,
        binary_integrity_services=("svc-web", "svc-siem"),
    )
    targets = integrity_targets_for_snapshot(snapshot, config)
    auditor = ActionAuditor(config)
    auditor.bind_snapshot(snapshot)

    assert "/srv/http/siem/all.log" not in targets["svc-siem"]
    changed_path = targets["svc-web"][0]

    def baseline(
        service_paths: dict[str, tuple[str, ...]],
    ) -> tuple[IntegritySample, ...]:
        return tuple(
            IntegritySample(
                service_id=service_id,
                path=path,
                exists=True,
                digest=f"baseline-{service_id}-{index}",
            )
            for service_id, paths in sorted(service_paths.items())
            for index, path in enumerate(paths)
        )

    def current(
        service_paths: dict[str, tuple[str, ...]],
    ) -> tuple[IntegritySample, ...]:
        samples: list[IntegritySample] = []
        for service_id, paths in sorted(service_paths.items()):
            for index, path in enumerate(paths):
                digest = f"baseline-{service_id}-{index}"
                if service_id == "svc-web" and path == changed_path:
                    digest = "changed-web-digest"
                samples.append(
                    IntegritySample(
                        service_id=service_id,
                        path=path,
                        exists=True,
                        digest=digest,
                    )
                )
        return tuple(samples)

    auditor.capture_baseline(baseline)
    summary = auditor.build_summary(current)

    assert summary.binary_integrity.enabled is True
    assert summary.binary_integrity.available is True
    assert summary.binary_integrity.changed_services == ("svc-web",)
    assert summary.binary_integrity.changed_paths[0].path == changed_path
