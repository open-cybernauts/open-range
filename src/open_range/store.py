"""Immutable snapshot persistence with explicit runtime hydration."""

from __future__ import annotations

import json
import time
from pathlib import Path
from random import Random
from typing import Literal, Protocol

from open_range.admission import ValidatorReport, ReferenceBundle
from open_range.snapshot import KindArtifacts, RuntimeSnapshot, Snapshot, world_hash
from open_range.synth import SynthArtifacts
from open_range.world_ir import WorldIR


PoolSplit = Literal["train", "eval"]


class SnapshotStore(Protocol):
    def create(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        wb: ReferenceBundle,
        vr: ValidatorReport,
        synth: SynthArtifacts | None = None,
        *,
        split: PoolSplit = "train",
    ) -> Snapshot: ...
    def load(self, snapshot_id: str) -> Snapshot: ...
    def load_world(self, snapshot_id: str) -> WorldIR: ...
    def load_runtime(self, snapshot_id: str) -> RuntimeSnapshot: ...
    def list(self, *, split: PoolSplit | None = None) -> tuple[Snapshot, ...]: ...
    def sample(
        self,
        *,
        split: PoolSplit = "train",
        seed: int | None = None,
        strategy: Literal["random", "latest"] = "random",
    ) -> Snapshot: ...
    def sample_runtime(
        self,
        *,
        split: PoolSplit = "train",
        seed: int | None = None,
        strategy: Literal["random", "latest"] = "random",
    ) -> RuntimeSnapshot: ...


class FileSnapshotStore:
    """Persist immutable snapshots as JSON on disk."""

    def __init__(self, store_dir: str | Path = "snapshots") -> None:
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        wb: ReferenceBundle,
        vr: ValidatorReport,
        synth: SynthArtifacts | None = None,
        *,
        split: PoolSplit = "train",
    ) -> Snapshot:
        db_seed_state = {"services": [svc.id for svc in world.services if svc.kind == "db"]}
        mail_state = {"mailboxes": [persona.mailbox for persona in world.green_personas if persona.mailbox]}
        file_assets = {asset.id: asset.location for asset in world.assets}
        identity_seed = {"users": [user.id for user in world.users]}
        state_seed_dir = artifacts.render_dir
        if synth is not None:
            db_seed_state = {
                "services": [svc.id for svc in world.services if svc.kind == "db"],
                "payload_files": [item.key for item in synth.service_payloads.get("svc-db", ())],
            }
            mail_state = {mailbox: list(messages) for mailbox, messages in synth.mailboxes.items()}
            file_assets = {
                synth_file.key: synth_file.mount_path
                for synth_file in synth.service_payloads.get("svc-fileshare", ())
            }
            identity_seed = {
                "users": [user.id for user in world.users],
                "mailboxes": sorted(synth.mailboxes),
            }
            state_seed_dir = synth.outdir
        snapshot_id = f"{world.world_id}-{world_hash(world)[:8]}"
        snap_dir = self.store_dir / snapshot_id
        snap_dir.mkdir(parents=True, exist_ok=True)
        world_path = snap_dir / "world.json"
        reference_bundle_path = snap_dir / "reference_bundle.json"
        validator_report_path = snap_dir / "validator_report.json"
        world_path.write_text(world.model_dump_json(indent=2), encoding="utf-8")
        reference_bundle_path.write_text(wb.model_dump_json(indent=2), encoding="utf-8")
        validator_report_path.write_text(vr.model_dump_json(indent=2), encoding="utf-8")
        snapshot = Snapshot(
            snapshot_id=snapshot_id,
            world_id=world.world_id,
            seed=world.seed,
            artifacts_dir=artifacts.render_dir,
            image_digests=artifacts.pinned_image_digests,
            state_seed_dir=state_seed_dir,
            world_path=str(world_path),
            reference_bundle_path=str(reference_bundle_path),
            validator_report_path=str(validator_report_path),
            artifacts=artifacts,
            db_seed_state=db_seed_state,
            mail_state=mail_state,
            file_assets=file_assets,
            identity_seed=identity_seed,
            validator_report=vr,
            world_hash=world_hash(world),
            parent_snapshot_id=None,
            parent_world_id=world.lineage.parent_world_id,
        )
        (snap_dir / "snapshot.json").write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
        (snap_dir / "metadata.json").write_text(
            json.dumps(
                {
                    "snapshot_id": snapshot_id,
                    "world_id": world.world_id,
                    "world_hash": snapshot.world_hash,
                    "stored_at": time.time(),
                    "weakness_count": len(world.weaknesses),
                    "service_count": len(world.services),
                    "split": split,
                },
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        return snapshot

    def load(self, snapshot_id: str) -> Snapshot:
        path = self.store_dir / snapshot_id / "snapshot.json"
        if not path.exists():
            raise FileNotFoundError(snapshot_id)
        return Snapshot.model_validate_json(path.read_text(encoding="utf-8"))

    def load_world(self, snapshot_id: str) -> WorldIR:
        snapshot = self.load(snapshot_id)
        world_path = Path(snapshot.world_path)
        return WorldIR.model_validate_json(world_path.read_text(encoding="utf-8"))

    def hydrate(self, snapshot: Snapshot) -> RuntimeSnapshot:
        world_path = Path(snapshot.world_path)
        world = WorldIR.model_validate_json(world_path.read_text(encoding="utf-8"))
        reference_path = Path(snapshot.reference_bundle_path)
        reference_bundle = ReferenceBundle.model_validate_json(reference_path.read_text(encoding="utf-8"))
        return RuntimeSnapshot.model_validate(
            {
                **snapshot.model_dump(mode="json"),
                "world": world.model_dump(mode="json"),
                "reference_bundle": reference_bundle.model_dump(mode="json"),
            }
        )

    def load_runtime(self, snapshot_id: str) -> RuntimeSnapshot:
        return self.hydrate(self.load(snapshot_id))

    def list(self, *, split: PoolSplit | None = None) -> tuple[Snapshot, ...]:
        snapshots: list[Snapshot] = []
        for entry in sorted(self.store_dir.iterdir(), key=lambda path: path.name):
            if not entry.is_dir():
                continue
            metadata = self._metadata_for(entry.name)
            if split is not None and metadata.get("split", "train") != split:
                continue
            snapshot_path = entry / "snapshot.json"
            if not snapshot_path.exists():
                continue
            snapshots.append(
                Snapshot.model_validate_json(snapshot_path.read_text(encoding="utf-8"))
            )
        return tuple(snapshots)

    def sample(
        self,
        *,
        split: PoolSplit = "train",
        seed: int | None = None,
        strategy: Literal["random", "latest"] = "random",
    ) -> Snapshot:
        snapshots = list(self.list(split=split))
        if not snapshots:
            raise FileNotFoundError(f"no snapshots available in split {split!r}")
        if strategy == "latest":
            return snapshots[-1]
        if strategy != "random":
            raise ValueError("strategy must be 'random' or 'latest'")
        rng = Random(seed)
        return snapshots[rng.randrange(len(snapshots))]

    def sample_runtime(
        self,
        *,
        split: PoolSplit = "train",
        seed: int | None = None,
        strategy: Literal["random", "latest"] = "random",
    ) -> RuntimeSnapshot:
        return self.hydrate(self.sample(split=split, seed=seed, strategy=strategy))

    def _metadata_for(self, snapshot_id: str) -> dict[str, object]:
        metadata_path = self.store_dir / snapshot_id / "metadata.json"
        if not metadata_path.exists():
            return {"split": "train"}
        return json.loads(metadata_path.read_text(encoding="utf-8"))
