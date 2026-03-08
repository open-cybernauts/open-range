import json

from click.testing import CliRunner

from open_range.cli import cli
from open_range.protocols import CheckResult, ContainerSet
from open_range.server.compose_runner import BootedSnapshotProject
from open_range.validator.validator import ValidationResult


class _DockerAwareCheck:
    def __init__(self) -> None:
        self.saw_containers = {}

    async def check(self, snapshot, containers: ContainerSet) -> CheckResult:
        self.saw_containers = dict(containers.container_ids)
        return CheckResult(
            name="docker_aware",
            passed=bool(containers.container_ids),
            details={"containers": dict(containers.container_ids)},
            error="" if containers.container_ids else "missing containers",
        )


def test_validate_docker_boots_temporary_project_and_passes_live_containers(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    rendered_dirs: list[str] = []
    teardown_calls: list[str] = []
    check = _DockerAwareCheck()

    class FakeRenderer:
        def render(self, spec, output_dir):
            rendered_dirs.append(str(output_dir))
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "docker-compose.yml").write_text(
                "services:\n  attacker:\n    image: alpine\n  web:\n    image: nginx\n",
                encoding="utf-8",
            )
            return output_dir

    class FakeComposeRunner:
        def boot(self, *, snapshot_id, artifacts_dir, compose, project_name=None):
            assert compose["services"].keys() == {"attacker", "web"}
            return BootedSnapshotProject(
                project_name=project_name or f"openrange-{snapshot_id}",
                compose_file=artifacts_dir / "docker-compose.yml",
                artifacts_dir=artifacts_dir,
                containers=ContainerSet(
                    project_name=project_name or f"openrange-{snapshot_id}",
                    container_ids={"attacker": "cid-attacker", "web": "cid-web"},
                ),
            )

        def teardown(self, project):
            teardown_calls.append(project.project_name)

    monkeypatch.setattr("open_range.builder.renderer.SnapshotRenderer", FakeRenderer)
    monkeypatch.setattr("open_range.server.compose_runner.ComposeProjectRunner", FakeComposeRunner)
    monkeypatch.setattr("open_range.cli._CHECK_REGISTRY", {"build_boot": "fake.DockerAwareCheck"})
    monkeypatch.setattr("open_range.cli._import_check", lambda dotted: lambda: check)

    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--snapshot", str(snapshot_path), "--docker"])

    assert result.exit_code == 0, result.output
    assert rendered_dirs
    assert check.saw_containers == {"attacker": "cid-attacker", "web": "cid-web"}
    assert teardown_calls
    assert "Booting temporary Docker project for validation" in result.output
    assert "Validation PASSED" in result.output


def test_validate_rejects_hugging_face_snapshot_deploy_for_docker_only_runtime(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    async def fake_validate(self, snapshot, containers):
        return ValidationResult(passed=True, checks=[], total_time_s=0.0)

    monkeypatch.setattr(
        "open_range.validator.validator.ValidatorGate.validate",
        fake_validate,
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "validate",
            "--snapshot",
            str(snapshot_path),
            "--deploy-hf",
            "--hf-space",
            "test/open-range",
            "--hf-token",
            "hf_test",
            "--checks",
            "isolation",
        ],
    )

    assert result.exit_code == 1, result.output
    assert "Hugging Face deployment failed" in result.output
    assert "Direct Hugging Face snapshot deployment is unsupported" in result.output
