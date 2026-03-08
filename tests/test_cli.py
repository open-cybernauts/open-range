import json
from types import SimpleNamespace

from click.testing import CliRunner

from open_range.cli import cli
from open_range.protocols import CheckResult, ContainerSet
from open_range.server.helm_runner import BootedRelease


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
            chart_dir = output_dir / "openrange"
            chart_dir.mkdir(parents=True, exist_ok=True)
            (chart_dir / "values.yaml").write_text(
                "services:\n  attacker:\n    image: kali\n  web:\n    image: nginx\n",
                encoding="utf-8",
            )
            (output_dir / "kind-config.yaml").write_text("kind: Cluster\n", encoding="utf-8")
            return output_dir

    class FakeHelmRunner:
        def boot(self, *, snapshot_id, artifacts_dir, compose, project_name=None):
            assert compose["services"].keys() == {"attacker", "web"}
            return BootedRelease(
                release_name=project_name or f"or-{snapshot_id}",
                chart_dir=artifacts_dir / "openrange",
                artifacts_dir=artifacts_dir,
                containers=ContainerSet(
                    project_name=project_name or f"openrange-{snapshot_id}",
                    container_ids={"attacker": "cid-attacker", "web": "cid-web"},
                ),
            )

        def teardown(self, project):
            teardown_calls.append(project.project_name)

    monkeypatch.setattr("open_range.builder.renderer.KindRenderer", FakeRenderer)
    monkeypatch.setattr("open_range.server.helm_runner.HelmRunner", FakeHelmRunner)
    monkeypatch.setattr("open_range.cli._CHECK_REGISTRY", {"build_boot": "fake.DockerAwareCheck"})
    monkeypatch.setattr("open_range.cli._import_check", lambda dotted: lambda: check)

    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--snapshot", str(snapshot_path), "--docker"])

    assert result.exit_code == 0, result.output
    assert rendered_dirs
    assert check.saw_containers == {"attacker": "cid-attacker", "web": "cid-web"}
    assert teardown_calls
    assert "Booting temporary Helm release for validation" in result.output
    assert "Validation PASSED" in result.output


def test_validate_docker_uses_rendered_values_for_live_checks(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    class _RenderedSpecCheck:
        def __init__(self) -> None:
            self.compose = {}
            self.saw_containers = {}

        async def check(self, snapshot, containers: ContainerSet) -> CheckResult:
            self.compose = dict(snapshot.compose)
            self.saw_containers = dict(containers.container_ids)
            return CheckResult(name="rendered_spec", passed=bool(self.compose))

    check = _RenderedSpecCheck()

    class FakeRenderer:
        def render(self, spec, output_dir):
            chart_dir = output_dir / "openrange"
            chart_dir.mkdir(parents=True, exist_ok=True)
            (chart_dir / "values.yaml").write_text(
                "services:\n  web:\n    image: nginx\n  db:\n    image: mysql\n",
                encoding="utf-8",
            )
            (output_dir / "kind-config.yaml").write_text("kind: Cluster\n", encoding="utf-8")
            return output_dir

    class FakeHelmRunner:
        def boot(self, *, snapshot_id, artifacts_dir, compose, project_name=None):
            assert compose["services"].keys() == {"web", "db"}
            return BootedRelease(
                release_name=project_name or f"or-{snapshot_id}",
                chart_dir=artifacts_dir / "openrange",
                artifacts_dir=artifacts_dir,
                containers=ContainerSet(
                    project_name=project_name or f"or-{snapshot_id}",
                    container_ids={"web": "pod-web", "db": "pod-db"},
                ),
            )

        def teardown(self, project):
            return None

    monkeypatch.setattr("open_range.builder.renderer.KindRenderer", FakeRenderer)
    monkeypatch.setattr("open_range.server.helm_runner.HelmRunner", FakeHelmRunner)
    monkeypatch.setattr("open_range.cli._CHECK_REGISTRY", {"build_boot": "fake.DockerAwareCheck"})
    monkeypatch.setattr("open_range.cli._import_check", lambda dotted: lambda: check)

    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--snapshot", str(snapshot_path), "--docker"])

    assert result.exit_code == 0, result.output
    assert check.compose["services"]["web"]["image"] == "nginx"
    assert check.saw_containers == {"web": "pod-web", "db": "pod-db"}


def test_validate_can_deploy_to_hugging_face_after_success(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    deployed = {}

    def fake_deploy(snapshot, *, space_id, token, create_repo, private, commit_message):
        deployed.update(
            {
                "snapshot": snapshot,
                "space_id": space_id,
                "token": token,
                "create_repo": create_repo,
                "private": private,
                "commit_message": commit_message,
            }
        )
        return SimpleNamespace(commit_url="https://huggingface.co/spaces/test/open-range/commit/abc123")

    monkeypatch.setattr(
        "open_range.hf_space.deploy_validated_snapshot_to_space",
        fake_deploy,
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

    assert result.exit_code == 0, result.output
    assert deployed["snapshot"] == str(snapshot_path)
    assert deployed["space_id"] == "test/open-range"
    assert deployed["token"] == "hf_test"
    assert deployed["create_repo"] is True
    assert "Hugging Face deployment complete." in result.output


def test_deploy_installs_rendered_chart_on_kind_cluster(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    compose_dir = tmp_path / "deploy"
    commands: list[list[str]] = []

    class FakeRenderer:
        def render(self, spec, output_dir):
            chart_dir = output_dir / "openrange"
            chart_dir.mkdir(parents=True, exist_ok=True)
            (chart_dir / "Chart.yaml").write_text("apiVersion: v2\nname: openrange\n", encoding="utf-8")
            (output_dir / "kind-config.yaml").write_text("kind: Cluster\n", encoding="utf-8")
            return output_dir

    def fake_run(args, capture_output, text, timeout):
        commands.append(list(args))
        if args[:2] == ["kubectl", "get"]:
            return SimpleNamespace(returncode=0, stdout="NAMESPACE NAME\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("open_range.builder.renderer.KindRenderer", FakeRenderer)
    monkeypatch.setattr("subprocess.run", fake_run)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["deploy", "--snapshot", str(snapshot_path), "--chart-dir", str(compose_dir)],
    )

    assert result.exit_code == 0, result.output
    assert commands[0][:3] == ["kind", "create", "cluster"]
    assert commands[1][:2] == ["helm", "install"]
    assert commands[2][:2] == ["kubectl", "get"]
    assert "Kind cluster created. Installing Helm chart ..." in result.output
    assert "Helm chart installed." in result.output
