"""Tests for HelmRunner and KubePodSet.

Unit tests that don't require a live Kind cluster -- mock subprocess
calls to verify the runner wires up helm/kubectl commands correctly.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from open_range.server.helm_runner import (
    BootedRelease,
    BootedSnapshotProject,
    HelmRunner,
    KubePodSet,
)


# ---------------------------------------------------------------------------
# KubePodSet
# ---------------------------------------------------------------------------


class TestKubePodSet:
    def test_resolve_namespace_slash_pod(self):
        ps = KubePodSet(
            project_name="or-test",
            container_ids={"web": "openrange-dmz/web-abc123"},
        )
        ns, pod = ps._resolve("web")
        assert ns == "openrange-dmz"
        assert pod == "web-abc123"

    def test_resolve_fallback_to_project_name(self):
        ps = KubePodSet(
            project_name="or-test",
            container_ids={"web": "web-abc123"},
        )
        ns, pod = ps._resolve("web")
        assert ns == "or-test"
        assert pod == "web-abc123"

    def test_resolve_unknown_container(self):
        ps = KubePodSet(project_name="or-test", container_ids={})
        ns, pod = ps._resolve("missing")
        assert ns == "or-test"
        assert pod == "missing"

    @pytest.mark.asyncio
    async def test_exec_builds_kubectl_command(self):
        ps = KubePodSet(
            project_name="or-test",
            container_ids={"web": "openrange-dmz/web-pod-1"},
        )
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"hello\n", None))
            mock_exec.return_value = mock_proc

            result = await ps.exec("web", "echo hello")

            assert result == "hello\n"
            args = mock_exec.call_args[0]
            assert args[0] == "kubectl"
            assert args[1] == "exec"
            assert "web-pod-1" in args
            assert "-n" in args
            idx = list(args).index("-n")
            assert args[idx + 1] == "openrange-dmz"

    @pytest.mark.asyncio
    async def test_exec_timeout_returns_marker(self):
        import asyncio

        ps = KubePodSet(
            project_name="or-test",
            container_ids={"web": "openrange-dmz/web-pod-1"},
        )
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_proc.kill = MagicMock()
            mock_exec.return_value = mock_proc

            result = await ps.exec("web", "sleep 100", timeout=0.001)
            assert result == "<timeout>"

    @pytest.mark.asyncio
    async def test_is_healthy_checks_phase_and_ready(self):
        ps = KubePodSet(
            project_name="or-test",
            container_ids={"web": "openrange-dmz/web-pod-1"},
        )
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            # First call: phase=Running, second call: Ready=True
            mock_proc1 = MagicMock()
            mock_proc1.communicate = AsyncMock(return_value=(b"Running", None))
            mock_proc2 = MagicMock()
            mock_proc2.communicate = AsyncMock(return_value=(b"True", None))
            mock_exec.side_effect = [mock_proc1, mock_proc2]

            result = await ps.is_healthy("web")
            assert result is True

    @pytest.mark.asyncio
    async def test_is_healthy_false_when_pending(self):
        ps = KubePodSet(
            project_name="or-test",
            container_ids={"web": "openrange-dmz/web-pod-1"},
        )
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"Pending", None))
            mock_exec.return_value = mock_proc

            result = await ps.is_healthy("web")
            assert result is False

    @pytest.mark.asyncio
    async def test_restart_deletes_pod(self):
        ps = KubePodSet(
            project_name="or-test",
            container_ids={"web": "openrange-dmz/web-pod-1"},
        )
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", None))
            mock_exec.return_value = mock_proc

            await ps.restart("web")

            args = mock_exec.call_args[0]
            assert "kubectl" in args
            assert "delete" in args
            assert "pod" in args
            assert "web-pod-1" in args

    @pytest.mark.asyncio
    async def test_cp_builds_kubectl_cp(self):
        ps = KubePodSet(
            project_name="or-test",
            container_ids={"web": "openrange-dmz/web-pod-1"},
        )
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", None))
            mock_exec.return_value = mock_proc

            await ps.cp("web", "/tmp/file.txt", "/var/www/file.txt")

            args = mock_exec.call_args[0]
            assert "kubectl" in args
            assert "cp" in args


# ---------------------------------------------------------------------------
# HelmRunner
# ---------------------------------------------------------------------------


class TestHelmRunner:
    def test_release_name_for_simple(self):
        assert HelmRunner.release_name_for("my_snap") == "or-my-snap"

    def test_release_name_for_truncates(self):
        long_id = "a" * 100
        name = HelmRunner.release_name_for(long_id)
        assert len(name) <= 53
        assert name.startswith("or-")

    def test_release_name_for_special_chars(self):
        name = HelmRunner.release_name_for("snap_foo.bar/baz!123")
        assert all(c.isalnum() or c == "-" for c in name)

    def test_project_name_for_alias(self):
        """project_name_for is an alias for release_name_for."""
        runner = HelmRunner()
        assert runner.project_name_for("test") == runner.release_name_for("test")

    def test_booted_release_fields(self):
        ps = KubePodSet(project_name="or-test", container_ids={"web": "ns/pod"})
        release = BootedRelease(
            release_name="or-test",
            chart_dir=Path("/tmp/chart"),
            artifacts_dir=Path("/tmp/artifacts"),
            containers=ps,
        )
        assert release.release_name == "or-test"
        assert release.containers is ps

    def test_booted_snapshot_project_alias(self):
        """BootedSnapshotProject is an alias for BootedRelease."""
        assert BootedSnapshotProject is BootedRelease

    def test_boot_calls_helm_install(self):
        runner = HelmRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            artifacts = Path(tmpdir)
            chart = artifacts / "openrange"
            chart.mkdir()
            (chart / "Chart.yaml").write_text("apiVersion: v2\nname: test\n")

            with patch.object(runner, "_run") as mock_run, \
                 patch.object(runner, "_discover_pods", return_value={"web": "ns/web-1"}), \
                 patch.object(runner, "_wait_until_healthy"):
                mock_run.return_value = MagicMock(stdout="", returncode=0)

                release = runner.boot(
                    snapshot_id="snap1",
                    artifacts_dir=artifacts,
                )

                assert release.release_name == HelmRunner.release_name_for("snap1")
                mock_run.assert_called_once()
                call_args = mock_run.call_args[0][0]
                assert "helm" in call_args
                assert "upgrade" in call_args
                assert "--install" in call_args

    def test_teardown_calls_helm_uninstall(self):
        runner = HelmRunner()
        ps = KubePodSet(project_name="or-snap1", container_ids={})
        release = BootedRelease(
            release_name="or-snap1",
            chart_dir=Path("/tmp/chart"),
            artifacts_dir=Path("/tmp"),
            containers=ps,
        )
        with patch.object(runner, "_run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", returncode=0)
            runner.teardown(release)
            call_args = mock_run.call_args[0][0]
            assert "helm" in call_args
            assert "uninstall" in call_args
            assert "or-snap1" in call_args

    def test_discover_pods_parses_jsonpath(self):
        runner = HelmRunner()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "openrange-dmz/web-abc123 web\n"
            "openrange-internal/db-def456 db\n"
            "openrange-external/attacker-ghi789 attacker\n"
        )
        with patch.object(runner, "_run", return_value=mock_result):
            pods = runner._discover_pods("or-test")
            assert pods == {
                "web": "openrange-dmz/web-abc123",
                "db": "openrange-internal/db-def456",
                "attacker": "openrange-external/attacker-ghi789",
            }

    def test_discover_pods_empty_returns_empty(self):
        runner = HelmRunner()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        with patch.object(runner, "_run", return_value=mock_result):
            pods = runner._discover_pods("or-test")
            assert pods == {}
