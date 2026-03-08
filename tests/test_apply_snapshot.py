"""Tests for RangeEnvironment._apply_snapshot() with mocked Docker.

Covers file deployment via docker exec (base64 encoding), SQL execution,
container name resolution, error handling, and mixed files dicts.
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, call, patch

import pytest

from open_range.protocols import (
    FlagSpec,
    SnapshotSpec,
    TruthGraph,
    Vulnerability,
)
from open_range.server.environment import RangeEnvironment


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env(docker_available: bool = True) -> RangeEnvironment:
    """Create a RangeEnvironment with docker_available control."""
    return RangeEnvironment(docker_available=docker_available)


def _make_snapshot(files: dict[str, str] | None = None) -> SnapshotSpec:
    """Create a minimal SnapshotSpec with the given files dict."""
    return SnapshotSpec(
        topology={"hosts": ["web", "db"], "zones": {"dmz": ["web"], "internal": ["db"]}},
        truth_graph=TruthGraph(vulns=[]),
        flags=[],
        golden_path=[],
        files=files or {},
    )


class _FakeExecResult:
    """Mimics docker SDK exec_run return value."""

    def __init__(self, stdout: bytes = b"", stderr: bytes = b""):
        self.output = (stdout, stderr)


class _FakeContainer:
    """Minimal fake Docker container."""

    def __init__(self, name: str, exec_side_effect=None):
        self.name = name
        self._exec_side_effect = exec_side_effect or (lambda *a, **kw: _FakeExecResult())

    def exec_run(self, cmd, **kwargs):
        return self._exec_side_effect(cmd, **kwargs)


class _FakeDockerClient:
    """Minimal fake Docker client."""

    def __init__(self, containers: dict[str, _FakeContainer] | None = None):
        self._containers = containers or {}

    @property
    def containers(self):
        return self

    def get(self, name: str):
        if name in self._containers:
            return self._containers[name]
        raise Exception(f"Container {name} not found")

    def list(self):
        return list(self._containers.values())


# ---------------------------------------------------------------------------
# Tests: Docker unavailable
# ---------------------------------------------------------------------------


class TestApplySnapshotNoDocker:
    """When Docker is not available, _apply_snapshot should be a no-op."""

    def test_skips_when_docker_unavailable(self):
        env = _make_env(docker_available=False)
        snapshot = _make_snapshot({"web:/var/www/test.php": "<?php echo 1; ?>"})
        # Should not raise
        env._apply_snapshot(snapshot)

    def test_skips_when_no_files(self):
        env = _make_env(docker_available=False)
        snapshot = _make_snapshot({})
        env._apply_snapshot(snapshot)

    def test_skips_when_files_is_none(self):
        env = _make_env(docker_available=False)
        snapshot = _make_snapshot()
        snapshot.files = {}
        env._apply_snapshot(snapshot)


# ---------------------------------------------------------------------------
# Tests: File deployment via base64
# ---------------------------------------------------------------------------


class TestFileDeployment:
    """Verify files are deployed to containers via base64-encoded docker exec."""

    def test_deploys_single_file(self):
        env = _make_env(docker_available=True)
        content = "<?php echo 'hello'; ?>"
        snapshot = _make_snapshot({"web:/var/www/portal/test.php": content})

        exec_calls = []

        def fake_exec_run(cmd, **kw):
            exec_calls.append(cmd)
            return _FakeExecResult()

        container = _FakeContainer("web", exec_side_effect=fake_exec_run)
        client = _FakeDockerClient({"web": container})
        env._docker_client = client
        env._docker_available = True

        env._apply_snapshot(snapshot)

        # Should have 2 calls: mkdir -p, then echo base64 | base64 -d > path
        assert len(exec_calls) == 2
        # First call: mkdir -p for parent directory
        mkdir_cmd = exec_calls[0]
        assert mkdir_cmd == ["sh", "-c", "mkdir -p '/var/www/portal'"]
        # Second call: base64 write
        write_cmd = exec_calls[1]
        assert isinstance(write_cmd, list)
        write_str = write_cmd[2] if len(write_cmd) > 2 else ""
        expected_b64 = base64.b64encode(content.encode()).decode()
        assert expected_b64 in write_str
        assert "/var/www/portal/test.php" in write_str

    def test_deploys_multiple_files_to_different_containers(self):
        env = _make_env(docker_available=True)
        snapshot = _make_snapshot({
            "web:/var/www/portal/index.php": "<?php echo 'web'; ?>",
            "files:/srv/shares/general/notes.txt": "some notes",
        })

        web_calls = []
        files_calls = []

        web = _FakeContainer(
            "web",
            exec_side_effect=lambda cmd, **kw: (web_calls.append(cmd), _FakeExecResult())[1],
        )
        files_container = _FakeContainer(
            "files",
            exec_side_effect=lambda cmd, **kw: (files_calls.append(cmd), _FakeExecResult())[1],
        )
        client = _FakeDockerClient({"web": web, "files": files_container})
        env._docker_client = client
        env._docker_available = True

        env._apply_snapshot(snapshot)

        # web: 2 calls (mkdir + write)
        assert len(web_calls) == 2
        # files: 2 calls (mkdir + write)
        assert len(files_calls) == 2

    def test_file_at_root_path(self):
        """File at / should still work (edge case for parent dir)."""
        env = _make_env(docker_available=True)
        snapshot = _make_snapshot({"web:/test.txt": "root file"})

        calls = []
        container = _FakeContainer(
            "web",
            exec_side_effect=lambda cmd, **kw: (calls.append(cmd), _FakeExecResult())[1],
        )
        client = _FakeDockerClient({"web": container})
        env._docker_client = client
        env._docker_available = True

        env._apply_snapshot(snapshot)

        # mkdir -p for "/" then base64 write
        assert len(calls) == 2


# ---------------------------------------------------------------------------
# Tests: SQL execution via docker exec
# ---------------------------------------------------------------------------


class TestSQLDeployment:
    """Verify db:sql entries are deployed via mysql commands."""

    def test_deploys_sql_to_db_container(self):
        env = _make_env(docker_available=True)
        sql = "INSERT INTO users VALUES (1, 'test');"
        snapshot = _make_snapshot({"db:sql": sql})

        calls = []

        def fake_exec(cmd, **kw):
            calls.append(cmd)
            return _FakeExecResult()

        db_container = _FakeContainer("db", exec_side_effect=fake_exec)
        client = _FakeDockerClient({"db": db_container})
        env._docker_client = client
        env._docker_available = True

        env._apply_snapshot(snapshot)

        # 3 calls: write SQL file, execute mysql, cleanup
        assert len(calls) == 3

        # First: base64 decode to /tmp/_snapshot.sql
        write_cmd_str = calls[0][2] if len(calls[0]) > 2 else ""
        expected_b64 = base64.b64encode(sql.encode()).decode()
        assert expected_b64 in write_cmd_str
        assert "/tmp/_snapshot.sql" in write_cmd_str

        # Second: mysql < /tmp/_snapshot.sql
        mysql_cmd_str = calls[1][2] if len(calls[1]) > 2 else ""
        assert "mysql" in mysql_cmd_str
        assert "/tmp/_snapshot.sql" in mysql_cmd_str

        # Third: rm -f /tmp/_snapshot.sql
        rm_cmd_str = calls[2][2] if len(calls[2]) > 2 else ""
        assert "rm" in rm_cmd_str
        assert "/tmp/_snapshot.sql" in rm_cmd_str

    def test_sql_error_logs_warning(self, caplog):
        """When mysql returns an ERROR, it should log a warning but not raise."""
        env = _make_env(docker_available=True)
        snapshot = _make_snapshot({"db:sql": "INVALID SQL;"})

        call_count = [0]

        def fake_exec(cmd, **kw):
            call_count[0] += 1
            # Return ERROR on the mysql command (2nd call)
            if call_count[0] == 2:
                return _FakeExecResult(stderr=b"ERROR 1064: Syntax error")
            return _FakeExecResult()

        db_container = _FakeContainer("db", exec_side_effect=fake_exec)
        client = _FakeDockerClient({"db": db_container})
        env._docker_client = client
        env._docker_available = True

        import logging
        with caplog.at_level(logging.WARNING):
            env._apply_snapshot(snapshot)

        assert any("SQL deployment error" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Tests: Container name resolution
# ---------------------------------------------------------------------------


class TestContainerNameResolution:
    """Verify _container_name resolves hosts correctly."""

    def test_resolves_via_compose_config(self):
        env = _make_env(docker_available=False)
        env._snapshot = SnapshotSpec(
            topology={},
            compose={
                "services": {"web": {}, "db": {}},
                "x-project-name": "openrange",
            },
        )
        assert env._container_name("web") == "openrange-web-1"
        assert env._container_name("db") == "openrange-db-1"

    def test_resolves_via_docker_listing(self):
        env = _make_env(docker_available=True)
        env._snapshot = None  # No compose config

        web_container = MagicMock()
        web_container.name = "open-range-web-1"
        db_container = MagicMock()
        db_container.name = "open-range-db-1"

        client = MagicMock()
        client.containers.list.return_value = [web_container, db_container]
        env._docker_client = client

        assert env._container_name("web") == "open-range-web-1"
        assert env._container_name("db") == "open-range-db-1"

    def test_falls_back_to_bare_name(self):
        env = _make_env(docker_available=False)
        env._snapshot = None
        assert env._container_name("web") == "web"


# ---------------------------------------------------------------------------
# Tests: Error handling for failed docker exec
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Verify graceful handling of docker exec failures."""

    def test_file_deployment_handles_exception(self, caplog):
        """If docker exec raises, log warning but continue."""
        env = _make_env(docker_available=True)
        snapshot = _make_snapshot({
            "web:/var/www/good.php": "good",
            "broken:/var/www/fail.php": "bad",
        })

        def fake_exec(cmd, **kw):
            return _FakeExecResult()

        web = _FakeContainer("web", exec_side_effect=fake_exec)
        # 'broken' container doesn't exist
        client = _FakeDockerClient({"web": web})
        env._docker_client = client
        env._docker_available = True

        import logging
        with caplog.at_level(logging.WARNING):
            env._apply_snapshot(snapshot)

        # Should deploy the good file and warn about the broken one
        assert any("Failed to deploy" in r.message or "broken" in r.message
                    for r in caplog.records)

    def test_bad_key_format_skipped(self, caplog):
        """Keys without ':' separator should be skipped with a warning."""
        env = _make_env(docker_available=True)
        snapshot = _make_snapshot({
            "no_colon_here": "this should be skipped",
            "web:/var/www/valid.php": "valid content",
        })

        calls = []
        web = _FakeContainer(
            "web",
            exec_side_effect=lambda cmd, **kw: (calls.append(cmd), _FakeExecResult())[1],
        )
        client = _FakeDockerClient({"web": web})
        env._docker_client = client
        env._docker_available = True

        import logging
        with caplog.at_level(logging.WARNING):
            env._apply_snapshot(snapshot)

        assert any("bad key format" in r.message for r in caplog.records)
        # Only valid file should be deployed (mkdir + write = 2 calls)
        assert len(calls) == 2

    def test_file_write_stderr_error_logged(self, caplog):
        """If file write returns stderr with 'Error', log warning."""
        env = _make_env(docker_available=True)
        snapshot = _make_snapshot({"web:/var/www/fail.php": "content"})

        call_count = [0]

        def fake_exec(cmd, **kw):
            call_count[0] += 1
            # Return error on the write call (2nd call)
            if call_count[0] == 2:
                return _FakeExecResult(stderr=b"Error: permission denied")
            return _FakeExecResult()

        web = _FakeContainer("web", exec_side_effect=fake_exec)
        client = _FakeDockerClient({"web": web})
        env._docker_client = client
        env._docker_available = True

        import logging
        with caplog.at_level(logging.WARNING):
            env._apply_snapshot(snapshot)

        assert any("File deployment error" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Tests: Mixed files dict (file paths + db:sql entries)
# ---------------------------------------------------------------------------


class TestMixedFilesDict:
    """Test snapshot with both regular file deployments and db:sql entries."""

    def test_mixed_deployment(self):
        env = _make_env(docker_available=True)
        snapshot = _make_snapshot({
            "web:/var/www/portal/index.php": "<?php echo 'hello'; ?>",
            "web:/etc/nginx/sites-available/default": "server { listen 80; }",
            "db:sql": "INSERT INTO secrets VALUES ('flag', 'FLAG{test}');",
            "files:/srv/shares/general/notes.txt": "meeting notes",
        })

        container_calls: dict[str, list] = {"web": [], "db": [], "files": []}

        def make_exec(name):
            def fake_exec(cmd, **kw):
                container_calls[name].append(cmd)
                return _FakeExecResult()
            return fake_exec

        containers = {
            name: _FakeContainer(name, exec_side_effect=make_exec(name))
            for name in ["web", "db", "files"]
        }
        client = _FakeDockerClient(containers)
        env._docker_client = client
        env._docker_available = True

        env._apply_snapshot(snapshot)

        # web: 2 files * 2 calls each = 4
        assert len(container_calls["web"]) == 4
        # db: 3 calls (write sql, execute, cleanup)
        assert len(container_calls["db"]) == 3
        # files: 1 file * 2 calls = 2
        assert len(container_calls["files"]) == 2

    def test_deployment_count_in_log(self, caplog):
        """Verify the final log message reports correct deployment counts."""
        env = _make_env(docker_available=True)
        snapshot = _make_snapshot({
            "web:/var/www/test.php": "test",
            "db:sql": "SELECT 1;",
        })

        def fake_exec(cmd, **kw):
            return _FakeExecResult()

        containers = {
            name: _FakeContainer(name, exec_side_effect=fake_exec)
            for name in ["web", "db"]
        }
        client = _FakeDockerClient(containers)
        env._docker_client = client
        env._docker_available = True

        import logging
        with caplog.at_level(logging.INFO):
            env._apply_snapshot(snapshot)

        assert any("2/2 artifacts deployed" in r.message for r in caplog.records)
