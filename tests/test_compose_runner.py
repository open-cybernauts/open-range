from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import json
import pytest

from open_range.server.compose_runner import ComposeProjectRunner, apply_rendered_payloads


def test_boot_tears_down_project_when_health_wait_fails(monkeypatch, tmp_path):
    runner = ComposeProjectRunner()
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text("services:\n  attacker:\n    image: alpine\n", encoding="utf-8")

    calls: list[tuple[str, tuple[str, ...]]] = []

    def fake_run(args, *, cwd, timeout):
        calls.append((args[3], tuple(args[5:])))
        if "ps" in args:
            return SimpleNamespace(stdout="cid-attacker\n", returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    def fake_wait(project, services):
        raise RuntimeError("Timed out waiting for healthy services: attacker")

    monkeypatch.setattr(runner, "_run", fake_run)
    monkeypatch.setattr(runner, "_wait_until_healthy", fake_wait)

    with pytest.raises(RuntimeError, match="Timed out waiting for healthy services"):
        runner.boot(
            snapshot_id="spec",
            artifacts_dir=tmp_path,
            compose={"services": {"attacker": {}}},
        )

    down_calls = [args for _project, args in calls if "down" in args]
    assert down_calls, "boot() should tear down the compose project after a health failure"


class _FakeContainers:
    def __init__(self) -> None:
        self.container_ids = {"web": "cid-web", "db": "cid-db"}
        self.exec_calls: list[tuple[str, str]] = []
        self.cp_calls: list[tuple[str, str, str]] = []

    async def exec(self, container: str, cmd: str, **kwargs) -> str:
        self.exec_calls.append((container, cmd))
        return "ok"

    async def cp(self, container: str, src: str, dest: str) -> None:
        self.cp_calls.append((container, src, dest))


def test_apply_rendered_payloads_copies_regular_files_and_sql(tmp_path):
    artifacts_dir = tmp_path
    payload_path = artifacts_dir / "rendered_files" / "web" / "var" / "www" / "portal" / "index.php"
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_path.write_text("<?php echo 'ok'; ?>\n", encoding="utf-8")

    sql_path = artifacts_dir / "rendered_files" / "db" / "sql" / "generated.sql"
    sql_path.parent.mkdir(parents=True, exist_ok=True)
    sql_path.write_text("SELECT 1;\n", encoding="utf-8")

    (artifacts_dir / "file-payloads.json").write_text(
        json.dumps(
            {
                "web:/var/www/portal/index.php": "rendered_files/web/var/www/portal/index.php",
                "db:sql": "rendered_files/db/sql/generated.sql",
            }
        ),
        encoding="utf-8",
    )

    containers = _FakeContainers()
    apply_rendered_payloads(
        containers=containers,  # type: ignore[arg-type]
        artifacts_dir=artifacts_dir,
        compose={"services": {"db": {"environment": {"MYSQL_ROOT_PASSWORD": "sup3rsecret"}}}},
    )

    assert ("web", str(payload_path), "/var/www/portal/index.php") in containers.cp_calls
    assert ("db", str(sql_path), "/tmp/openrange-generated.sql") in containers.cp_calls
    assert ("web", "mkdir -p /var/www/portal") in containers.exec_calls
    assert (
        "db",
        "mysql -u root -psup3rsecret < /tmp/openrange-generated.sql",
    ) in containers.exec_calls
    assert ("db", "rm -f /tmp/openrange-generated.sql") in containers.exec_calls
