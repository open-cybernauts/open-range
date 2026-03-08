"""Integration tests for the full renderer pipeline.

Loads real LLM output from snapshots/llm_tier1_test.json, parses it
through _parse_llm_response(), renders through KindRenderer.render(),
and verifies the Helm chart and Kind config contain expected content.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from open_range.builder.builder import _parse_llm_response
from open_range.builder.renderer import KindRenderer

ROOT = Path(__file__).parent.parent
SNAPSHOT_PATH = ROOT / "snapshots" / "llm_tier1_test.json"

pytestmark = pytest.mark.skipif(
    not SNAPSHOT_PATH.exists(),
    reason="LLM fixture snapshots/llm_tier1_test.json not present",
)


@pytest.fixture
def llm_output() -> dict:
    """Load the real LLM output JSON."""
    return json.loads(SNAPSHOT_PATH.read_text())


@pytest.fixture
def parsed_spec(llm_output):
    """Parse real LLM output through _parse_llm_response."""
    return _parse_llm_response(json.dumps(llm_output))


@pytest.fixture
def rendered_dir(parsed_spec):
    """Render the parsed spec and yield the output directory."""
    renderer = KindRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "integration_out"
        renderer.render(parsed_spec, out)
        yield out


@pytest.fixture
def values(rendered_dir):
    """Parse the generated values.yaml."""
    return yaml.safe_load((rendered_dir / "openrange" / "values.yaml").read_text())


# ---------------------------------------------------------------------------
# Pipeline: parse -> render round-trip
# ---------------------------------------------------------------------------


class TestParseLLMOutput:
    """Verify _parse_llm_response correctly handles real LLM output."""

    def test_parse_produces_snapshot_spec(self, parsed_spec):
        from open_range.protocols import SnapshotSpec
        assert isinstance(parsed_spec, SnapshotSpec)

    def test_parse_has_topology(self, parsed_spec):
        assert "hosts" in parsed_spec.topology
        assert len(parsed_spec.topology["hosts"]) == 8

    def test_parse_has_vulns(self, parsed_spec):
        assert len(parsed_spec.truth_graph.vulns) >= 1
        vuln_types = {v.type for v in parsed_spec.truth_graph.vulns}
        assert "sqli" in vuln_types

    def test_parse_has_flags(self, parsed_spec):
        assert len(parsed_spec.flags) >= 2

    def test_parse_has_golden_path(self, parsed_spec):
        assert len(parsed_spec.golden_path) >= 1
        for step in parsed_spec.golden_path:
            assert step.command, f"Step {step.step} has empty command"

    def test_parse_has_task_briefings(self, parsed_spec):
        assert parsed_spec.task.red_briefing
        assert parsed_spec.task.blue_briefing

    def test_parse_has_files(self, parsed_spec):
        assert len(parsed_spec.files) > 0
        web_files = [k for k in parsed_spec.files if k.startswith("web:")]
        assert len(web_files) > 0

    def test_parse_has_npc_personas(self, parsed_spec):
        assert len(parsed_spec.npc_personas) >= 1

    def test_golden_path_uses_command_field(self, parsed_spec):
        for step in parsed_spec.golden_path:
            assert step.command

    def test_golden_path_uses_expect_in_stdout(self, parsed_spec):
        for step in parsed_spec.golden_path:
            assert step.expect_in_stdout


# ---------------------------------------------------------------------------
# Rendered output structure
# ---------------------------------------------------------------------------


class TestRenderedStructure:
    def test_kind_config_exists(self, rendered_dir):
        assert (rendered_dir / "kind-config.yaml").exists()

    def test_helm_chart_exists(self, rendered_dir):
        chart = rendered_dir / "openrange"
        assert chart.is_dir()
        assert (chart / "Chart.yaml").exists()
        assert (chart / "values.yaml").exists()

    def test_all_templates_exist(self, rendered_dir):
        templates = rendered_dir / "openrange" / "templates"
        for name in ["namespaces.yaml", "deployments.yaml", "services.yaml",
                      "configmaps.yaml", "secrets.yaml", "networkpolicies.yaml"]:
            assert (templates / name).exists(), f"Missing: {name}"


# ---------------------------------------------------------------------------
# Kind config verification
# ---------------------------------------------------------------------------


class TestKindConfig:
    def test_valid_kind_config(self, rendered_dir):
        data = yaml.safe_load((rendered_dir / "kind-config.yaml").read_text())
        assert data["kind"] == "Cluster"
        assert data["apiVersion"] == "kind.x-k8s.io/v1alpha4"

    def test_has_control_plane_node(self, rendered_dir):
        data = yaml.safe_load((rendered_dir / "kind-config.yaml").read_text())
        assert len(data["nodes"]) >= 1
        assert data["nodes"][0]["role"] == "control-plane"

    def test_disables_default_cni(self, rendered_dir):
        data = yaml.safe_load((rendered_dir / "kind-config.yaml").read_text())
        assert data["networking"]["disableDefaultCNI"] is True


# ---------------------------------------------------------------------------
# values.yaml content verification
# ---------------------------------------------------------------------------


class TestValuesContent:
    def test_has_all_zones(self, values):
        assert "external" in values["zones"]
        assert "dmz" in values["zones"]
        assert "internal" in values["zones"]
        assert "management" in values["zones"]

    def test_has_core_services(self, values):
        for svc in ["web", "db", "ldap", "siem", "attacker"]:
            assert svc in values["services"], f"Missing service: {svc}"

    def test_services_have_correct_zones(self, values):
        assert values["services"]["web"]["zone"] == "dmz"
        assert values["services"]["db"]["zone"] == "internal"
        assert values["services"]["ldap"]["zone"] == "management"
        assert values["services"]["attacker"]["zone"] == "external"

    def test_services_have_images(self, values):
        for name, svc in values["services"].items():
            assert "image" in svc, f"Service {name} has no image"
            assert svc["image"], f"Service {name} has empty image"

    def test_web_has_db_env(self, values):
        env = values["services"]["web"]["env"]
        assert "internal" in env["DB_HOST"]

    def test_db_has_mysql_env(self, values):
        env = values["services"]["db"]["env"]
        assert env["MYSQL_DATABASE"] == "referral_db"

    def test_has_users(self, values):
        assert len(values["users"]) > 0

    def test_has_flags(self, values):
        assert len(values["flags"]) >= 2


# ---------------------------------------------------------------------------
# Payload files verification
# ---------------------------------------------------------------------------


class TestPayloads:
    def test_web_has_payloads(self, values):
        web = values["services"]["web"]
        assert "payloads" in web
        assert len(web["payloads"]) > 0

    def test_web_payloads_have_php(self, values):
        web_payloads = values["services"]["web"]["payloads"]
        php_payloads = [p for p in web_payloads if ".php" in p.get("key", "")]
        assert len(php_payloads) > 0

    def test_db_has_sql_payload(self, values):
        db = values["services"]["db"]
        if "payloads" in db:
            sql_payloads = [p for p in db["payloads"]
                           if "init.sql" in p.get("mountPath", "")]
            assert len(sql_payloads) >= 1

    def test_payload_content_not_empty(self, values):
        for name, svc in values["services"].items():
            for p in svc.get("payloads", []):
                assert p["content"].strip(), (
                    f"Empty payload content in {name}: {p['key']}"
                )


# ---------------------------------------------------------------------------
# Files preserved through parse
# ---------------------------------------------------------------------------


class TestFilesPreserved:
    def test_files_dict_has_web_files(self, parsed_spec):
        web_files = {k: v for k, v in parsed_spec.files.items() if k.startswith("web:")}
        assert len(web_files) > 0

    def test_files_dict_has_sql(self, parsed_spec):
        assert "db:sql" in parsed_spec.files

    def test_index_php_content(self, parsed_spec):
        key = "web:/var/www/portal/index.php"
        assert key in parsed_spec.files
        assert "Meridian Referral Portal" in parsed_spec.files[key]

    def test_lookup_php_has_sqli(self, parsed_spec):
        key = "web:/var/www/portal/lookup.php"
        assert key in parsed_spec.files
        content = parsed_spec.files[key]
        assert "last_name LIKE" in content or "$last" in content

    def test_sql_has_user_inserts(self, parsed_spec):
        sql = parsed_spec.files.get("db:sql", "")
        assert "dthompson" in sql
        assert "kwilliams" in sql

    def test_sql_has_flag_insert(self, parsed_spec):
        sql = parsed_spec.files.get("db:sql", "")
        assert "FLAG{9f3a2b4c5d6e7f80}" in sql

    def test_files_samba_shares(self, parsed_spec):
        files_entries = {k: v for k, v in parsed_spec.files.items() if k.startswith("files:")}
        assert len(files_entries) > 0
