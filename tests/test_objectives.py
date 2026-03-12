from __future__ import annotations

from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.predicates import PredicateEngine
from tests.support import manifest_payload


def _manifest_payload() -> dict:
    payload = manifest_payload()
    payload["objectives"]["red"] = [
        {"predicate": "asset_read(finance_docs)"},
        {"predicate": "credential_obtained(idp_admin_cred)"},
    ]
    return payload


def test_predicate_engine_builds_service_native_graders_for_red_objectives() -> None:
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    predicates = PredicateEngine(world)

    graders = {objective.predicate: predicates.objective_grader(objective.predicate) for objective in world.red_objectives}

    assert graders["asset_read(finance_docs)"] is not None
    assert graders["asset_read(finance_docs)"].grader_kind == "file_exists"
    assert graders["credential_obtained(idp_admin_cred)"] is not None
    assert graders["credential_obtained(idp_admin_cred)"].grader_kind == "event_present"
    assert graders["credential_obtained(idp_admin_cred)"].objective_tag == "privilege_escalation"
