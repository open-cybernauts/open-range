from __future__ import annotations

from types import SimpleNamespace

from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.objectives import evaluate_objective_grader_live
from open_range.predicates import PredicateEngine
from open_range.weaknesses import CatalogWeaknessSeeder
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


def test_live_event_backed_admin_grader_still_requires_the_event() -> None:
    payload = manifest_payload()
    payload["security"]["pinned_weaknesses"] = [
        {
            "family": "config_identity",
            "kind": "admin_surface_exposed",
            "target": "service:svc-idp",
        }
    ]
    world = CatalogWeaknessSeeder().apply(EnterpriseSaaSManifestCompiler().compile(payload))
    predicates = PredicateEngine(world)
    grader = predicates.objective_grader("unauthorized_admin_login(svc-idp)")
    assert grader is not None

    class _Pods:
        async def exec(self, service: str, cmd: str, timeout: float = 10.0):
            del service, cmd, timeout
            return SimpleNamespace(ok=True, stdout="target_ref=svc-idp\nadmin_surface_public=true\n", stderr="")

    snapshot = SimpleNamespace(world=world, file_assets={}, db_seed_state={})

    assert evaluate_objective_grader_live(
        "unauthorized_admin_login(svc-idp)",
        grader,
        snapshot=snapshot,
        pods=_Pods(),
        events=(),
        service_health={"svc-idp": 1.0},
        outputs=("admin_surface public",),
    ) is False

    assert evaluate_objective_grader_live(
        "unauthorized_admin_login(svc-idp)",
        grader,
        snapshot=snapshot,
        pods=_Pods(),
        events=(
            SimpleNamespace(
                event_type="UnauthorizedCredentialUse",
                target_entity="svc-idp",
                linked_objective_predicates=("unauthorized_admin_login(svc-idp)",),
            ),
        ),
        service_health={"svc-idp": 1.0},
        outputs=("admin_surface public",),
    ) is True
