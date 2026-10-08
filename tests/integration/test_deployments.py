from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, update

from udeploy_api.models import AgentTaskRow, AuditEvent, DeploymentEvent, DockerHost
from udeploy_api.services.deployments import reconcile
from udeploy_domain.plan import AgentTask
from udeploy_security import pki

from ..conftest import (
    World,
    agent_client,
    auth,
    build_world,
    drain,
    enroll_host,
    publish_release,
    release_body,
)
from ..factories import manifest

pytestmark = pytest.mark.integration


async def verified_release(w: World, version: str, **kw: Any) -> str:
    body = release_body(version, **kw)
    publish_release(w, body)
    r = await w.api.post(
        "/v1/ci/artifacts/published", json=body, headers={"Authorization": f"Bearer {w.ci_token}"}
    )
    assert r.status_code in (200, 202), r.text
    await drain(w.ctx)
    return str(r.json()["release_id"])


async def online_host(w: World, pool: str = "production-docker", name: str = "vps-1") -> tuple[str, bytes]:
    host_id, cert = await enroll_host(w, name=name, pool=pool)
    async with agent_client(w.ctx, cert) as agent:
        r = await agent.post("/v1/agent/heartbeat", json={"agent_version": "test"})
        assert r.status_code == 200, r.text
    return host_id, cert


async def deploy(w: World, release_id: str, env: str, who: dict[str, str], **headers: str) -> dict[str, Any]:
    r = await w.api.post(
        "/v1/deployments",
        json={"project_id": w.project_id, "environment": env, "release_id": release_id},
        headers={**auth(who), **headers},
    )
    assert r.status_code == 202, r.text
    return dict(r.json())


async def claim(w: World, cert: bytes) -> AgentTask | None:
    async with agent_client(w.ctx, cert) as agent:
        r = await agent.post("/v1/agent/tasks/claim", params={"wait": 0})
        assert r.status_code == 200, r.text
        data = r.json()["task"]
        return AgentTask.model_validate(data) if data else None


async def run_agent_steps(
    w: World, cert: bytes, task: AgentTask, outcome: str = "succeeded"
) -> dict[str, Any]:
    async with agent_client(w.ctx, cert) as agent:
        for state in ("pulling", "verifying", "starting", "healthchecking", "switching"):
            r = await agent.post(
                f"/v1/agent/tasks/{task.task_id}/events", json={"state": state, "message": state}
            )
            assert r.status_code == 200, r.text
        result = {"outcome": outcome, "running_digests": {s.name: s.digest for s in task.plan.services}}
        if outcome != "succeeded":
            result["error"] = "health check failed"
        r = await agent.post(f"/v1/agent/tasks/{task.task_id}/complete", json=result)
        assert r.status_code == 200, r.text
        return dict(r.json())


async def get_dep(w: World, dep_id: str) -> dict[str, Any]:
    r = await w.api.get(f"/v1/deployments/{dep_id}", headers=auth(w.owner))
    return dict(r.json())


# ---------------------------------------------------------------------------------------


async def test_full_production_flow_with_four_eyes_approval(world: World) -> None:
    rel = await verified_release(world, "1.0.0", tag="v1.0.0")
    _host_id, cert = await online_host(world)
    dep = await deploy(world, rel, "production", world.deployer)
    assert dep["state"] == "awaiting_approval"

    r = await world.api.post(f"/v1/deployments/{dep['id']}/approve", headers=auth(world.deployer))
    assert r.status_code == 403  # requester cannot approve their own production deployment
    r = await world.api.post(f"/v1/deployments/{dep['id']}/approve", headers=auth(world.owner))
    assert r.status_code == 200 and r.json()["state"] == "queued"

    await drain(world.ctx)
    assert (await get_dep(world, dep["id"]))["state"] == "preparing"
    task = await claim(world, cert)
    assert task is not None and task.plan.environment == "production"
    assert all("@sha256:" in s.image for s in task.plan.services)
    assert (
        task.secrets["inkerflow/database-url"].get_secret_value()
        == "postgres://app:production-pw@db/inkerflow"
    )
    out = await run_agent_steps(world, cert, task)
    assert out["deployment_state"] == "succeeded"
    final = await get_dep(world, dep["id"])
    assert final["state"] == "succeeded" and final["running_digests"]["api"].startswith("sha256:")

    # secrets never leak into the persisted plan, the API output or the audit log
    assert "production-pw" not in json.dumps(final)
    async with world.ctx.db.session() as s:
        audits = json.dumps([e.details for e in (await s.scalars(select(AuditEvent))).all()])
        events = json.dumps([e.message + e.log for e in (await s.scalars(select(DeploymentEvent))).all()])
    assert "production-pw" not in audits and "production-pw" not in events


async def test_developer_cannot_deploy_to_protected_environment(world: World) -> None:
    rel = await verified_release(world, "1.0.0", tag="v1.0.0")
    r = await world.api.post(
        "/v1/deployments",
        json={"project_id": world.project_id, "environment": "production", "release_id": rel},
        headers=auth(world.developer),
    )
    assert r.status_code == 403


async def test_environment_rules_block_wrong_release(world: World) -> None:
    rel = await verified_release(world, "feature-x", branch="feature/x")
    dep = await deploy(world, rel, "production", world.deployer)
    assert dep["state"] == "blocked_by_policy" and "not allowed in production" in dep["error"]


async def test_failed_scan_blocks_deployment(world: World) -> None:
    rel = await verified_release(world, "1.0.1", tag="v1.0.1", scan="failed")
    dep = await deploy(world, rel, "production", world.deployer)
    assert dep["state"] == "blocked_by_policy" and "scan" in dep["error"]


async def test_idempotency_key(world: World) -> None:
    rel = await verified_release(world, "1.0.2", tag="v1.0.2")
    a = await deploy(world, rel, "production", world.deployer, **{"Idempotency-Key": "abc-123"})
    b = await deploy(world, rel, "production", world.deployer, **{"Idempotency-Key": "abc-123"})
    assert a["id"] == b["id"]


async def test_concurrent_deployments_are_serialised(world: World) -> None:
    r1 = await verified_release(world, "1.0.0", tag="v1.0.0")
    r2 = await verified_release(world, "1.1.0", tag="v1.1.0")
    _, cert = await online_host(world)
    d1 = await deploy(world, r1, "production", world.deployer)
    d2 = await deploy(world, r2, "production", world.deployer)
    for d in (d1, d2):
        await world.api.post(f"/v1/deployments/{d['id']}/approve", headers=auth(world.owner))
    await drain(world.ctx, rounds=2)
    states = {(await get_dep(world, d["id"]))["state"] for d in (d1, d2)}
    assert states == {"preparing", "queued"}  # exactly one owns the environment
    task = await claim(world, cert)
    assert task is not None
    await run_agent_steps(world, cert, task)
    await drain(world.ctx)
    task2 = await claim(world, cert)
    assert task2 is not None and task2.plan.deployment_id != task.plan.deployment_id
    assert task2.plan.previous is not None  # the plan knows what it replaces (for rollback)
    await run_agent_steps(world, cert, task2)


async def test_health_failure_reports_rollback_and_previous_stays_current(world: World) -> None:
    r1 = await verified_release(world, "1.0.0", tag="v1.0.0")
    r2 = await verified_release(world, "2.0.0", tag="v2.0.0")
    _, cert = await online_host(world)
    for rel, outcome in ((r1, "succeeded"), (r2, "rolled_back")):
        d = await deploy(world, rel, "production", world.deployer)
        await world.api.post(f"/v1/deployments/{d['id']}/approve", headers=auth(world.owner))
        await drain(world.ctx)
        task = await claim(world, cert)
        assert task is not None
        res = await run_agent_steps(world, cert, task, outcome=outcome)
        assert res["deployment_state"] == outcome
    project = (await world.api.get(f"/v1/projects/{world.project_id}", headers=auth(world.owner))).json()
    prod = next(e for e in project["environments"] if e["name"] == "production")
    current = await get_dep(world, prod["current_deployment_id"])
    assert current["release_id"] == r1  # the failed release never became current


async def test_rollback_endpoint_redeploys_previous_release_by_digest(world: World) -> None:
    r1 = await verified_release(world, "1.0.0", tag="v1.0.0")
    r2 = await verified_release(world, "2.0.0", tag="v2.0.0")
    _, cert = await online_host(world)
    ids = []
    for rel in (r1, r2):
        d = await deploy(world, rel, "production", world.deployer)
        await world.api.post(f"/v1/deployments/{d['id']}/approve", headers=auth(world.owner))
        await drain(world.ctx)
        task = await claim(world, cert)
        assert task is not None
        await run_agent_steps(world, cert, task)
        ids.append(d["id"])
    r = await world.api.post(f"/v1/deployments/{ids[1]}/rollback", headers=auth(world.deployer))
    assert r.status_code == 202, r.text
    rb = r.json()
    assert rb["release_id"] == r1 and rb["trigger"] == "rollback" and rb["state"] == "queued"


async def test_cancel_before_and_during_execution(world: World) -> None:
    rel = await verified_release(world, "1.0.0", tag="v1.0.0")
    d = await deploy(world, rel, "production", world.deployer)
    r = await world.api.post(f"/v1/deployments/{d['id']}/cancel", headers=auth(world.deployer))
    assert r.json()["state"] == "cancelled"

    _, cert = await online_host(world)
    d = await deploy(world, rel, "production", world.deployer)
    await world.api.post(f"/v1/deployments/{d['id']}/approve", headers=auth(world.owner))
    await drain(world.ctx)
    task = await claim(world, cert)
    assert task is not None
    await world.api.post(f"/v1/deployments/{d['id']}/cancel", headers=auth(world.deployer))
    async with agent_client(world.ctx, cert) as agent:
        r = await agent.post(f"/v1/agent/tasks/{task.task_id}/events", json={"state": "pulling"})
        assert r.json()["cancel_requested"] is True


async def test_agent_offline_task_is_requeued_then_failed(world: World) -> None:
    rel = await verified_release(world, "1.0.0", tag="v1.0.0")
    _, cert = await online_host(world)
    d = await deploy(world, rel, "production", world.deployer)
    await world.api.post(f"/v1/deployments/{d['id']}/approve", headers=auth(world.owner))
    await drain(world.ctx)
    for attempt in range(1, world.ctx.settings.task_max_attempts + 1):
        task = await claim(world, cert)  # agent (re)claims, then "crashes"
        assert task is not None and task.attempt == attempt
        async with world.ctx.db.session() as s:
            await s.execute(
                update(AgentTaskRow).values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )
            await s.execute(update(DockerHost).values(last_seen_at=datetime.now(UTC) - timedelta(hours=1)))
            stats = await reconcile(world.ctx, s)
            await s.commit()
    assert stats["failed_tasks"] == 1
    final = await get_dep(world, d["id"])
    assert final["state"] == "failed" and "agent lost" in final["error"]


async def test_no_online_host_keeps_deployment_queued(world: World) -> None:
    rel = await verified_release(world, "1.0.0", tag="v1.0.0")
    d = await deploy(world, rel, "production", world.deployer)
    await world.api.post(f"/v1/deployments/{d['id']}/approve", headers=auth(world.owner))
    results = await drain(world.ctx, rounds=1)
    assert ("udeploy.start_deployment", "waiting_for_host") in results
    assert (await get_dep(world, d["id"]))["state"] == "queued"


# ------------------------------------------------------------------ isolation


async def test_project_b_cannot_reach_project_a(ctx, api) -> None:  # type: ignore[no-untyped-def]
    a = await build_world(ctx, api, slug="acme")
    b = await build_world(
        ctx,
        api,
        slug="globex",
        manifest_doc=manifest(project="shop", repository="globex/shop", domain="other.example"),
    )
    # B's owner cannot see A's project, secrets, deployments or audit log
    assert (await api.get(f"/v1/projects/{a.project_id}", headers=auth(b.owner))).status_code == 404
    r = await api.get(f"/v1/projects/{a.project_id}/environments/production/secrets", headers=auth(b.owner))
    assert r.status_code == 404
    r = await api.put(
        f"/v1/projects/{a.project_id}/environments/production/secrets/x",
        json={"value": "v"},
        headers=auth(b.owner),
    )
    assert r.status_code == 404
    assert (
        await api.get("/v1/audit-events", params={"organization_id": a.org_id}, headers=auth(b.owner))
    ).status_code == 403
    # B's CI token cannot publish releases into A
    body = release_body("9.9.9")
    r = await api.post(
        "/v1/ci/artifacts/published", json=body, headers={"Authorization": f"Bearer {b.ci_token}"}
    )
    assert r.status_code == 422  # services/images do not belong to B's project
    # secrets listing never returns values
    r = await api.get(f"/v1/projects/{a.project_id}/environments/production/secrets", headers=auth(a.owner))
    assert r.json()["items"][0].keys() == {"path", "version", "updated_at"}


async def test_agent_cannot_access_tasks_of_another_host(world: World) -> None:
    rel = await verified_release(world, "1.0.0", tag="v1.0.0")
    _, cert = await online_host(world)
    _, other_cert = await enroll_host(world, name="vps-2", pool="staging-docker")
    d = await deploy(world, rel, "production", world.deployer)
    await world.api.post(f"/v1/deployments/{d['id']}/approve", headers=auth(world.owner))
    await drain(world.ctx)
    assert await claim(world, other_cert) is None
    task = await claim(world, cert)
    assert task is not None
    async with agent_client(world.ctx, other_cert) as other:
        r = await other.post(f"/v1/agent/tasks/{task.task_id}/events", json={"state": "pulling"})
        assert r.status_code == 401


async def test_agent_api_requires_known_certificate(world: World) -> None:
    async with agent_client(world.ctx, None) as anon:
        assert (await anon.post("/v1/agent/tasks/claim")).status_code == 401
    ca_key, ca_cert = pki.create_ca("rogue CA")
    rogue = pki.sign_agent_csr(
        ca_key, ca_cert, pki.make_csr(pki.new_private_key_pem(), "x"), str(uuid.uuid4())
    )
    async with agent_client(world.ctx, rogue) as bad:
        assert (await bad.post("/v1/agent/heartbeat", json={"agent_version": "x"})).status_code == 401


async def test_disabled_host_is_locked_out(world: World) -> None:
    host_id, cert = await online_host(world)
    r = await world.api.post(f"/v1/hosts/{host_id}/disable", headers=auth(world.owner))
    assert r.status_code == 200
    async with agent_client(world.ctx, cert) as agent:
        assert (await agent.post("/v1/agent/heartbeat", json={"agent_version": "x"})).status_code == 401


async def test_enroll_token_is_single_use(world: World) -> None:
    r = await world.api.post(
        "/v1/hosts/enroll-token",
        json={"organization_id": world.org_id, "host_name": "h", "pool": "p"},
        headers=auth(world.owner),
    )
    token = r.json()["token"]
    csr = pki.make_csr(pki.new_private_key_pem(), "h").decode()
    assert (
        await world.api.post("/v1/agent/enroll", json={"token": token, "csr_pem": csr})
    ).status_code == 201
    assert (
        await world.api.post("/v1/agent/enroll", json={"token": token, "csr_pem": csr})
    ).status_code == 401


async def test_hostile_manifest_rejected_via_api(world: World) -> None:
    from ..factories import hostile

    r = await world.api.put(
        f"/v1/projects/{world.project_id}/manifest",
        content=json.dumps(hostile(manifest())),
        headers={**auth(world.owner), "Content-Type": "application/json"},
    )
    assert r.status_code == 422
    errors = "\n".join(r.json()["error"]["details"])
    assert "privileged" in errors and "docker.sock" in errors and "cap_add" in errors


async def test_route_hijack_across_projects_refused(ctx, api) -> None:  # type: ignore[no-untyped-def]
    await build_world(ctx, api, slug="acme")  # owns api.inkerflow.example, inkerflow.example, ...
    w2 = await build_world(
        ctx, api, slug="acme2", manifest_doc=manifest(project="ok", repository="g/ok", domain="other.example")
    )
    evil = manifest(project="evil", repository="group/evil")  # same hosts as acme's project
    r = await api.post(
        "/v1/projects",
        json={
            "organization_id": w2.org_id,
            "slug": "evil",
            "name": "evil",
            "source_provider": "gitlab",
            "repository": "group/evil",
            "manifest": evil,
        },
        headers=auth(w2.owner),
    )
    assert r.status_code == 409 and "already claimed" in r.json()["error"]["message"]


async def test_events_and_history_endpoints(world: World) -> None:
    rel = await verified_release(world, "1.0.0", tag="v1.0.0")
    d = await deploy(world, rel, "production", world.deployer)
    r = await world.api.get(f"/v1/deployments/{d['id']}/events", headers=auth(world.owner))
    assert [e["state"] for e in r.json()["items"]] == ["received", "validated", "awaiting_approval"]
    r = await world.api.get(f"/v1/projects/{world.project_id}/history", headers=auth(world.owner))
    assert r.json()["items"][0]["release_version"] == "1.0.0"
    r = await world.api.get(
        "/v1/audit-events", params={"organization_id": world.org_id}, headers=auth(world.owner)
    )
    actions = {e["action"] for e in r.json()["items"]}
    assert {"release.created", "release.verified", "deployment.requested"} <= actions
    r = await world.api.get(
        "/v1/audit-events", params={"organization_id": world.org_id}, headers=auth(world.developer)
    )
    assert r.status_code == 403  # developers are not auditors
