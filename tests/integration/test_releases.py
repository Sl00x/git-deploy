from __future__ import annotations

import pytest
from sqlalchemy import func, select

from udeploy_api.models import Deployment, Release

from ..conftest import World, drain, publish_release, release_body
from ..factories import COMMIT_B, digest

pytestmark = pytest.mark.integration


async def ci_post(w: World, body: dict) -> tuple[int, dict]:  # type: ignore[type-arg]
    r = await w.api.post(
        "/v1/ci/artifacts/published", json=body, headers={"Authorization": f"Bearer {w.ci_token}"}
    )
    return r.status_code, r.json()


async def test_ci_token_required(world: World) -> None:
    r = await world.api.post("/v1/ci/artifacts/published", json=release_body("1.0.0"))
    assert r.status_code == 401
    r = await world.api.post(
        "/v1/ci/artifacts/published",
        json=release_body("1.0.0"),
        headers={"Authorization": "Bearer udci_forged"},
    )
    assert r.status_code == 401


async def test_notification_before_registry_push_never_deploys(world: World) -> None:
    status, data = await ci_post(world, release_body("1.0.0", branch="main"))
    assert status == 202 and data["status"] == "pending_verification"
    await drain(world.ctx, rounds=10)  # bounded retries, image never appears
    async with world.ctx.db.session() as s:
        rel = await s.get(Release, data["release_id"])
        assert rel is not None and rel.status == "verification_failed"
        assert "not found" in rel.status_detail
        assert await s.scalar(select(func.count()).select_from(Deployment)) == 0


async def test_published_release_is_verified_and_auto_deployed_to_staging_only(world: World) -> None:
    body = release_body("1.1.0", branch="main")
    publish_release(world, body)
    _, data = await ci_post(world, body)
    await drain(world.ctx)
    async with world.ctx.db.session() as s:
        rel = await s.get(Release, data["release_id"])
        assert rel is not None and rel.status == "verified"
        assert all(a.digest_verified for a in rel.artifacts)
        deps = (await s.scalars(select(Deployment))).all()
    assert len(deps) == 1  # staging (branch rule); production needs a v* tag
    assert deps[0].state == "queued"  # no online host yet


async def test_three_services_same_tag_different_digests(world: World) -> None:
    digests = {"api": digest("A"), "worker": digest("W"), "frontend": digest("F")}
    body = release_body("2.0.0", tag="v2.0.0", digests=digests)
    publish_release(world, body)
    _, data = await ci_post(world, body)
    await drain(world.ctx)
    r = await world.api.get(
        f"/v1/releases/{data['release_id']}", headers={"Authorization": world.owner["Authorization"]}
    )
    arts = {a["service"]: a for a in r.json()["artifacts"]}
    assert {a["tag"] for a in arts.values()} == {"2.0.0"}
    assert {s: a["digest"] for s, a in arts.items()} == digests
    assert arts["api"]["image"].endswith("prod/inkerflow_api@" + digests["api"])


async def test_retag_does_not_silently_replace_digest(world: World) -> None:
    body = release_body("3.0.0", tag="v3.0.0")
    publish_release(world, body)
    first_status, first = await ci_post(world, body)
    again_status, again = await ci_post(world, body)  # CI retry: idempotent
    assert (first_status, again_status) == (202, 200) and first["release_id"] == again["release_id"]
    evil = release_body(
        "3.0.0",
        tag="v3.0.0",
        commit=COMMIT_B,
        digests={"api": digest("evil"), "worker": digest("w"), "frontend": digest("f")},
    )
    status, err = await ci_post(world, evil)
    assert status == 409 and err["error"]["code"] == "conflict"


async def test_tag_moved_in_registry_fails_verification(world: World) -> None:
    body = release_body("3.1.0", tag="v3.1.0")
    publish_release(world, body)
    world.registry.tags[("prod/inkerflow_api", "3.1.0")] = digest("force-pushed")
    world.registry.publish("prod/inkerflow_api", digest("force-pushed"))
    _, data = await ci_post(world, body)
    await drain(world.ctx)
    async with world.ctx.db.session() as s:
        rel = await s.get(Release, data["release_id"])
        assert (
            rel is not None and rel.status == "verification_failed" and "now points to" in rel.status_detail
        )


async def test_image_built_from_another_commit_is_refused(world: World) -> None:
    body = release_body("3.2.0", tag="v3.2.0")
    for art in body["artifacts"]:
        world.registry.publish(
            art["image"], art["digest"], art["tag"], labels={"org.opencontainers.image.revision": COMMIT_B}
        )
    _, data = await ci_post(world, body)
    await drain(world.ctx)
    async with world.ctx.db.session() as s:
        rel = await s.get(Release, data["release_id"])
        assert rel is not None and rel.status == "verification_failed" and "built from" in rel.status_detail


async def test_artifact_substitution_refused(world: World) -> None:
    body = release_body("4.0.0")
    body["artifacts"][0]["image"] = "prod/someone-elses-project_api"
    status, err = await ci_post(world, body)
    assert status == 422 and "does not match expected" in err["error"]["message"]


async def test_registry_outage_bounded_retries(world: World) -> None:
    body = release_body("5.0.0", branch="main")
    publish_release(world, body)
    world.registry.unavailable = True
    _, data = await ci_post(world, body)
    results = await drain(world.ctx, rounds=10)
    verify_runs = [r for r in results if r[0] == "udeploy.verify_release"]
    assert len(verify_runs) == world.ctx.settings.release_verify_max_retries
    async with world.ctx.db.session() as s:
        rel = await s.get(Release, data["release_id"])
        assert rel is not None and rel.status == "verification_failed"
        assert "RegistryUnavailable" in rel.status_detail
        assert await s.scalar(select(func.count()).select_from(Deployment)) == 0


async def test_registry_recovers_within_retry_budget(world: World) -> None:
    body = release_body("5.1.0", branch="main")
    publish_release(world, body)
    world.registry.unavailable = True
    _, data = await ci_post(world, body)
    await drain(world.ctx, rounds=1)
    world.registry.unavailable = False
    await drain(world.ctx)
    async with world.ctx.db.session() as s:
        rel = await s.get(Release, data["release_id"])
        assert rel is not None and rel.status == "verified"
