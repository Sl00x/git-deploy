from __future__ import annotations

import json
import time
import uuid

import httpx
import pytest
from sqlalchemy import func, select

from udeploy_api.models import AuditEvent, Deployment, WebhookDelivery
from udeploy_security.webhooks import github_signature, standard_webhook_signature

from ..conftest import World, auth, build_world
from ..factories import COMMIT, manifest

pytestmark = pytest.mark.integration


def gh_push(repo: str, ref: str = "refs/tags/v1.0.0") -> bytes:
    return json.dumps(
        {"ref": ref, "after": COMMIT, "repository": {"full_name": repo}, "sender": {"login": "dev"}}
    ).encode()


@pytest.fixture
async def gh_world(ctx, api) -> World:  # type: ignore[no-untyped-def]
    doc = manifest(provider="github", repository="acme/inkerflow")
    return await build_world(ctx, api, manifest_doc=doc)


async def post_github(
    api: httpx.AsyncClient,
    w: World,
    body: bytes,
    *,
    delivery: str | None = None,
    secret: str | None = None,
    event: str = "push",
) -> httpx.Response:
    sig = github_signature((secret or w.webhook["secret"]).encode(), body)
    return await api.post(
        f"/v1/webhooks/github/{w.webhook['id']}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": event,
            "X-GitHub-Delivery": delivery or str(uuid.uuid4()),
        },
    )


async def test_github_valid_signature_is_accepted_but_never_deploys(gh_world: World) -> None:
    r = await post_github(gh_world.api, gh_world, gh_push("acme/inkerflow"))
    assert r.status_code == 202 and r.json()["status"] == "accepted"
    async with gh_world.ctx.db.session() as s:
        assert await s.scalar(select(func.count()).select_from(Deployment)) == 0
        row = await s.scalar(select(WebhookDelivery))
        assert row is not None and row.commit_sha == COMMIT and row.normalized["kind"] == "tag"


async def test_github_invalid_signature_rejected(gh_world: World) -> None:
    r = await post_github(gh_world.api, gh_world, gh_push("acme/inkerflow"), secret="wrong")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"
    async with gh_world.ctx.db.session() as s:
        assert await s.scalar(select(func.count()).select_from(WebhookDelivery)) == 0


async def test_signature_checked_before_json_parsing(gh_world: World) -> None:
    r = await gh_world.api.post(
        f"/v1/webhooks/github/{gh_world.webhook['id']}",
        content=b"{not json",
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "x",
        },
    )
    assert r.status_code == 401  # not 400: garbage is never parsed when unauthenticated


async def test_duplicate_delivery_is_idempotent(gh_world: World) -> None:
    body = gh_push("acme/inkerflow")
    first = await post_github(gh_world.api, gh_world, body, delivery="d-1")
    second = await post_github(gh_world.api, gh_world, body, delivery="d-1")
    assert first.json()["status"] == "accepted"
    assert second.status_code == 202 and second.json()["status"] == "duplicate"
    async with gh_world.ctx.db.session() as s:
        assert await s.scalar(select(func.count()).select_from(WebhookDelivery)) == 1


async def test_repository_confusion_is_rejected(gh_world: World) -> None:
    r = await post_github(gh_world.api, gh_world, gh_push("attacker/other-repo"))
    assert r.json()["status"] == "rejected"


async def test_unknown_endpoint_and_limits(gh_world: World) -> None:
    body = gh_push("acme/inkerflow")
    r = await gh_world.api.post(
        f"/v1/webhooks/github/{uuid.uuid4()}", content=body, headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 404
    r = await gh_world.api.post(
        f"/v1/webhooks/github/{gh_world.webhook['id']}", content=body, headers={"Content-Type": "text/plain"}
    )
    assert r.status_code == 415
    big = b"{" + b" " * (1024 * 1024 + 10) + b"}"
    r = await post_github(gh_world.api, gh_world, big)
    assert r.status_code == 413


async def test_webhook_secret_never_in_audit(gh_world: World) -> None:
    await post_github(gh_world.api, gh_world, gh_push("acme/inkerflow"))
    async with gh_world.ctx.db.session() as s:
        details = [json.dumps(e.details) for e in (await s.scalars(select(AuditEvent))).all()]
    assert not any(gh_world.webhook["secret"] in d for d in details)


# ------------------------------------------------------------------ GitLab


def gl_tag_push(repo: str = "group/inkerflow") -> bytes:
    return json.dumps(
        {
            "object_kind": "tag_push",
            "ref": "refs/tags/v1.0.0",
            "checkout_sha": COMMIT,
            "project": {"path_with_namespace": repo},
            "user_username": "dev",
        }
    ).encode()


async def test_gitlab_token(world: World) -> None:
    url = f"/v1/webhooks/gitlab/{world.webhook['id']}"
    ok = await world.api.post(
        url,
        content=gl_tag_push(),
        headers={
            "Content-Type": "application/json",
            "X-Gitlab-Token": world.webhook["secret"],
            "X-Gitlab-Event": "Tag Push Hook",
            "Idempotency-Key": "k1",
        },
    )
    assert ok.status_code == 202 and ok.json()["status"] == "accepted"
    bad = await world.api.post(
        url,
        content=gl_tag_push(),
        headers={
            "Content-Type": "application/json",
            "X-Gitlab-Token": "nope",
            "X-Gitlab-Event": "Tag Push Hook",
            "Idempotency-Key": "k2",
        },
    )
    assert bad.status_code == 401
    retry = await world.api.post(
        url,
        content=gl_tag_push(),
        headers={
            "Content-Type": "application/json",
            "X-Gitlab-Token": world.webhook["secret"],
            "X-Gitlab-Event": "Tag Push Hook",
            "Idempotency-Key": "k1",
        },
    )
    assert retry.json()["status"] == "duplicate"


async def test_gitlab_signing_token_and_replay(world: World) -> None:
    r = await world.api.post(
        f"/v1/projects/{world.project_id}/webhook-endpoints",
        json={"provider": "gitlab", "signing_secret": "sign-key"},
        headers=auth(world.owner),
    )
    ep = r.json()
    body = gl_tag_push()
    now = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-Gitlab-Token": ep["secret"],
        "X-Gitlab-Event": "Tag Push Hook",
        "webhook-id": "msg_1",
        "webhook-timestamp": now,
        "webhook-signature": standard_webhook_signature(b"sign-key", "msg_1", now, body),
    }
    ok = await world.api.post(f"/v1/webhooks/gitlab/{ep['id']}", content=body, headers=headers)
    assert ok.status_code == 202, ok.text
    tampered = await world.api.post(
        f"/v1/webhooks/gitlab/{ep['id']}", content=body.replace(b"v1.0.0", b"v6.6.6"), headers=headers
    )
    assert tampered.status_code == 401  # a valid X-Gitlab-Token does not protect body integrity
    old = str(int(time.time()) - 3600)
    replay = await world.api.post(
        f"/v1/webhooks/gitlab/{ep['id']}",
        content=body,
        headers={
            **headers,
            "webhook-timestamp": old,
            "webhook-signature": standard_webhook_signature(b"sign-key", "msg_1", old, body),
        },
    )
    assert replay.status_code == 401
