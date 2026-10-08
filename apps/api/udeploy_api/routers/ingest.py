"""Unauthenticated-by-bearer ingress: Git webhooks and CI notifications."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Request, Response
from pydantic import ValidationError

from ..deps import Ctx, CurrentCI, Session, client_ip, rate_limit, read_limited_body
from ..errors import APIError
from ..services import webhooks
from ..services.releases import ReleaseIn, create_release

router = APIRouter(prefix="/v1", tags=["ingest"])


def _require_json(request: Request) -> None:
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype != "application/json":
        raise APIError(
            "Content-Type must be application/json", status_code=415, code="unsupported_media_type"
        )


@router.post("/webhooks/github/{endpoint_id}", status_code=202, summary="GitHub webhook receiver")
async def github_webhook(
    endpoint_id: uuid.UUID, request: Request, ctx: Ctx, session: Session
) -> dict[str, Any]:
    await rate_limit(request, f"wh:{client_ip(request)}", ctx.settings.webhook_rate_limit_per_minute)
    _require_json(request)
    body = await read_limited_body(request, ctx.settings.webhook_max_body_bytes)
    headers = {k.lower(): v for k, v in request.headers.items()}
    return await webhooks.ingest_github(ctx, session, endpoint_id, body, headers)


@router.post("/webhooks/gitlab/{endpoint_id}", status_code=202, summary="GitLab webhook receiver")
async def gitlab_webhook(
    endpoint_id: uuid.UUID, request: Request, ctx: Ctx, session: Session
) -> dict[str, Any]:
    await rate_limit(request, f"wh:{client_ip(request)}", ctx.settings.webhook_rate_limit_per_minute)
    _require_json(request)
    body = await read_limited_body(request, ctx.settings.webhook_max_body_bytes)
    headers = {k.lower(): v for k, v in request.headers.items()}
    return await webhooks.ingest_gitlab(ctx, session, endpoint_id, body, headers)


@router.post(
    "/ci/artifacts/published",
    status_code=202,
    summary="CI notification: images were pushed (authenticated with a project CI token)",
)
async def artifacts_published(
    request: Request, response: Response, ctx: Ctx, session: Session, ci: CurrentCI
) -> dict[str, Any]:
    _require_json(request)
    body = await read_limited_body(request, ctx.settings.api_max_body_bytes)
    try:
        data = ReleaseIn.model_validate_json(body)
    except ValidationError as exc:
        raise APIError(
            "invalid release notification",
            status_code=422,
            code="validation_error",
            details=[{"loc": list(map(str, e["loc"])), "msg": e["msg"]} for e in exc.errors()],
        ) from exc
    release, created = await create_release(session, ci.project, data, ci_token_id=ci.token.id)
    await session.commit()
    if not created:
        response.status_code = 200
    return {
        "release_id": str(release.id),
        "status": release.status,
        "created": created,
        "detail": "digests will be verified against the registry before any deployment",
    }
