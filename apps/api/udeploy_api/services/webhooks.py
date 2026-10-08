"""Webhook ingestion: authenticate raw bytes, dedupe, normalise, store durably.

Nothing here deploys. Accepted events are recorded (and linked later to the
release built from the same commit); deployments only follow verified releases.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from udeploy_providers.git import NormalizedEvent, UnsupportedEvent, normalize_github, normalize_gitlab
from udeploy_security.webhooks import (
    WebhookAuthError,
    verify_github,
    verify_gitlab_token,
    verify_standard_webhook,
)

from .. import audit
from ..context import AppContext, webhook_aad
from ..errors import APIError, NotFound, Unauthorized
from ..models import Project, WebhookDelivery, WebhookEndpoint


class WebhookResult(dict[str, Any]):
    pass


async def _endpoint(
    session: AsyncSession, endpoint_id: uuid.UUID, provider: str
) -> tuple[WebhookEndpoint, Project]:
    row = (
        await session.execute(
            select(WebhookEndpoint, Project)
            .join(Project, Project.id == WebhookEndpoint.project_id)
            .where(WebhookEndpoint.id == endpoint_id, WebhookEndpoint.provider == provider)
        )
    ).first()
    if row is None or not row[0].active:
        # Same answer for unknown and inactive endpoints (no enumeration).
        raise NotFound("unknown webhook endpoint")
    return row[0], row[1]


def _parse(body: bytes) -> dict[str, Any]:
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise APIError("body is not valid JSON", code="invalid_payload") from exc
    if not isinstance(data, dict):
        raise APIError("payload must be a JSON object", code="invalid_payload")
    return data


async def _store(
    session: AsyncSession,
    endpoint: WebhookEndpoint,
    project: Project,
    *,
    provider: str,
    delivery_id: str,
    event_type: str,
    normalized: NormalizedEvent | None,
    status: str,
    detail: str,
) -> WebhookResult:
    key = f"{provider}:{endpoint.id}:{delivery_id}:{event_type}"
    stmt = (
        insert(WebhookDelivery)
        .values(
            id=uuid.uuid4(),
            endpoint_id=endpoint.id,
            idempotency_key=key,
            provider=provider,
            delivery_id=delivery_id,
            event_type=event_type,
            status=status,
            detail=detail,
            normalized=normalized.model_dump(mode="json") if normalized else None,
            commit_sha=normalized.commit_sha if normalized else None,
            received_at=datetime.now(UTC),
        )
        .on_conflict_do_nothing(index_elements=["idempotency_key"])
        .returning(WebhookDelivery.id)
    )
    inserted = (await session.execute(stmt)).scalar_one_or_none()
    if inserted is None:
        return WebhookResult(status="duplicate", delivery_id=delivery_id)
    audit.record(
        session,
        f"webhook.{status}",
        actor_type="webhook",
        actor_id=endpoint.id,
        organization_id=project.organization_id,
        target_type="webhook_delivery",
        target_id=inserted,
        details={
            "provider": provider,
            "event": event_type,
            "detail": detail,
            "kind": normalized.kind if normalized else None,
            "ref": normalized.ref if normalized else None,
            "commit_sha": normalized.commit_sha if normalized else None,
        },
    )
    await session.commit()
    return WebhookResult(status=status, delivery_id=delivery_id, id=str(inserted), detail=detail)


async def ingest_github(
    ctx: AppContext, session: AsyncSession, endpoint_id: uuid.UUID, body: bytes, headers: dict[str, str]
) -> WebhookResult:
    endpoint, project = await _endpoint(session, endpoint_id, "github")
    secret = ctx.box.decrypt(endpoint.secret_ciphertext, webhook_aad(endpoint.id, "secret"))
    try:
        verify_github(secret, body, headers.get("x-hub-signature-256"))  # before JSON parsing
    except WebhookAuthError as exc:
        raise Unauthorized(f"webhook authentication failed: {exc}") from exc
    event = headers.get("x-github-event", "")
    delivery = headers.get("x-github-delivery", "")
    if not event or not delivery or len(delivery) > 200:
        raise APIError("missing X-GitHub-Event or X-GitHub-Delivery header", code="invalid_headers")
    payload = _parse(body)
    try:
        normalized: NormalizedEvent | None = normalize_github(event, payload)
        status, detail = "accepted", ""
    except UnsupportedEvent as exc:
        normalized, status, detail = None, "ignored", str(exc)
    if normalized and normalized.repository.lower() != project.repository.lower():
        normalized, status, detail = None, "rejected", "repository does not match the endpoint's project"
    return await _store(
        session,
        endpoint,
        project,
        provider="github",
        delivery_id=delivery,
        event_type=event,
        normalized=normalized,
        status=status,
        detail=detail,
    )


async def ingest_gitlab(
    ctx: AppContext, session: AsyncSession, endpoint_id: uuid.UUID, body: bytes, headers: dict[str, str]
) -> WebhookResult:
    endpoint, project = await _endpoint(session, endpoint_id, "gitlab")
    token = ctx.box.decrypt(endpoint.secret_ciphertext, webhook_aad(endpoint.id, "secret"))
    try:
        verify_gitlab_token(token, headers.get("x-gitlab-token"))
        if endpoint.signing_secret_ciphertext:
            signing = ctx.box.decrypt(endpoint.signing_secret_ciphertext, webhook_aad(endpoint.id, "signing"))
            verify_standard_webhook(
                signing,
                body,
                headers.get("webhook-id"),
                headers.get("webhook-timestamp"),
                headers.get("webhook-signature"),
            )
    except WebhookAuthError as exc:
        raise Unauthorized(f"webhook authentication failed: {exc}") from exc
    event = headers.get("x-gitlab-event", "")
    delivery = (
        headers.get("idempotency-key")
        or headers.get("x-gitlab-event-uuid")
        or headers.get("webhook-id")
        or ""
    )
    if not event or not delivery or len(delivery) > 200:
        raise APIError("missing X-Gitlab-Event or delivery identifier header", code="invalid_headers")
    payload = _parse(body)
    try:
        normalized: NormalizedEvent | None = normalize_gitlab(event, payload)
        status, detail = "accepted", ""
    except UnsupportedEvent as exc:
        normalized, status, detail = None, "ignored", str(exc)
    if normalized and normalized.repository.lower() != project.repository.lower():
        normalized, status, detail = None, "rejected", "repository does not match the endpoint's project"
    return await _store(
        session,
        endpoint,
        project,
        provider="gitlab",
        delivery_id=delivery,
        event_type=event,
        normalized=normalized,
        status=status,
        detail=detail,
    )
