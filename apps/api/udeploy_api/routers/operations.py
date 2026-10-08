"""Releases, deployments, hosts and audit endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from .. import audit
from ..auth import Perm
from ..deps import Ctx, CurrentUser, Page, Session, load_environment, load_project
from ..errors import NotFound
from ..models import AuditEvent, Deployment, DeploymentEvent, DockerHost, Environment, Project, Release
from ..services import deployments as dsvc
from ..services import hosts as hsvc
from ..services.releases import ReleaseIn, create_release

router = APIRouter(prefix="/v1", tags=["operations"])


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _release_view(r: Release) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "project_id": str(r.project_id),
        "version": r.version,
        "commit_sha": r.commit_sha,
        "branch": r.branch,
        "tag": r.tag,
        "build_id": r.build_id,
        "build_url": r.build_url,
        "status": r.status,
        "status_detail": r.status_detail,
        "created_at": r.created_at.isoformat(),
        "verified_at": r.verified_at.isoformat() if r.verified_at else None,
        "artifacts": [
            {
                "service": a.service_name,
                "image": f"{a.registry_host}/{a.repository_path}@{a.digest}",
                "tag": a.tag,
                "digest": a.digest,
                "platform": a.platform,
                "scan_status": a.scan_status,
                "signed": a.signed,
                "digest_verified": a.digest_verified,
                "revision_label": a.revision_label,
            }
            for a in r.artifacts
        ],
    }


# ------------------------------------------------------------------ releases


class ManualReleaseIn(ReleaseIn):
    project_id: uuid.UUID


@router.post("/releases", status_code=202, summary="Register a release manually (same verification as CI)")
async def post_release(body: ManualReleaseIn, session: Session, user: CurrentUser) -> dict[str, Any]:
    project = await load_project(session, user, body.project_id, Perm.RELEASE_CREATE)
    data = ReleaseIn.model_validate(body.model_dump(exclude={"project_id"}))
    release, _created = await create_release(session, project, data, user_id=user.id)
    await session.commit()
    return _release_view(release)


@router.get("/releases/{release_id}")
async def get_release(release_id: uuid.UUID, session: Session, user: CurrentUser) -> dict[str, Any]:
    release = await session.get(Release, release_id)
    if release is None:
        raise NotFound("release not found")
    await load_project(session, user, release.project_id, Perm.READ)
    return _release_view(release)


@router.get("/releases")
async def list_releases(
    session: Session, user: CurrentUser, project_id: uuid.UUID, page: Annotated[Page, Depends()]
) -> dict[str, Any]:
    await load_project(session, user, project_id, Perm.READ)
    order = Release.created_at.desc() if page.order == "desc" else Release.created_at.asc()
    rows = (
        await session.scalars(
            select(Release)
            .where(Release.project_id == project_id)
            .order_by(order)
            .limit(page.limit)
            .offset(page.offset)
        )
    ).all()
    return page.wrap([_release_view(r) for r in rows])


# ------------------------------------------------------------------ deployments


class DeploymentIn(_In):
    project_id: uuid.UUID
    environment: str = Field(max_length=63)
    release_id: uuid.UUID


async def _load_deployment(
    session: Session, user: CurrentUser, deployment_id: uuid.UUID, perm: Perm
) -> tuple[Deployment, Project, Environment]:
    dep = await session.get(Deployment, deployment_id, with_for_update=perm != Perm.READ)
    if dep is None:
        raise NotFound("deployment not found")
    project = await load_project(session, user, dep.project_id, Perm.READ)
    env = await session.get(Environment, dep.environment_id)
    assert env is not None
    user.require(perm, project.organization_id, project.id)
    if perm in (Perm.DEPLOY, Perm.APPROVE) and env.require_approval:
        user.require(Perm.DEPLOY_PROTECTED, project.organization_id, project.id)
    return dep, project, env


@router.post("/deployments", status_code=202)
async def create_deployment(
    body: DeploymentIn,
    ctx: Ctx,
    session: Session,
    user: CurrentUser,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=200)] = None,
) -> dict[str, Any]:
    project = await load_project(session, user, body.project_id, Perm.DEPLOY)
    env = await load_environment(session, project, body.environment)
    if env.require_approval:
        user.require(Perm.DEPLOY_PROTECTED, project.organization_id, project.id)
    release = await session.get(Release, body.release_id)
    if release is None or release.project_id != project.id:
        raise NotFound("release not found")
    key = f"user:{user.id}:{idempotency_key}" if idempotency_key else None
    dep = await dsvc.request_deployment(
        ctx,
        session,
        project=project,
        environment=env,
        release=release,
        trigger="manual",
        user_id=user.id,
        idempotency_key=key,
    )
    await session.commit()
    return dsvc.deployment_view(dep)


@router.get("/deployments/{deployment_id}")
async def get_deployment(deployment_id: uuid.UUID, session: Session, user: CurrentUser) -> dict[str, Any]:
    dep, _project, env = await _load_deployment(session, user, deployment_id, Perm.READ)
    view = dsvc.deployment_view(dep)
    view["environment"] = env.name
    view["plan"] = dep.plan
    return view


@router.post("/deployments/{deployment_id}/approve")
async def approve_deployment(
    deployment_id: uuid.UUID, ctx: Ctx, session: Session, user: CurrentUser
) -> dict[str, Any]:
    dep, project, _env = await _load_deployment(session, user, deployment_id, Perm.APPROVE)
    await dsvc.approve(ctx, session, dep, user.id)
    audit.record(
        session,
        "deployment.approved",
        actor_type="user",
        actor_id=user.id,
        organization_id=project.organization_id,
        target_type="deployment",
        target_id=dep.id,
    )
    await session.commit()
    return dsvc.deployment_view(dep)


@router.post("/deployments/{deployment_id}/cancel")
async def cancel_deployment(deployment_id: uuid.UUID, session: Session, user: CurrentUser) -> dict[str, Any]:
    dep, project, _env = await _load_deployment(session, user, deployment_id, Perm.DEPLOY)
    await dsvc.cancel(session, dep)
    audit.record(
        session,
        "deployment.cancel_requested",
        actor_type="user",
        actor_id=user.id,
        organization_id=project.organization_id,
        target_type="deployment",
        target_id=dep.id,
    )
    await session.commit()
    return dsvc.deployment_view(dep)


@router.post(
    "/deployments/{deployment_id}/rollback",
    status_code=202,
    summary="Redeploy the previous successful release of the environment (by digest)",
)
async def rollback_deployment(
    deployment_id: uuid.UUID, ctx: Ctx, session: Session, user: CurrentUser
) -> dict[str, Any]:
    dep, project, env = await _load_deployment(session, user, deployment_id, Perm.DEPLOY)
    target = await dsvc.find_rollback_target(session, dep)
    release = await session.get(Release, target.release_id)
    assert release is not None
    new = await dsvc.request_deployment(
        ctx,
        session,
        project=project,
        environment=env,
        release=release,
        trigger="rollback",
        user_id=user.id,
        rollback_of=dep,
    )
    await session.commit()
    return dsvc.deployment_view(new)


@router.get("/deployments/{deployment_id}/events")
async def deployment_events(
    deployment_id: uuid.UUID,
    session: Session,
    user: CurrentUser,
    after_id: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    await _load_deployment(session, user, deployment_id, Perm.READ)
    rows = (
        await session.scalars(
            select(DeploymentEvent)
            .where(DeploymentEvent.deployment_id == deployment_id, DeploymentEvent.id > after_id)
            .order_by(DeploymentEvent.id)
            .limit(500)
        )
    ).all()
    return {
        "items": [
            {
                "id": e.id,
                "state": e.state,
                "message": e.message,
                "source": e.source,
                "at": e.created_at.isoformat(),
            }
            for e in rows
        ]
    }


@router.get("/deployments/{deployment_id}/logs")
async def deployment_logs(deployment_id: uuid.UUID, session: Session, user: CurrentUser) -> dict[str, Any]:
    await _load_deployment(session, user, deployment_id, Perm.READ)
    rows = (
        await session.scalars(
            select(DeploymentEvent)
            .where(DeploymentEvent.deployment_id == deployment_id, DeploymentEvent.log != "")
            .order_by(DeploymentEvent.id)
        )
    ).all()
    return {"items": [{"state": e.state, "at": e.created_at.isoformat(), "log": e.log} for e in rows]}


# ------------------------------------------------------------------ hosts


class EnrollTokenIn(_In):
    organization_id: uuid.UUID
    host_name: str = Field(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    pool: str = Field(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@router.post("/hosts/enroll-token", status_code=201)
async def host_enroll_token(
    body: EnrollTokenIn, ctx: Ctx, session: Session, user: CurrentUser
) -> dict[str, Any]:
    user.require(Perm.HOST_WRITE, body.organization_id)
    row, token = hsvc.create_enroll_token(
        session, ctx, body.organization_id, body.host_name, body.pool, user.id
    )
    await session.flush()
    audit.record(
        session,
        "host.enroll_token_created",
        actor_type="user",
        actor_id=user.id,
        organization_id=body.organization_id,
        target_type="enroll_token",
        target_id=row.id,
        details={"host": body.host_name, "pool": body.pool},
    )
    await session.commit()
    return {
        "token": token,
        "expires_at": row.expires_at.isoformat(),
        "enroll_url": f"{ctx.settings.public_base_url.rstrip('/')}/v1/agent/enroll",
        "agent_api_url": ctx.settings.agent_api_url,
        "note": "single use; pass it to `udeploy-agent enroll`",
    }


def _host_view(h: DockerHost, offline_after: int) -> dict[str, Any]:
    from datetime import UTC, datetime

    online = bool(h.last_seen_at and (datetime.now(UTC) - h.last_seen_at).total_seconds() < offline_after)
    return {
        "id": str(h.id),
        "name": h.name,
        "pool": h.pool,
        "status": h.status,
        "online": online,
        "last_seen_at": h.last_seen_at.isoformat() if h.last_seen_at else None,
        "cert_not_after": h.cert_not_after.isoformat() if h.cert_not_after else None,
        "facts": h.facts,
    }


@router.get("/hosts")
async def list_hosts(
    ctx: Ctx, session: Session, user: CurrentUser, organization_id: uuid.UUID
) -> dict[str, Any]:
    user.require(Perm.READ, organization_id)
    rows = (
        await session.scalars(select(DockerHost).where(DockerHost.organization_id == organization_id))
    ).all()
    return {"items": [_host_view(h, ctx.settings.agent_offline_after_seconds) for h in rows]}


@router.get("/hosts/{host_id}/health")
async def host_health(host_id: uuid.UUID, ctx: Ctx, session: Session, user: CurrentUser) -> dict[str, Any]:
    host = await session.get(DockerHost, host_id)
    if host is None or not user.can(Perm.READ, host.organization_id):
        raise NotFound("host not found")
    return _host_view(host, ctx.settings.agent_offline_after_seconds)


@router.post("/hosts/{host_id}/disable", summary="Revoke a host: its certificate stops working immediately")
async def disable_host(host_id: uuid.UUID, ctx: Ctx, session: Session, user: CurrentUser) -> dict[str, Any]:
    host = await session.get(DockerHost, host_id)
    if host is None or not user.can(Perm.READ, host.organization_id):
        raise NotFound("host not found")
    user.require(Perm.HOST_WRITE, host.organization_id)
    host.status = "disabled"
    host.cert_fingerprint = None
    audit.record(
        session,
        "host.disabled",
        actor_type="user",
        actor_id=user.id,
        organization_id=host.organization_id,
        target_type="host",
        target_id=host.id,
    )
    await session.commit()
    return _host_view(host, ctx.settings.agent_offline_after_seconds)


# ------------------------------------------------------------------ audit


@router.get("/audit-events")
async def audit_events(
    session: Session,
    user: CurrentUser,
    organization_id: uuid.UUID,
    page: Annotated[Page, Depends()],
    action: str | None = None,
    target_id: str | None = None,
) -> dict[str, Any]:
    user.require(Perm.AUDIT_READ, organization_id)
    q = select(AuditEvent).where(AuditEvent.organization_id == organization_id)
    if action:
        q = q.where(AuditEvent.action == action)
    if target_id:
        q = q.where(AuditEvent.target_id == target_id)
    order = AuditEvent.id.desc() if page.order == "desc" else AuditEvent.id.asc()
    rows = (await session.scalars(q.order_by(order).limit(page.limit).offset(page.offset))).all()
    return page.wrap(
        [
            {
                "id": e.id,
                "action": e.action,
                "actor_type": e.actor_type,
                "actor_id": e.actor_id,
                "target_type": e.target_type,
                "target_id": e.target_id,
                "details": e.details,
                "correlation_id": e.correlation_id,
                "at": e.created_at.isoformat(),
            }
            for e in rows
        ]
    )
