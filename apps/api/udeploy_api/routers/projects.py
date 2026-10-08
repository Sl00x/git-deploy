"""Organizations, projects, services, environments, secrets, webhooks, CI tokens, registries."""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import delete, select

from udeploy_domain.naming import NamingError, image_repository_name, normalize_registry_host
from udeploy_security.tokens import display_prefix, generate, hash_token

from .. import audit
from ..auth import Perm, Role
from ..context import registry_aad, webhook_aad
from ..deps import Ctx, CurrentUser, Page, Session, load_environment, load_project, read_limited_body
from ..errors import APIError, Conflict, NotFound, PolicyViolation
from ..models import (
    CIToken,
    Deployment,
    Environment,
    Membership,
    Organization,
    Project,
    Registry,
    Release,
    SecretValue,
    Service,
    WebhookEndpoint,
)
from ..services.manifests import apply_manifest, platform_policy
from ..services.secrets import LocalEncryptedSecrets

router = APIRouter(prefix="/v1", tags=["configuration"])

SLUG = r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------------------ organizations


@router.get("/organizations")
async def list_organizations(session: Session, user: CurrentUser) -> dict[str, Any]:
    ids = user.organization_ids()
    orgs = (
        await session.scalars(
            select(Organization).where(Organization.id.in_(ids)).order_by(Organization.slug)
        )
    ).all()
    return {
        "items": [
            {
                "id": str(o.id),
                "slug": o.slug,
                "name": o.name,
                "allowed_domains": o.allowed_domains,
                "roles": sorted(r.value for r in user.roles_for(o.id)),
            }
            for o in orgs
        ]
    }


class OrgPatch(_In):
    allowed_domains: list[Annotated[str, Field(pattern=r"^[a-z0-9.-]{3,253}$")]] | None = None
    name: str | None = Field(None, max_length=200)


@router.patch("/organizations/{org_id}")
async def patch_organization(
    org_id: uuid.UUID, body: OrgPatch, session: Session, user: CurrentUser
) -> dict[str, Any]:
    org = await session.get(Organization, org_id)
    if org is None or not user.can(Perm.READ, org.id):
        raise NotFound("organization not found")
    user.require(Perm.ORG_ADMIN, org.id)
    if body.allowed_domains is not None:
        org.allowed_domains = sorted(set(body.allowed_domains))
    if body.name is not None:
        org.name = body.name
    audit.record(
        session,
        "organization.updated",
        actor_type="user",
        actor_id=user.id,
        organization_id=org.id,
        target_type="organization",
        target_id=org.id,
        details=body.model_dump(exclude_none=True),
    )
    await session.commit()
    return {"id": str(org.id), "slug": org.slug, "allowed_domains": org.allowed_domains}


class MemberIn(_In):
    email: str = Field(max_length=320)
    role: Role
    project_id: uuid.UUID | None = None


@router.post("/organizations/{org_id}/members", status_code=201)
async def add_member(
    org_id: uuid.UUID, body: MemberIn, session: Session, user: CurrentUser
) -> dict[str, Any]:
    from ..models import User

    org = await session.get(Organization, org_id)
    if org is None or not user.can(Perm.READ, org.id):
        raise NotFound("organization not found")
    user.require(Perm.ORG_ADMIN, org.id)
    member = await session.scalar(select(User).where(User.email == body.email.lower()))
    if member is None:
        member = User(email=body.email.lower())
        session.add(member)
        await session.flush()
    if body.project_id:
        project = await session.get(Project, body.project_id)
        if project is None or project.organization_id != org.id:
            raise NotFound("project not found")
    session.add(
        Membership(user_id=member.id, organization_id=org.id, project_id=body.project_id, role=body.role)
    )
    audit.record(
        session,
        "membership.created",
        actor_type="user",
        actor_id=user.id,
        organization_id=org.id,
        target_type="user",
        target_id=member.id,
        details=body.model_dump(mode="json"),
    )
    await session.commit()
    return {"user_id": str(member.id), "role": body.role}


# ------------------------------------------------------------------ registries


class RegistryIn(_In):
    organization_id: uuid.UUID
    name: str = Field(pattern=SLUG)
    kind: Literal["generic", "dockerhub", "ghcr", "gitlab", "harbor", "ecr", "acr"] = "generic"
    host: str = Field(max_length=255)
    namespace: str = Field("", max_length=255, pattern=r"^[a-z0-9._/-]*$")
    username: str | None = Field(None, max_length=255)
    password: SecretStr | None = None
    insecure_http: bool = Field(False, description="plain HTTP; only for loopback/test registries")


def _registry_view(r: Registry) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "organization_id": str(r.organization_id),
        "name": r.name,
        "kind": r.kind,
        "host": r.host,
        "namespace": r.namespace,
        "username": r.username,
        "has_password": bool(r.password_ciphertext),
        "insecure_http": r.insecure_http,
    }


@router.post("/registries", status_code=201)
async def create_registry(body: RegistryIn, ctx: Ctx, session: Session, user: CurrentUser) -> dict[str, Any]:
    user.require(Perm.REGISTRY_WRITE, body.organization_id)
    try:
        host = normalize_registry_host(body.host)
    except NamingError as exc:
        raise PolicyViolation(str(exc)) from exc
    if await session.scalar(
        select(Registry).where(Registry.organization_id == body.organization_id, Registry.name == body.name)
    ):
        raise Conflict("registry name already used")
    reg = Registry(
        organization_id=body.organization_id,
        name=body.name,
        kind=body.kind,
        host=host,
        namespace=body.namespace.strip("/"),
        username=body.username,
        insecure_http=body.insecure_http,
    )
    session.add(reg)
    await session.flush()
    if body.password is not None:
        reg.password_ciphertext = ctx.box.encrypt(
            body.password.get_secret_value().encode(), registry_aad(reg)
        )
    audit.record(
        session,
        "registry.created",
        actor_type="user",
        actor_id=user.id,
        organization_id=body.organization_id,
        target_type="registry",
        target_id=reg.id,
        details={"name": reg.name, "host": host},
    )
    await session.commit()
    return _registry_view(reg)


@router.get("/registries")
async def list_registries(session: Session, user: CurrentUser, organization_id: uuid.UUID) -> dict[str, Any]:
    user.require(Perm.READ, organization_id)
    rows = (await session.scalars(select(Registry).where(Registry.organization_id == organization_id))).all()
    return {"items": [_registry_view(r) for r in rows]}


# ------------------------------------------------------------------ projects


class ProjectIn(_In):
    organization_id: uuid.UUID
    slug: str = Field(pattern=SLUG)
    name: str = Field(max_length=200)
    source_provider: Literal["github", "gitlab"]
    repository: str = Field(max_length=255, pattern=r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$")
    manifest: dict[str, Any] | None = None


def _project_view(p: Project) -> dict[str, Any]:
    return {
        "id": str(p.id),
        "organization_id": str(p.organization_id),
        "slug": p.slug,
        "name": p.name,
        "source_provider": p.source_provider,
        "repository": p.repository,
        "manifest_version": p.manifest_version,
        "manifest": p.manifest,
        "created_at": p.created_at.isoformat(),
        "updated_at": p.updated_at.isoformat(),
    }


@router.post("/projects", status_code=201)
async def create_project(body: ProjectIn, ctx: Ctx, session: Session, user: CurrentUser) -> dict[str, Any]:
    user.require(Perm.PROJECT_WRITE, body.organization_id)
    org = await session.get(Organization, body.organization_id)
    if org is None:
        raise NotFound("organization not found")
    dup = await session.scalar(
        select(Project).where(
            Project.organization_id == org.id,
            (Project.slug == body.slug)
            | ((Project.source_provider == body.source_provider) & (Project.repository == body.repository)),
        )
    )
    if dup:
        raise Conflict("a project with this slug or repository already exists")
    project = Project(
        organization_id=org.id,
        slug=body.slug,
        name=body.name,
        source_provider=body.source_provider,
        repository=body.repository,
    )
    session.add(project)
    await session.flush()
    await session.refresh(project, ["organization"])
    if body.manifest is not None:
        await apply_manifest(session, project, body.manifest, ctx.settings)
    audit.record(
        session,
        "project.created",
        actor_type="user",
        actor_id=user.id,
        organization_id=org.id,
        target_type="project",
        target_id=project.id,
        details={"slug": body.slug, "repository": body.repository},
    )
    await session.commit()
    return _project_view(project)


@router.get("/projects")
async def list_projects(
    session: Session, user: CurrentUser, page: Annotated[Page, Depends()]
) -> dict[str, Any]:
    ids = user.organization_ids()
    rows = (
        await session.scalars(
            select(Project)
            .where(Project.organization_id.in_(ids))
            .order_by(Project.slug)
            .limit(page.limit)
            .offset(page.offset)
        )
    ).all()
    visible = [p for p in rows if user.can(Perm.READ, p.organization_id, p.id)]
    return page.wrap([_project_view(p) for p in visible])


@router.get("/projects/{project_id}")
async def get_project(project_id: uuid.UUID, session: Session, user: CurrentUser) -> dict[str, Any]:
    project = await load_project(session, user, project_id, Perm.READ)
    services = (await session.scalars(select(Service).where(Service.project_id == project.id))).all()
    envs = (await session.scalars(select(Environment).where(Environment.project_id == project.id))).all()
    view = _project_view(project)
    view["services"] = [
        {"id": str(s.id), "name": s.name, "image_repository": s.image_repository} for s in services
    ]
    view["environments"] = [_env_view(e) for e in envs]
    return view


class ProjectPatch(_In):
    name: str | None = Field(None, max_length=200)
    manifest: dict[str, Any] | None = None


@router.patch("/projects/{project_id}")
async def patch_project(
    project_id: uuid.UUID, body: ProjectPatch, ctx: Ctx, session: Session, user: CurrentUser
) -> dict[str, Any]:
    project = await load_project(session, user, project_id, Perm.PROJECT_WRITE)
    if body.name is not None:
        project.name = body.name
    if body.manifest is not None:
        await apply_manifest(session, project, body.manifest, ctx.settings)
    audit.record(
        session,
        "project.updated",
        actor_type="user",
        actor_id=user.id,
        organization_id=project.organization_id,
        target_type="project",
        target_id=project.id,
        details={"manifest_version": project.manifest_version, "name": body.name},
    )
    await session.commit()
    return _project_view(project)


@router.put("/projects/{project_id}/manifest", summary="Register an approved manifest (YAML or JSON)")
async def put_manifest(
    project_id: uuid.UUID, request: Request, ctx: Ctx, session: Session, user: CurrentUser
) -> dict[str, Any]:
    import json

    from udeploy_domain.manifest import load_manifest_yaml

    project = await load_project(session, user, project_id, Perm.PROJECT_WRITE)
    raw = await read_limited_body(request, 256 * 1024)
    ctype = request.headers.get("content-type", "").split(";")[0].strip()
    try:
        data = json.loads(raw) if ctype == "application/json" else load_manifest_yaml(raw.decode())
    except Exception as exc:
        raise APIError(f"cannot parse manifest: {type(exc).__name__}", code="invalid_payload") from exc
    if not isinstance(data, dict):
        raise APIError("manifest must be a mapping", code="invalid_payload")
    await apply_manifest(session, project, data, ctx.settings)
    audit.record(
        session,
        "project.manifest_applied",
        actor_type="user",
        actor_id=user.id,
        organization_id=project.organization_id,
        target_type="project",
        target_id=project.id,
        details={"manifest_version": project.manifest_version},
    )
    await session.commit()
    return _project_view(project)


class ServiceIn(_In):
    name: str = Field(pattern=SLUG, max_length=40)
    spec: dict[str, Any] = Field(default_factory=dict)


@router.post("/projects/{project_id}/services", status_code=201)
async def add_service(
    project_id: uuid.UUID, body: ServiceIn, ctx: Ctx, session: Session, user: CurrentUser
) -> dict[str, Any]:
    """Adds a service by merging it into the stored manifest (same validation path)."""
    project = await load_project(session, user, project_id, Perm.PROJECT_WRITE)
    if not project.manifest:
        raise Conflict("register a manifest first (PUT /v1/projects/{id}/manifest)")
    manifest = dict(project.manifest)
    if body.name in manifest.get("services", {}):
        raise Conflict("service already exists")
    manifest["services"] = {**manifest["services"], body.name: body.spec}
    await apply_manifest(session, project, manifest, ctx.settings)
    await session.commit()
    svc = await session.scalar(
        select(Service).where(Service.project_id == project.id, Service.name == body.name)
    )
    assert svc is not None
    return {"id": str(svc.id), "name": svc.name, "image_repository": svc.image_repository}


def _env_view(e: Environment) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "name": e.name,
        "host_pool": e.host_pool,
        "branches": e.branches,
        "tags": e.tags,
        "auto_deploy": e.auto_deploy,
        "require_approval": e.require_approval,
        "pinned_host_id": str(e.pinned_host_id) if e.pinned_host_id else None,
        "current_deployment_id": str(e.current_deployment_id) if e.current_deployment_id else None,
    }


class EnvironmentIn(_In):
    name: str = Field(pattern=SLUG)
    host_pool: str = Field(pattern=SLUG)
    branches: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    auto_deploy: bool = False
    require_approval: bool = False


@router.post("/projects/{project_id}/environments", status_code=201)
async def add_environment(
    project_id: uuid.UUID, body: EnvironmentIn, ctx: Ctx, session: Session, user: CurrentUser
) -> dict[str, Any]:
    project = await load_project(session, user, project_id, Perm.PROJECT_WRITE)
    if not project.manifest:
        raise Conflict("register a manifest first (PUT /v1/projects/{id}/manifest)")
    manifest = dict(project.manifest)
    if body.name in manifest.get("targets", {}):
        raise Conflict("environment already exists")
    manifest["targets"] = {**manifest.get("targets", {}), body.name: {"hostPool": body.host_pool}}
    release = dict(manifest.get("release", {}))
    release["environments"] = {
        **release.get("environments", {}),
        body.name: {
            "branches": body.branches,
            "tags": body.tags,
            "autoDeploy": body.auto_deploy,
            "requireApproval": body.require_approval,
        },
    }
    manifest["release"] = release
    await apply_manifest(session, project, manifest, ctx.settings)
    await session.commit()
    env = await load_environment(session, project, body.name)
    return _env_view(env)


@router.get("/projects/{project_id}/history")
async def project_history(
    project_id: uuid.UUID,
    session: Session,
    user: CurrentUser,
    page: Annotated[Page, Depends()],
    environment: str | None = None,
) -> dict[str, Any]:
    from ..services.deployments import deployment_view

    project = await load_project(session, user, project_id, Perm.READ)
    q = (
        select(Deployment, Release.version)
        .join(Release, Release.id == Deployment.release_id)
        .where(Deployment.project_id == project.id)
    )
    if environment:
        env = await load_environment(session, project, environment)
        q = q.where(Deployment.environment_id == env.id)
    order = Deployment.created_at.desc() if page.order == "desc" else Deployment.created_at.asc()
    rows = (await session.execute(q.order_by(order).limit(page.limit).offset(page.offset))).all()
    return page.wrap([{**deployment_view(d), "release_version": v} for d, v in rows])


# ------------------------------------------------------------------ secrets (write-only)

SECRET_PATH = r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*){0,7}$"


class SecretIn(_In):
    value: SecretStr = Field(description="never returned by any endpoint")


@router.put("/projects/{project_id}/environments/{environment}/secrets/{path:path}", status_code=204)
async def put_secret(
    project_id: uuid.UUID,
    environment: str,
    path: str,
    body: SecretIn,
    ctx: Ctx,
    session: Session,
    user: CurrentUser,
) -> None:
    import re

    if not re.match(SECRET_PATH, path):
        raise PolicyViolation("invalid secret path")
    project = await load_project(session, user, project_id, Perm.SECRET_WRITE)
    env = await load_environment(session, project, environment)
    if len(body.value.get_secret_value().encode()) > 64 * 1024:
        raise APIError("secret too large (64 KiB max)", status_code=413, code="payload_too_large")
    row = await LocalEncryptedSecrets(session, ctx.box).put(project, env, path, body.value.get_secret_value())
    await session.flush()
    audit.record(
        session,
        "secret.written",
        actor_type="user",
        actor_id=user.id,
        organization_id=project.organization_id,
        target_type="secret",
        target_id=row.id,
        details={"path": path, "environment": env.name, "version": row.version},
    )
    await session.commit()


@router.get("/projects/{project_id}/environments/{environment}/secrets")
async def list_secrets(
    project_id: uuid.UUID, environment: str, session: Session, user: CurrentUser
) -> dict[str, Any]:
    project = await load_project(session, user, project_id, Perm.READ)
    env = await load_environment(session, project, environment)
    rows = (await session.scalars(select(SecretValue).where(SecretValue.environment_id == env.id))).all()
    return {
        "items": [
            {"path": r.path, "version": r.version, "updated_at": r.updated_at.isoformat()} for r in rows
        ]
    }


@router.delete("/projects/{project_id}/environments/{environment}/secrets/{path:path}", status_code=204)
async def delete_secret(
    project_id: uuid.UUID, environment: str, path: str, session: Session, user: CurrentUser
) -> None:
    project = await load_project(session, user, project_id, Perm.SECRET_WRITE)
    env = await load_environment(session, project, environment)
    result = await session.execute(
        delete(SecretValue).where(SecretValue.environment_id == env.id, SecretValue.path == path)
    )
    if not getattr(result, "rowcount", 0):
        raise NotFound("secret not found")
    audit.record(
        session,
        "secret.deleted",
        actor_type="user",
        actor_id=user.id,
        organization_id=project.organization_id,
        target_type="secret",
        target_id=None,
        details={"path": path, "environment": env.name},
    )
    await session.commit()


# ------------------------------------------------------------------ webhook endpoints & CI tokens


class WebhookEndpointIn(_In):
    provider: Literal["github", "gitlab"]
    signing_secret: SecretStr | None = Field(None, description="GitLab signing token (optional)")


@router.post("/projects/{project_id}/webhook-endpoints", status_code=201)
async def create_webhook_endpoint(
    project_id: uuid.UUID, body: WebhookEndpointIn, ctx: Ctx, session: Session, user: CurrentUser
) -> dict[str, Any]:
    project = await load_project(session, user, project_id, Perm.PROJECT_WRITE)
    if body.provider != project.source_provider:
        raise PolicyViolation("webhook provider must match the project's source provider")
    secret = generate("webhook")
    endpoint = WebhookEndpoint(project_id=project.id, provider=body.provider, secret_ciphertext="")
    session.add(endpoint)
    await session.flush()
    endpoint.secret_ciphertext = ctx.box.encrypt(secret.encode(), webhook_aad(endpoint.id, "secret"))
    if body.signing_secret is not None:
        endpoint.signing_secret_ciphertext = ctx.box.encrypt(
            body.signing_secret.get_secret_value().encode(), webhook_aad(endpoint.id, "signing")
        )
    audit.record(
        session,
        "webhook_endpoint.created",
        actor_type="user",
        actor_id=user.id,
        organization_id=project.organization_id,
        target_type="webhook_endpoint",
        target_id=endpoint.id,
    )
    await session.commit()
    return {
        "id": str(endpoint.id),
        "url": f"{ctx.settings.public_base_url.rstrip('/')}/v1/webhooks/{body.provider}/{endpoint.id}",
        "secret": secret,
        "note": "the secret is shown once; configure it as the webhook secret / X-Gitlab-Token",
    }


class CITokenIn(_In):
    name: str = Field(max_length=100)


@router.post("/projects/{project_id}/ci-tokens", status_code=201)
async def create_ci_token(
    project_id: uuid.UUID, body: CITokenIn, session: Session, user: CurrentUser
) -> dict[str, Any]:
    project = await load_project(session, user, project_id, Perm.PROJECT_WRITE)
    token = generate("ci")
    row = CIToken(
        project_id=project.id, name=body.name, token_hash=hash_token(token), prefix=display_prefix(token)
    )
    session.add(row)
    await session.flush()
    audit.record(
        session,
        "ci_token.created",
        actor_type="user",
        actor_id=user.id,
        organization_id=project.organization_id,
        target_type="ci_token",
        target_id=row.id,
        details={"name": body.name},
    )
    await session.commit()
    return {"id": str(row.id), "token": token, "note": "shown once; store it as a masked CI variable"}


@router.delete("/projects/{project_id}/ci-tokens/{token_id}", status_code=204)
async def revoke_ci_token(
    project_id: uuid.UUID, token_id: uuid.UUID, session: Session, user: CurrentUser
) -> None:
    from datetime import UTC, datetime

    project = await load_project(session, user, project_id, Perm.PROJECT_WRITE)
    row = await session.get(CIToken, token_id)
    if row is None or row.project_id != project.id:
        raise NotFound("token not found")
    row.revoked_at = datetime.now(UTC)
    audit.record(
        session,
        "ci_token.revoked",
        actor_type="user",
        actor_id=user.id,
        organization_id=project.organization_id,
        target_type="ci_token",
        target_id=row.id,
    )
    await session.commit()


@router.post("/projects/{project_id}/manifest/validate", summary="Dry-run manifest validation")
async def validate_manifest_dry_run(
    project_id: uuid.UUID,
    ctx: Ctx,
    session: Session,
    user: CurrentUser,
    manifest: Annotated[dict[str, Any], Body()],
) -> dict[str, Any]:
    from udeploy_planner.policy import ManifestRejected, validate_manifest

    project = await load_project(session, user, project_id, Perm.READ)
    policy = await platform_policy(session, project.organization, ctx.settings)
    try:
        parsed = validate_manifest(manifest, policy)
    except ManifestRejected as exc:
        return {"valid": False, "errors": exc.errors}
    images = {
        name: image_repository_name(
            s.image_name, repository=project.repository, service=name, project=project.slug
        )
        for name, s in parsed.services.items()
    }
    return {"valid": True, "errors": [], "images": images}
