"""Bearer-token authentication and project/environment scoped RBAC."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from udeploy_security.tokens import hash_token

from .errors import Forbidden, Unauthorized
from .models import ApiToken, CIToken, Membership, Project, User


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    DEVELOPER = "developer"
    DEPLOYER = "deployer"
    VIEWER = "viewer"
    AUDITOR = "auditor"


class Perm(StrEnum):
    READ = "read"
    AUDIT_READ = "audit.read"
    RELEASE_CREATE = "release.create"
    DEPLOY = "deploy"
    DEPLOY_PROTECTED = "deploy.protected"  # environments with requireApproval (production)
    APPROVE = "deploy.approve"
    PROJECT_WRITE = "project.write"
    SECRET_WRITE = "secret.write"
    REGISTRY_WRITE = "registry.write"
    HOST_WRITE = "host.write"
    ORG_ADMIN = "org.admin"


_BASE = {Perm.READ}
ROLE_PERMS: dict[Role, frozenset[Perm]] = {
    Role.VIEWER: frozenset(_BASE),
    Role.AUDITOR: frozenset(_BASE | {Perm.AUDIT_READ}),
    Role.DEVELOPER: frozenset(_BASE | {Perm.RELEASE_CREATE, Perm.DEPLOY}),
    Role.DEPLOYER: frozenset(_BASE | {Perm.DEPLOY, Perm.DEPLOY_PROTECTED, Perm.APPROVE}),
    Role.ADMIN: frozenset(set(Perm) - {Perm.ORG_ADMIN}),
    Role.OWNER: frozenset(Perm),
}


@dataclass
class Principal:
    user: User
    token_id: uuid.UUID
    memberships: list[Membership] = field(default_factory=list)

    @property
    def id(self) -> uuid.UUID:
        return self.user.id

    def roles_for(self, organization_id: uuid.UUID, project_id: uuid.UUID | None = None) -> set[Role]:
        roles: set[Role] = set()
        for m in self.memberships:
            if m.organization_id != organization_id:
                continue
            if m.project_id is None or (project_id is not None and m.project_id == project_id):
                roles.add(Role(m.role))
        return roles

    def can(self, perm: Perm, organization_id: uuid.UUID, project_id: uuid.UUID | None = None) -> bool:
        return any(perm in ROLE_PERMS[r] for r in self.roles_for(organization_id, project_id))

    def require(self, perm: Perm, organization_id: uuid.UUID, project_id: uuid.UUID | None = None) -> None:
        if not self.can(perm, organization_id, project_id):
            raise Forbidden(f"missing permission {perm.value}")

    def organization_ids(self) -> set[uuid.UUID]:
        return {m.organization_id for m in self.memberships}


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise Unauthorized("missing bearer token")
    return token.strip()


async def authenticate_user(request: Request, session: AsyncSession) -> Principal:
    token = _bearer(request)
    if not token.startswith("udp_"):
        raise Unauthorized("invalid token")
    row = (
        await session.execute(
            select(ApiToken, User)
            .join(User, User.id == ApiToken.user_id)
            .where(ApiToken.token_hash == hash_token(token))
        )
    ).first()
    now = datetime.now(UTC)
    if row is None:
        raise Unauthorized("invalid token")
    api_token, user = row
    if api_token.revoked_at or (api_token.expires_at and api_token.expires_at < now) or not user.is_active:
        raise Unauthorized("token expired or revoked")
    if api_token.last_used_at is None or now - api_token.last_used_at > timedelta(minutes=5):
        api_token.last_used_at = now
    memberships = list((await session.scalars(select(Membership).where(Membership.user_id == user.id))).all())
    return Principal(user=user, token_id=api_token.id, memberships=memberships)


@dataclass
class CIPrincipal:
    token: CIToken
    project: Project


async def authenticate_ci(request: Request, session: AsyncSession) -> CIPrincipal:
    token = _bearer(request)
    if not token.startswith("udci_"):
        raise Unauthorized("invalid CI token")
    row = (
        await session.execute(
            select(CIToken, Project)
            .join(Project, Project.id == CIToken.project_id)
            .where(CIToken.token_hash == hash_token(token))
        )
    ).first()
    if row is None or row[0].revoked_at is not None:
        raise Unauthorized("invalid CI token")
    ci_token, project = row
    ci_token.last_used_at = datetime.now(UTC)
    return CIPrincipal(token=ci_token, project=project)
