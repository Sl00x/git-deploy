"""SQLAlchemy 2.x models (PostgreSQL)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from udeploy_domain.states import ACTIVE, DeploymentState, ReleaseStatus, TaskStatus

JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> uuid.UUID:
    return uuid.uuid4()


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONType, list[Any]: JSONType, datetime: DateTime(timezone=True)}


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(default=utcnow, server_default=text("now()"))


# ------------------------------------------------------------------ identity


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(63), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    allowed_domains: Mapped[list[Any]] = mapped_column(default=list)


class User(TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)


class Membership(TimestampMixin, Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "organization_id", "project_id", name="uq_membership"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    # NULL = organization-wide role; otherwise the role only applies to this project.
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(20))


class ApiToken(TimestampMixin, Base):
    __tablename__ = "api_tokens"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(16))
    expires_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


# ------------------------------------------------------------------ projects


class Project(TimestampMixin, Base):
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug", name="uq_project_slug"),
        UniqueConstraint("organization_id", "source_provider", "repository", name="uq_project_repo"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"))
    slug: Mapped[str] = mapped_column(String(63))
    name: Mapped[str] = mapped_column(String(200))
    source_provider: Mapped[str] = mapped_column(String(20))
    repository: Mapped[str] = mapped_column(String(255))
    manifest: Mapped[dict[str, Any] | None]
    manifest_version: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    organization: Mapped[Organization] = relationship(lazy="joined")


class Service(TimestampMixin, Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_service_name"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(40))
    image_repository: Mapped[str] = mapped_column(String(255))
    spec: Mapped[dict[str, Any]]


class Environment(TimestampMixin, Base):
    __tablename__ = "environments"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_environment_name"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(63))
    host_pool: Mapped[str] = mapped_column(String(63))
    branches: Mapped[list[Any]] = mapped_column(default=list)
    tags: Mapped[list[Any]] = mapped_column(default=list)
    auto_deploy: Mapped[bool] = mapped_column(Boolean, default=False)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    pinned_host_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("docker_hosts.id", ondelete="SET NULL")
    )
    current_deployment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("deployments.id", ondelete="SET NULL", use_alter=True, name="fk_env_current_deployment")
    )


class Route(TimestampMixin, Base):
    __tablename__ = "routes"
    # Platform-wide: a host+path can only ever belong to one environment (anti hijack).
    __table_args__ = (UniqueConstraint("host", "path_prefix", name="uq_route_host_path"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    environment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE"), index=True
    )
    service_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"))
    host: Mapped[str] = mapped_column(String(253))
    path_prefix: Mapped[str] = mapped_column(String(256), default="/")
    tls: Mapped[bool] = mapped_column(Boolean, default=True)


class Registry(TimestampMixin, Base):
    __tablename__ = "registries"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_registry_name"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(63))
    kind: Mapped[str] = mapped_column(String(20), default="generic")
    host: Mapped[str] = mapped_column(String(255))
    namespace: Mapped[str] = mapped_column(String(255), default="")
    username: Mapped[str | None] = mapped_column(String(255))
    password_ciphertext: Mapped[str | None] = mapped_column(Text)
    insecure_http: Mapped[bool] = mapped_column(Boolean, default=False)


class SecretValue(TimestampMixin, Base):
    __tablename__ = "secrets"
    __table_args__ = (UniqueConstraint("environment_id", "path", name="uq_secret_path"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("environments.id", ondelete="CASCADE"))
    path: Mapped[str] = mapped_column(String(255))
    ciphertext: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


# ------------------------------------------------------------------ ingestion


class WebhookEndpoint(TimestampMixin, Base):
    __tablename__ = "webhook_endpoints"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(20))
    secret_ciphertext: Mapped[str] = mapped_column(Text)
    signing_secret_ciphertext: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(300), unique=True)
    provider: Mapped[str] = mapped_column(String(20))
    delivery_id: Mapped[str] = mapped_column(String(200))
    event_type: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20))
    detail: Mapped[str] = mapped_column(Text, default="")
    normalized: Mapped[dict[str, Any] | None]
    commit_sha: Mapped[str | None] = mapped_column(String(64), index=True)
    received_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)


class CIToken(TimestampMixin, Base):
    __tablename__ = "ci_tokens"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(16))
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


# ------------------------------------------------------------------ releases


class Release(TimestampMixin, Base):
    __tablename__ = "releases"
    __table_args__ = (UniqueConstraint("project_id", "version", name="uq_release_version"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    version: Mapped[str] = mapped_column(String(128))
    commit_sha: Mapped[str] = mapped_column(String(64))
    branch: Mapped[str | None] = mapped_column(String(255))
    tag: Mapped[str | None] = mapped_column(String(255))
    build_id: Mapped[str | None] = mapped_column(String(255))
    build_url: Mapped[str | None] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(30), default=ReleaseStatus.PENDING_VERIFICATION)
    status_detail: Mapped[str] = mapped_column(Text, default="")
    verify_attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_by_ci_token_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("ci_tokens.id", ondelete="SET NULL")
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    source_delivery_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("webhook_deliveries.id", ondelete="SET NULL")
    )
    verified_at: Mapped[datetime | None]

    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="release", lazy="selectin", order_by="Artifact.service_name"
    )


class Artifact(TimestampMixin, Base):
    __tablename__ = "artifacts"
    __table_args__ = (UniqueConstraint("release_id", "service_name", name="uq_artifact_service"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    release_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("releases.id", ondelete="CASCADE"), index=True)
    service_name: Mapped[str] = mapped_column(String(40))
    registry_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("registries.id", ondelete="RESTRICT"))
    registry_host: Mapped[str] = mapped_column(String(255))
    repository_path: Mapped[str] = mapped_column(String(255))
    tag: Mapped[str | None] = mapped_column(String(128))
    digest: Mapped[str] = mapped_column(String(71))
    platform: Mapped[str] = mapped_column(String(30), default="linux/amd64")
    scan_status: Mapped[str] = mapped_column(String(20), default="unknown")
    scan_report_url: Mapped[str | None] = mapped_column(String(1000))
    signed: Mapped[bool] = mapped_column(Boolean, default=False)
    digest_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    revision_label: Mapped[str | None] = mapped_column(String(64))
    labels: Mapped[dict[str, Any] | None]

    release: Mapped[Release] = relationship(back_populates="artifacts")


# ------------------------------------------------------------------ hosts


class DockerHost(TimestampMixin, Base):
    __tablename__ = "docker_hosts"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_host_name"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(63))
    pool: Mapped[str] = mapped_column(String(63))
    status: Mapped[str] = mapped_column(String(20), default="active")
    cert_fingerprint: Mapped[str | None] = mapped_column(String(64), unique=True)
    cert_not_after: Mapped[datetime | None]
    last_seen_at: Mapped[datetime | None]
    facts: Mapped[dict[str, Any] | None]


class HostEnrollToken(TimestampMixin, Base):
    __tablename__ = "host_enroll_tokens"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    host_name: Mapped[str] = mapped_column(String(63))
    pool: Mapped[str] = mapped_column(String(63))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


# ------------------------------------------------------------------ deployments

_ACTIVE_SQL = ", ".join(f"'{s.value}'" for s in sorted(ACTIVE))


class Deployment(TimestampMixin, Base):
    __tablename__ = "deployments"
    __table_args__ = (
        # Hard serialisation guarantee: one executing deployment per environment.
        Index(
            "uq_deployment_active_env",
            "environment_id",
            unique=True,
            postgresql_where=text(f"state IN ({_ACTIVE_SQL})"),
        ),
        Index("ix_deployment_env_created", "environment_id", "created_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("environments.id", ondelete="CASCADE"))
    release_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("releases.id", ondelete="RESTRICT"))
    state: Mapped[str] = mapped_column(String(30), default=DeploymentState.RECEIVED, index=True)
    strategy: Mapped[str] = mapped_column(String(20), default="recreate")
    trigger: Mapped[str] = mapped_column(String(20))
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    requested_by_ci_token_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("ci_tokens.id", ondelete="SET NULL")
    )
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    rollback_of_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("deployments.id", ondelete="SET NULL")
    )
    host_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("docker_hosts.id", ondelete="SET NULL"))
    plan: Mapped[dict[str, Any] | None]
    plan_sha256: Mapped[str | None] = mapped_column(String(64))
    running_digests: Mapped[dict[str, Any] | None]
    error: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(200), unique=True)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class DeploymentEvent(Base):
    __tablename__ = "deployment_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    deployment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("deployments.id", ondelete="CASCADE"), index=True
    )
    state: Mapped[str] = mapped_column(String(30))
    message: Mapped[str] = mapped_column(Text, default="")
    log: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(20), default="control-plane")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


_OPEN_TASK_SQL = f"'{TaskStatus.PENDING.value}', '{TaskStatus.CLAIMED.value}'"


class AgentTaskRow(TimestampMixin, Base):
    __tablename__ = "agent_tasks"
    __table_args__ = (
        Index(
            "uq_agent_task_open_deployment",
            "deployment_id",
            unique=True,
            postgresql_where=text(f"status IN ({_OPEN_TASK_SQL})"),
        ),
        Index("ix_agent_task_host_status", "host_id", "status"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    deployment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("deployments.id", ondelete="CASCADE"))
    host_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("docker_hosts.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(20), default="deploy")
    status: Mapped[str] = mapped_column(String(20), default=TaskStatus.PENDING)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    lease_expires_at: Mapped[datetime | None]
    claimed_at: Mapped[datetime | None]
    completed_at: Mapped[datetime | None]
    result: Mapped[dict[str, Any] | None]


# ------------------------------------------------------------------ audit / outbox


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    actor_type: Mapped[str] = mapped_column(String(20))
    actor_id: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(100), index=True)
    target_type: Mapped[str | None] = mapped_column(String(50))
    target_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any] | None]
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)


class OutboxMessage(Base):
    __tablename__ = "outbox"
    __table_args__ = (Index("ix_outbox_pending", "id", postgresql_where=text("dispatched_at IS NULL")),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    topic: Mapped[str] = mapped_column(String(100))
    payload: Mapped[dict[str, Any]]
    not_before: Mapped[datetime] = mapped_column(default=utcnow)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    dispatched_at: Mapped[datetime | None]
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class DeadLetter(Base):
    __tablename__ = "dead_letters"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    task_name: Mapped[str] = mapped_column(String(200))
    payload: Mapped[dict[str, Any]]
    error: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
