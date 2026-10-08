"""Releases: immutable sets of (service -> digest) produced by CI and verified
against the registry before anything can be deployed."""

from __future__ import annotations

import fnmatch
import logging
import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from udeploy_domain.naming import is_commit_sha, is_digest, normalize_tag
from udeploy_domain.states import ReleaseStatus
from udeploy_providers.registry import DigestMismatch, ManifestNotFound, RegistryError

from .. import audit
from ..context import AppContext
from ..errors import Conflict, NotFound, PolicyViolation
from ..models import Artifact, Environment, Project, Registry, Release, Service, WebhookDelivery
from . import outbox

log = logging.getLogger("udeploy.releases")

OCI_REVISION_LABEL = "org.opencontainers.image.revision"


class ScanInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["passed", "failed", "skipped", "unknown"] = "unknown"
    report_url: str | None = Field(None, max_length=1000)


class ArtifactIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: str = Field(max_length=40)
    registry: str = Field(max_length=63, description="registry name configured in the organization")
    image: str | None = Field(None, max_length=255, description="repository path; must match the service")
    tag: str | None = Field(None, max_length=128)
    digest: str
    platform: Literal["linux/amd64", "linux/arm64"] = "linux/amd64"
    scan: ScanInfo = Field(default_factory=ScanInfo)
    signed: bool = False

    @field_validator("digest")
    @classmethod
    def _digest(cls, v: str) -> str:
        if not is_digest(v):
            raise ValueError("digest must be sha256:<64 hex>")
        return v


class ReleaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(max_length=128)
    commit_sha: str
    branch: str | None = Field(None, max_length=255)
    tag: str | None = Field(None, max_length=255)
    build_id: str | None = Field(None, max_length=255)
    build_url: str | None = Field(None, max_length=1000)
    artifacts: list[ArtifactIn] = Field(min_length=1, max_length=50)

    @field_validator("commit_sha")
    @classmethod
    def _sha(cls, v: str) -> str:
        if not is_commit_sha(v):
            raise ValueError("commit_sha must be a full 40 (or 64) hex commit id")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if normalize_tag(v) != v:
            raise ValueError("version must be a valid OCI tag (no '/', spaces, ...)")
        return v


def _fingerprint(
    commit_sha: str, artifacts: list[tuple[str, str, str]]
) -> tuple[str, frozenset[tuple[str, str, str]]]:
    return commit_sha, frozenset(artifacts)


async def create_release(
    session: AsyncSession,
    project: Project,
    data: ReleaseIn,
    *,
    ci_token_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
) -> tuple[Release, bool]:
    """Returns (release, created). Re-posting identical data is idempotent;
    re-using a version with different content is refused (anti re-tag)."""
    services = {
        s.name: s for s in (await session.scalars(select(Service).where(Service.project_id == project.id)))
    }
    registries = {
        r.name: r
        for r in (
            await session.scalars(select(Registry).where(Registry.organization_id == project.organization_id))
        )
    }
    names = [a.service for a in data.artifacts]
    if len(names) != len(set(names)):
        raise PolicyViolation("an artifact is listed twice for the same service")

    resolved: list[tuple[ArtifactIn, Registry, str]] = []
    for art in data.artifacts:
        svc = services.get(art.service)
        if svc is None:
            raise PolicyViolation(f"unknown service {art.service!r} for project {project.slug}")
        reg = registries.get(art.registry)
        if reg is None:
            raise PolicyViolation(f"unknown registry {art.registry!r}")
        expected_path = "/".join(p for p in (reg.namespace.strip("/"), svc.image_repository) if p)
        if art.image is not None and art.image != expected_path:
            # Artifact substitution protection: a project can only ship its own image names.
            raise PolicyViolation(
                f"{art.service}: image {art.image!r} does not match expected {expected_path!r}"
            )
        resolved.append((art, reg, expected_path))

    incoming = _fingerprint(data.commit_sha, [(a.service, path, a.digest) for a, _r, path in resolved])
    existing = await session.scalar(
        select(Release).where(Release.project_id == project.id, Release.version == data.version)
    )
    if existing is not None:
        current = _fingerprint(
            existing.commit_sha, [(a.service_name, a.repository_path, a.digest) for a in existing.artifacts]
        )
        if current == incoming:
            return existing, False
        audit.record(
            session,
            "release.retag_rejected",
            actor_type="ci" if ci_token_id else "user",
            actor_id=ci_token_id or user_id,
            organization_id=project.organization_id,
            target_type="release",
            target_id=existing.id,
            details={"version": data.version, "commit_sha": data.commit_sha},
        )
        await session.commit()
        raise Conflict(
            f"release {data.version} already exists with different content; versions are immutable",
            details={"release_id": str(existing.id)},
        )

    source = await session.scalar(
        select(WebhookDelivery)
        .where(WebhookDelivery.commit_sha == data.commit_sha, WebhookDelivery.status == "accepted")
        .order_by(WebhookDelivery.received_at.desc())
        .limit(1)
    )
    release = Release(
        project_id=project.id,
        version=data.version,
        commit_sha=data.commit_sha,
        branch=data.branch,
        tag=data.tag,
        build_id=data.build_id,
        build_url=data.build_url,
        status=ReleaseStatus.PENDING_VERIFICATION,
        created_by_ci_token_id=ci_token_id,
        created_by_user_id=user_id,
        source_delivery_id=source.id if source else None,
    )
    session.add(release)
    await session.flush()
    for art, reg, path in resolved:
        session.add(
            Artifact(
                release_id=release.id,
                service_name=art.service,
                registry_id=reg.id,
                registry_host=reg.host,
                repository_path=path,
                tag=art.tag,
                digest=art.digest,
                platform=art.platform,
                scan_status=art.scan.status,
                scan_report_url=art.scan.report_url,
                signed=art.signed,
            )
        )
    outbox.enqueue(session, outbox.TOPIC_VERIFY_RELEASE, {"release_id": str(release.id)})
    audit.record(
        session,
        "release.created",
        actor_type="ci" if ci_token_id else "user",
        actor_id=ci_token_id or user_id,
        organization_id=project.organization_id,
        target_type="release",
        target_id=release.id,
        details={
            "version": data.version,
            "commit_sha": data.commit_sha,
            "artifacts": {a.service: a.digest for a, _r, _p in resolved},
            "linked_webhook_delivery": str(source.id) if source else None,
        },
    )
    await session.flush()
    await session.refresh(release, ["artifacts"])
    return release, True


class VerifyOutcome(BaseModel):
    status: Literal["verified", "failed", "retry"]
    detail: str = ""


async def verify_release(ctx: AppContext, session: AsyncSession, release_id: uuid.UUID) -> VerifyOutcome:
    """Check every artifact digest against its registry (content-addressed)."""
    release = await session.get(Release, release_id, with_for_update=True)
    if release is None:
        raise NotFound("release not found")
    if release.status != ReleaseStatus.PENDING_VERIFICATION:
        return VerifyOutcome(status="verified" if release.status == ReleaseStatus.VERIFIED else "failed")
    project = await session.get(Project, release.project_id)
    assert project is not None
    release.verify_attempts += 1
    problems: list[str] = []
    retryable = False
    for art in release.artifacts:
        registry = await session.get(Registry, art.registry_id)
        assert registry is not None
        client = ctx.registry_factory(registry, ctx.box)
        try:
            config = await client.image_config(art.repository_path, art.digest, art.platform)
            if config.platform != art.platform:
                problems.append(f"{art.service_name}: image platform {config.platform} != {art.platform}")
                continue
            revision = config.labels.get(OCI_REVISION_LABEL)
            art.labels = config.labels
            art.revision_label = revision
            if revision is not None and revision != release.commit_sha:
                problems.append(
                    f"{art.service_name}: image was built from {revision}, not from {release.commit_sha}"
                )
                continue
            if art.tag:
                current = await client.resolve(art.repository_path, art.tag)
                if current.digest != art.digest and current.digest != config.manifest_digest:
                    problems.append(f"{art.service_name}: tag {art.tag} now points to {current.digest}")
                    continue
            art.digest_verified = True
        except ManifestNotFound as exc:
            retryable = True
            problems.append(f"{art.service_name}: {exc}")
        except DigestMismatch as exc:
            problems.append(f"{art.service_name}: {exc}")
        except RegistryError as exc:
            retryable = retryable or exc.retryable
            problems.append(f"{art.service_name}: {type(exc).__name__}: {exc}")
        finally:
            await client.aclose()

    if not problems:
        release.status = ReleaseStatus.VERIFIED
        release.verified_at = datetime.now(UTC)
        release.status_detail = "all digests present in registry"
        audit.record(
            session,
            "release.verified",
            actor_type="system",
            actor_id=None,
            organization_id=project.organization_id,
            target_type="release",
            target_id=release.id,
        )
        await _auto_deploy(ctx, session, project, release)
        return VerifyOutcome(status="verified")

    detail = "; ".join(problems)
    if retryable and release.verify_attempts < ctx.settings.release_verify_max_retries:
        release.status_detail = f"attempt {release.verify_attempts}: {detail}"
        delay = ctx.settings.release_verify_backoff_seconds * (2 ** (release.verify_attempts - 1))
        outbox.enqueue(
            session, outbox.TOPIC_VERIFY_RELEASE, {"release_id": str(release.id)}, delay_seconds=delay
        )
        return VerifyOutcome(status="retry", detail=detail)
    release.status = ReleaseStatus.VERIFICATION_FAILED
    release.status_detail = detail
    audit.record(
        session,
        "release.verification_failed",
        actor_type="system",
        actor_id=None,
        organization_id=project.organization_id,
        target_type="release",
        target_id=release.id,
        details={"detail": detail},
    )
    return VerifyOutcome(status="failed", detail=detail)


def release_matches_environment(release: Release, env: Environment) -> bool:
    """Environment rules: tag patterns and/or branch patterns. No rule = any release."""
    if not env.tags and not env.branches:
        return True
    if release.tag and any(fnmatch.fnmatchcase(release.tag, p) for p in env.tags):
        return True
    return bool(release.branch and any(fnmatch.fnmatchcase(release.branch, p) for p in env.branches))


async def _auto_deploy(ctx: AppContext, session: AsyncSession, project: Project, release: Release) -> None:
    from ..models import Deployment
    from .deployments import request_deployment  # circular import guard

    envs = (await session.scalars(select(Environment).where(Environment.project_id == project.id))).all()
    for env in envs:
        if not (env.auto_deploy and (env.tags or env.branches) and release_matches_environment(release, env)):
            continue
        # Out-of-order protection: never auto-deploy an older release over a newer one.
        newer = await session.scalar(
            select(Deployment.id)
            .join(Release, Release.id == Deployment.release_id)
            .where(
                Deployment.environment_id == env.id,
                Deployment.state.notin_(["failed", "cancelled", "blocked_by_policy", "rolled_back"]),
                Release.created_at > release.created_at,
            )
            .limit(1)
        )
        if newer is not None:
            audit.record(
                session,
                "release.auto_deploy_skipped",
                actor_type="system",
                actor_id=None,
                organization_id=project.organization_id,
                target_type="release",
                target_id=release.id,
                details={"environment": env.name, "reason": "a newer release is already deployed or queued"},
            )
            continue
        await request_deployment(
            ctx, session, project=project, environment=env, release=release, trigger="auto"
        )
