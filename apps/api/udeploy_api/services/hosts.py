"""Docker host enrolment (CSR signing) and the agent task protocol."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from cryptography import x509
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from udeploy_domain.plan import AgentTask, DeploymentPlan
from udeploy_domain.states import TERMINAL, DeploymentState, TaskStatus
from udeploy_security import pki
from udeploy_security.tokens import generate, hash_token

from .. import audit
from ..context import AppContext
from ..errors import APIError, Conflict, Unauthorized
from ..models import AgentTaskRow, Deployment, DockerHost, Environment, HostEnrollToken, Project
from .deployments import add_event, transition
from .secrets import LocalEncryptedSecrets


def create_enroll_token(
    session: AsyncSession, ctx: AppContext, org_id: uuid.UUID, host_name: str, pool: str, user_id: uuid.UUID
) -> tuple[HostEnrollToken, str]:
    token = generate("enroll")
    row = HostEnrollToken(
        organization_id=org_id,
        host_name=host_name,
        pool=pool,
        token_hash=hash_token(token),
        expires_at=datetime.now(UTC) + timedelta(seconds=ctx.settings.enroll_token_ttl_seconds),
        created_by_user_id=user_id,
    )
    session.add(row)
    return row, token


async def enroll(
    ctx: AppContext, session: AsyncSession, token: str, csr_pem: bytes
) -> tuple[DockerHost, bytes]:
    if ctx.pki is None:
        raise APIError("control plane PKI is not initialised (`udeploy-admin init-pki`)", status_code=503)
    row = await session.scalar(
        select(HostEnrollToken).where(HostEnrollToken.token_hash == hash_token(token)).with_for_update()
    )
    now = datetime.now(UTC)
    if row is None or row.used_at is not None or row.expires_at < now:
        raise Unauthorized("enrolment token invalid, expired or already used")
    row.used_at = now  # single use
    host = await session.scalar(
        select(DockerHost).where(
            DockerHost.organization_id == row.organization_id, DockerHost.name == row.host_name
        )
    )
    if host is None:
        host = DockerHost(
            organization_id=row.organization_id, name=row.host_name, pool=row.pool, status="active"
        )
        session.add(host)
        await session.flush()
    else:
        # Re-enrolment replaces the identity: the previous certificate stops working immediately.
        host.pool = row.pool
        host.status = "active"
    try:
        cert_pem = pki.sign_agent_csr(
            ctx.pki.ca_key_pem, ctx.pki.ca_cert_pem, csr_pem, str(host.id), days=ctx.settings.agent_cert_days
        )
    except pki.PKIError as exc:
        raise APIError(str(exc), status_code=400, code="invalid_csr") from exc
    cert = pki.load_cert(cert_pem)
    host.cert_fingerprint = pki.fingerprint(cert)
    host.cert_not_after = pki.not_after(cert)
    audit.record(
        session,
        "host.enrolled",
        actor_type="enroll_token",
        actor_id=row.id,
        organization_id=row.organization_id,
        target_type="host",
        target_id=host.id,
        details={"name": host.name, "pool": host.pool, "fingerprint": host.cert_fingerprint},
    )
    return host, cert_pem


async def host_from_peer_cert(session: AsyncSession, der: bytes | None) -> DockerHost:
    if not der:
        raise Unauthorized("client certificate required")
    fp = pki.fingerprint_der(der)
    host = await session.scalar(select(DockerHost).where(DockerHost.cert_fingerprint == fp))
    if host is None or host.status != "active":
        raise Unauthorized("unknown or disabled agent certificate")
    cert = x509.load_der_x509_certificate(der)
    if pki.host_id_from_cert(cert) != str(host.id):
        raise Unauthorized("certificate identity mismatch")
    return host


async def renew(ctx: AppContext, session: AsyncSession, host: DockerHost, csr_pem: bytes) -> bytes:
    assert ctx.pki is not None
    cert_pem = pki.sign_agent_csr(
        ctx.pki.ca_key_pem, ctx.pki.ca_cert_pem, csr_pem, str(host.id), days=ctx.settings.agent_cert_days
    )
    cert = pki.load_cert(cert_pem)
    host.cert_fingerprint = pki.fingerprint(cert)
    host.cert_not_after = pki.not_after(cert)
    audit.record(
        session,
        "host.certificate_renewed",
        actor_type="agent",
        actor_id=host.id,
        organization_id=host.organization_id,
        target_type="host",
        target_id=host.id,
    )
    return cert_pem


def touch(host: DockerHost, ctx: AppContext) -> None:
    host.last_seen_at = datetime.now(UTC)


async def _try_claim(ctx: AppContext, session: AsyncSession, host: DockerHost) -> AgentTask | None:
    now = datetime.now(UTC)
    rows = (
        await session.scalars(
            select(AgentTaskRow)
            .where(
                AgentTaskRow.host_id == host.id,
                (AgentTaskRow.status == TaskStatus.PENDING)
                # An agent that restarted mid-task resumes its own claimed task.
                | (AgentTaskRow.status == TaskStatus.CLAIMED),
            )
            .order_by(AgentTaskRow.created_at)
            .with_for_update(skip_locked=True)
            .limit(5)
        )
    ).all()
    for task in rows:
        deployment = await session.get(Deployment, task.deployment_id, with_for_update=True)
        assert deployment is not None
        if DeploymentState(deployment.state) in TERMINAL:
            task.status = TaskStatus.FAILED
            task.completed_at = now
            continue
        if task.attempt >= task.max_attempts:
            task.status = TaskStatus.FAILED
            task.completed_at = now
            deployment.error = f"agent task failed {task.attempt} times"
            transition(session, deployment, DeploymentState.FAILED, deployment.error)
            continue
        assert deployment.plan is not None and deployment.plan_sha256 is not None
        plan = DeploymentPlan.model_validate(deployment.plan)
        if plan.sha256() != deployment.plan_sha256:
            task.status = TaskStatus.FAILED
            deployment.error = "stored plan does not match its checksum"
            transition(session, deployment, DeploymentState.FAILED, deployment.error)
            continue
        env = await session.get(Environment, deployment.environment_id)
        project = await session.get(Project, deployment.project_id)
        assert env is not None and project is not None
        refs = {s.ref for svc in plan.services for s in svc.secrets}
        try:
            secrets = await LocalEncryptedSecrets(session, ctx.box).resolve(env, project, refs)
        except KeyError as exc:
            task.status = TaskStatus.FAILED
            deployment.error = str(exc)
            transition(session, deployment, DeploymentState.FAILED, deployment.error)
            continue
        task.status = TaskStatus.CLAIMED
        task.attempt += 1
        task.claimed_at = now
        task.lease_expires_at = now + timedelta(seconds=ctx.settings.agent_lease_seconds)
        add_event(
            session, deployment, deployment.state, f"claimed by agent {host.name} (attempt {task.attempt})"
        )
        return AgentTask.model_validate(
            {
                "task_id": str(task.id),
                "kind": "deploy",
                "attempt": task.attempt,
                "plan": plan,
                "plan_sha256": deployment.plan_sha256,
                "secrets": secrets,
                "lease_seconds": ctx.settings.agent_lease_seconds,
            }
        )
    return None


async def claim(ctx: AppContext, host_id: uuid.UUID, wait_seconds: float) -> AgentTask | None:
    """Long poll: each attempt uses its own short transaction."""
    deadline = asyncio.get_running_loop().time() + wait_seconds
    while True:
        async with ctx.db.session() as session:
            host = await session.get(DockerHost, host_id)
            assert host is not None
            touch(host, ctx)
            task = await _try_claim(ctx, session, host)
            await session.commit()
        if task is not None or asyncio.get_running_loop().time() >= deadline:
            return task
        await asyncio.sleep(1.0)


async def task_for_host(
    session: AsyncSession, host: DockerHost, task_id: uuid.UUID
) -> tuple[AgentTaskRow, Deployment]:
    task = await session.get(AgentTaskRow, task_id, with_for_update=True)
    if task is None or task.host_id != host.id:
        raise Unauthorized("task does not belong to this agent")
    deployment = await session.get(Deployment, task.deployment_id, with_for_update=True)
    assert deployment is not None
    return task, deployment


def renew_lease(task: AgentTaskRow, ctx: AppContext) -> None:
    if task.status != TaskStatus.CLAIMED:
        raise Conflict(f"task is {task.status}")
    task.lease_expires_at = datetime.now(UTC) + timedelta(seconds=ctx.settings.agent_lease_seconds)
