"""Deployment orchestration on the control-plane side.

Responsibilities: policy gates, approval, serialisation per environment,
host selection, immutable plan generation, agent result handling and
crash/timeout reconciliation. Actual Docker work happens only on the agent.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from udeploy_domain.manifest import ServiceSpec
from udeploy_domain.plan import PreviousRelease, ReleaseRef, RoutePlan, TaskResult
from udeploy_domain.states import (
    ACTIVE,
    TERMINAL,
    DeploymentState,
    ReleaseStatus,
    TaskStatus,
    check_transition,
)
from udeploy_planner.builder import ArtifactRef, PlanInputs, build_plan
from udeploy_planner.policy import PlanRejected
from udeploy_security.masking import mask

from .. import audit
from ..context import AppContext
from ..errors import Conflict, Forbidden, PolicyViolation
from ..models import (
    AgentTaskRow,
    Artifact,
    Deployment,
    DeploymentEvent,
    DockerHost,
    Environment,
    Organization,
    Project,
    Registry,
    Release,
    Route,
    Service,
)
from . import outbox
from .releases import release_matches_environment
from .secrets import LocalEncryptedSecrets

log = logging.getLogger("udeploy.deployments")
S = DeploymentState
PRE_EXECUTION = {S.RECEIVED, S.VALIDATED, S.AWAITING_APPROVAL, S.QUEUED}


def add_event(
    session: AsyncSession,
    deployment: Deployment,
    state: str,
    message: str = "",
    *,
    log_text: str = "",
    source: str = "control-plane",
) -> None:
    session.add(
        DeploymentEvent(
            deployment_id=deployment.id,
            state=state,
            message=mask(message)[:4000],
            log=mask(log_text)[:64000],
            source=source,
        )
    )


def transition(
    session: AsyncSession, deployment: Deployment, target: DeploymentState, message: str = ""
) -> None:
    check_transition(DeploymentState(deployment.state), target)
    deployment.state = target
    now = datetime.now(UTC)
    deployment.updated_at = now
    if target in TERMINAL:
        deployment.finished_at = now
    add_event(session, deployment, target, message)


def _policy_flags(project: Project) -> tuple[bool, bool]:
    release_policy = (project.manifest or {}).get("release", {})
    return bool(release_policy.get("requireScanPass", True)), bool(
        release_policy.get("requireSignedArtifact", False)
    )


async def request_deployment(
    ctx: AppContext,
    session: AsyncSession,
    *,
    project: Project,
    environment: Environment,
    release: Release,
    trigger: str,
    user_id: uuid.UUID | None = None,
    ci_token_id: uuid.UUID | None = None,
    idempotency_key: str | None = None,
    rollback_of: Deployment | None = None,
) -> Deployment:
    if idempotency_key:
        existing = await session.scalar(
            select(Deployment).where(Deployment.idempotency_key == idempotency_key)
        )
        if existing is not None:
            if existing.release_id != release.id or existing.environment_id != environment.id:
                raise Conflict("Idempotency-Key reused for a different deployment request")
            return existing
    if release.project_id != project.id or environment.project_id != project.id:
        raise PolicyViolation("release and environment must belong to the project")
    if release.status != ReleaseStatus.VERIFIED:
        raise Conflict(f"release {release.version} is not verified (status: {release.status})")

    deployment = Deployment(
        project_id=project.id,
        environment_id=environment.id,
        release_id=release.id,
        trigger=trigger,
        state=S.RECEIVED,
        requested_by_user_id=user_id,
        requested_by_ci_token_id=ci_token_id,
        idempotency_key=idempotency_key,
        rollback_of_id=rollback_of.id if rollback_of else None,
    )
    session.add(deployment)
    await session.flush()
    add_event(
        session, deployment, S.RECEIVED, f"{trigger} deployment of {release.version} to {environment.name}"
    )

    problems: list[str] = []
    if not release_matches_environment(release, environment):
        problems.append(
            f"release {release.version} (tag={release.tag}, branch={release.branch}) is not allowed in "
            f"{environment.name} (tags={environment.tags}, branches={environment.branches})"
        )
    require_scan, require_signed = _policy_flags(project)
    for art in release.artifacts:
        if not art.digest_verified:
            problems.append(f"{art.service_name}: digest not verified in registry")
        if require_scan and art.scan_status != "passed":
            problems.append(
                f"{art.service_name}: vulnerability scan status is {art.scan_status!r}, 'passed' required"
            )
        if require_signed:
            problems.append(
                f"{art.service_name}: requireSignedArtifact is set but signature verification is not "
                "implemented in this version (phase 2); refusing to deploy (fail closed)"
            )
    if problems:
        deployment.error = "; ".join(problems)
        transition(session, deployment, S.BLOCKED_BY_POLICY, deployment.error)
        audit.record(
            session,
            "deployment.blocked_by_policy",
            actor_type="system",
            actor_id=None,
            organization_id=project.organization_id,
            target_type="deployment",
            target_id=deployment.id,
            details={"problems": problems},
        )
        return deployment

    transition(session, deployment, S.VALIDATED)
    skip_approval = trigger == "rollback" and rollback_of is not None
    if environment.require_approval and not skip_approval:
        transition(session, deployment, S.AWAITING_APPROVAL, "production gate: waiting for a second person")
    else:
        transition(session, deployment, S.QUEUED)
        outbox.enqueue(session, outbox.TOPIC_START_DEPLOYMENT, {"deployment_id": str(deployment.id)})
    audit.record(
        session,
        "deployment.requested",
        actor_type="user" if user_id else ("ci" if ci_token_id else "system"),
        actor_id=user_id or ci_token_id,
        organization_id=project.organization_id,
        target_type="deployment",
        target_id=deployment.id,
        details={"release": release.version, "environment": environment.name, "trigger": trigger},
    )
    return deployment


async def approve(
    ctx: AppContext, session: AsyncSession, deployment: Deployment, approver_id: uuid.UUID
) -> None:
    if deployment.state != S.AWAITING_APPROVAL:
        raise Conflict(f"deployment is {deployment.state}, not awaiting approval")
    if deployment.requested_by_user_id == approver_id:
        raise Forbidden("four-eyes rule: the requester cannot approve their own deployment")
    deployment.approved_by_user_id = approver_id
    transition(session, deployment, S.QUEUED, "approved")
    outbox.enqueue(session, outbox.TOPIC_START_DEPLOYMENT, {"deployment_id": str(deployment.id)})


async def cancel(session: AsyncSession, deployment: Deployment) -> None:
    state = DeploymentState(deployment.state)
    if state in TERMINAL:
        raise Conflict(f"deployment already {state}")
    if state in PRE_EXECUTION:
        transition(session, deployment, S.CANCELLED, "cancelled before execution")
        return
    # Executing: the agent sees the flag on its next report and restores the previous release.
    deployment.cancel_requested = True
    add_event(session, deployment, deployment.state, "cancellation requested; agent will roll back")


async def find_rollback_target(session: AsyncSession, deployment: Deployment) -> Deployment:
    """Most recent successful deployment of the environment that is not `deployment`."""
    env = await session.get(Environment, deployment.environment_id)
    assert env is not None
    candidates = (
        await session.scalars(
            select(Deployment)
            .where(
                Deployment.environment_id == env.id,
                Deployment.state == S.SUCCEEDED,
                Deployment.id != deployment.id,
                Deployment.release_id != deployment.release_id,
                Deployment.created_at < deployment.created_at,
            )
            .order_by(Deployment.created_at.desc())
            .limit(1)
        )
    ).all()
    if not candidates:
        raise Conflict("no previous successful release to roll back to")
    return candidates[0]


# ---------------------------------------------------------------- worker side


async def _select_host(
    session: AsyncSession, ctx: AppContext, env: Environment, org_id: uuid.UUID
) -> DockerHost | None:
    cutoff = datetime.now(UTC) - timedelta(seconds=ctx.settings.agent_offline_after_seconds)
    if env.pinned_host_id is not None:
        host = await session.get(DockerHost, env.pinned_host_id)
        if host and host.status == "active" and host.last_seen_at and host.last_seen_at >= cutoff:
            return host
        return None  # data volumes live on the pinned host: never move silently
    return await session.scalar(
        select(DockerHost)
        .where(
            DockerHost.organization_id == org_id,
            DockerHost.pool == env.host_pool,
            DockerHost.status == "active",
            DockerHost.last_seen_at >= cutoff,
        )
        .order_by(DockerHost.name)
        .limit(1)
    )


async def _plan_inputs(
    ctx: AppContext,
    session: AsyncSession,
    deployment: Deployment,
    project: Project,
    env: Environment,
    release: Release,
    host: DockerHost,
) -> PlanInputs:
    org = await session.get(Organization, project.organization_id)
    assert org is not None
    services = (await session.scalars(select(Service).where(Service.project_id == project.id))).all()
    routes_rows = (
        await session.execute(
            select(Route, Service.name)
            .join(Service, Service.id == Route.service_id)
            .where(Route.environment_id == env.id)
        )
    ).all()
    routes: dict[str, list[RoutePlan]] = {}
    for route, svc_name in sorted(routes_rows, key=lambda r: (r[1], r[0].host, r[0].path_prefix)):
        routes.setdefault(svc_name, []).append(
            RoutePlan(host=route.host, path_prefix=route.path_prefix, tls=route.tls)
        )
    artifacts = {
        a.service_name: ArtifactRef(a.registry_host, a.repository_path, a.digest, a.platform)
        for a in release.artifacts
    }
    previous: PreviousRelease | None = None
    previous_artifacts: dict[str, ArtifactRef] = {}
    if env.current_deployment_id:
        prev = await session.get(Deployment, env.current_deployment_id)
        if prev is not None and prev.plan:
            prev_release = await session.get(Release, prev.release_id)
            assert prev_release is not None
            prev_services = prev.plan.get("services", [])
            previous = PreviousRelease(
                deployment_id=str(prev.id),
                release_version=prev_release.version,
                digests={s["name"]: s["digest"] for s in prev_services},
            )
            for s in prev_services:
                host_part, path_part = s["image"].split("@")[0].split("/", 1)
                previous_artifacts[s["name"]] = ArtifactRef(host_part, path_part, s["digest"], s["platform"])
    registries = (
        await session.scalars(select(Registry.host).where(Registry.organization_id == org.id))
    ).all()
    secrets = LocalEncryptedSecrets(session, ctx.box)
    return PlanInputs(
        plan_id=str(uuid.uuid4()),
        deployment_id=str(deployment.id),
        host_id=str(host.id),
        organization=org.slug,
        project=project.slug,
        environment=env.name,
        release=ReleaseRef(id=str(release.id), version=release.version, commit_sha=release.commit_sha),
        services={s.name: ServiceSpec.model_validate(s.spec) for s in services},
        routes=routes,
        artifacts=artifacts,
        previous=previous,
        previous_artifacts=previous_artifacts,
        allowed_registries=frozenset(registries),
        available_secrets=await secrets.available_paths(env.id),
    )


async def start_deployment(ctx: AppContext, session: AsyncSession, deployment_id: uuid.UUID) -> str:
    """Idempotent: safe to run several times for the same deployment."""
    deployment = await session.get(Deployment, deployment_id, with_for_update=True)
    if deployment is None:
        return "missing"
    if deployment.state != S.QUEUED:
        return f"noop:{deployment.state}"
    if deployment.cancel_requested:
        transition(session, deployment, S.CANCELLED, "cancelled before execution")
        return "cancelled"
    env = await session.get(Environment, deployment.environment_id, with_for_update=True)
    project = await session.get(Project, deployment.project_id)
    release = await session.get(Release, deployment.release_id)
    assert env is not None and project is not None and release is not None

    # Arbitration: an automatic deployment superseded by a newer queued automatic one is dropped.
    if deployment.trigger == "auto":
        newer = await session.scalar(
            select(Deployment.id)
            .where(
                Deployment.environment_id == env.id,
                Deployment.state == S.QUEUED,
                Deployment.trigger == "auto",
                Deployment.created_at > deployment.created_at,
            )
            .limit(1)
        )
        if newer is not None:
            transition(session, deployment, S.CANCELLED, f"superseded by newer deployment {newer}")
            return "superseded"

    active = await session.scalar(
        select(Deployment.id)
        .where(Deployment.environment_id == env.id, Deployment.state.in_(list(ACTIVE)))
        .limit(1)
    )
    if active is not None:
        outbox.enqueue(
            session, outbox.TOPIC_START_DEPLOYMENT, {"deployment_id": str(deployment.id)}, delay_seconds=10
        )
        return "waiting_for_environment_lock"

    host = await _select_host(session, ctx, env, project.organization_id)
    if host is None:
        age = (datetime.now(UTC) - deployment.created_at).total_seconds()
        if age > ctx.settings.deployment_stuck_after_seconds:
            deployment.error = f"no online Docker host in pool {env.host_pool!r}"
            transition(session, deployment, S.FAILED, deployment.error)
            return "failed_no_host"
        add_event(
            session, deployment, deployment.state, f"waiting for an online host in pool {env.host_pool!r}"
        )
        outbox.enqueue(
            session, outbox.TOPIC_START_DEPLOYMENT, {"deployment_id": str(deployment.id)}, delay_seconds=15
        )
        return "waiting_for_host"

    try:
        inputs = await _plan_inputs(ctx, session, deployment, project, env, release, host)
        plan = build_plan(inputs)
    except PlanRejected as exc:
        deployment.error = str(exc)
        transition(session, deployment, S.BLOCKED_BY_POLICY, str(exc))
        return "blocked"

    deployment.plan = plan.model_dump(mode="json")
    deployment.plan_sha256 = plan.sha256()
    deployment.host_id = host.id
    deployment.started_at = datetime.now(UTC)
    transition(session, deployment, S.PREPARING, f"plan {plan.plan_id} for host {host.name}")
    session.add(
        AgentTaskRow(
            deployment_id=deployment.id,
            host_id=host.id,
            max_attempts=ctx.settings.task_max_attempts,
        )
    )
    try:
        await session.flush()
    except IntegrityError:
        # Lost a race on the partial unique index: another deployment became active.
        await session.rollback()
        async with ctx.db.session() as s2:
            outbox.enqueue(
                s2, outbox.TOPIC_START_DEPLOYMENT, {"deployment_id": str(deployment_id)}, delay_seconds=10
            )
            await s2.commit()
        return "lost_race"
    return "dispatched"


async def apply_agent_event(
    session: AsyncSession, deployment: Deployment, state: DeploymentState, message: str, log_text: str
) -> None:
    current = DeploymentState(deployment.state)
    if current in TERMINAL:
        return
    if state != current:
        if _is_replay(current, state):
            # A re-claimed task (agent restart) replays earlier steps: record, do not move backwards.
            add_event(
                session, deployment, current, f"[replay {state}] {message}", log_text=log_text, source="agent"
            )
            return
        check_transition(current, state)
        deployment.state = state
    deployment.updated_at = datetime.now(UTC)
    add_event(session, deployment, state, message, log_text=log_text, source="agent")


_EXECUTION = [S.PREPARING, S.PULLING, S.VERIFYING, S.STARTING, S.HEALTHCHECKING, S.SWITCHING]


def _is_replay(current: DeploymentState, target: DeploymentState) -> bool:
    return (
        current in _EXECUTION
        and target in _EXECUTION
        and _EXECUTION.index(target) < _EXECUTION.index(current)
    )


async def apply_agent_result(
    session: AsyncSession, task: AgentTaskRow, deployment: Deployment, result: TaskResult
) -> None:
    now = datetime.now(UTC)
    task.status = TaskStatus.DONE if result.outcome == "succeeded" else TaskStatus.FAILED
    task.completed_at = now
    task.result = result.model_dump(mode="json")
    target = {"succeeded": S.SUCCEEDED, "rolled_back": S.ROLLED_BACK, "failed": S.FAILED}[result.outcome]
    current = DeploymentState(deployment.state)
    if current in TERMINAL:
        return
    if target == S.ROLLED_BACK and current not in (S.ROLLBACK_PENDING,):
        check_transition(current, S.ROLLBACK_PENDING)
        deployment.state = S.ROLLBACK_PENDING
    deployment.error = result.error
    deployment.running_digests = result.running_digests
    transition(session, deployment, target, result.error or result.outcome)
    if target == S.SUCCEEDED:
        env = await session.get(Environment, deployment.environment_id, with_for_update=True)
        assert env is not None
        env.current_deployment_id = deployment.id
        env.pinned_host_id = deployment.host_id
    project = await session.get(Project, deployment.project_id)
    assert project is not None
    audit.record(
        session,
        f"deployment.{result.outcome}",
        actor_type="agent",
        actor_id=task.host_id,
        organization_id=project.organization_id,
        target_type="deployment",
        target_id=deployment.id,
        details={"running_digests": result.running_digests, "error": result.error},
    )


async def reconcile(ctx: AppContext, session: AsyncSession) -> dict[str, int]:
    """Periodic crash recovery. Never performs destructive runtime actions."""
    now = datetime.now(UTC)
    stats = {"requeued_tasks": 0, "failed_tasks": 0, "redispatched": 0, "timed_out": 0, "reverify": 0}
    offline_cutoff = now - timedelta(seconds=ctx.settings.agent_offline_after_seconds)

    expired = (
        await session.scalars(
            select(AgentTaskRow)
            .where(AgentTaskRow.status == TaskStatus.CLAIMED, AgentTaskRow.lease_expires_at < now)
            .with_for_update(skip_locked=True)
        )
    ).all()
    for task in expired:
        deployment = await session.get(Deployment, task.deployment_id, with_for_update=True)
        assert deployment is not None
        if task.attempt >= task.max_attempts:
            task.status = TaskStatus.FAILED
            task.completed_at = now
            if DeploymentState(deployment.state) not in TERMINAL:
                deployment.error = (
                    "agent lost during execution after "
                    f"{task.attempt} attempts; runtime state on the host must be inspected"
                )
                transition(session, deployment, S.FAILED, deployment.error)
            stats["failed_tasks"] += 1
        else:
            # Back to pending: the same host re-claims it when it reconnects (plans are idempotent).
            task.status = TaskStatus.PENDING
            task.lease_expires_at = None
            add_event(
                session, deployment, deployment.state, "agent lease expired; task re-queued for the host"
            )
            stats["requeued_tasks"] += 1

    # Lost queue messages: queued deployments with no pending outbox entry are re-dispatched.
    stale_queued = (
        await session.scalars(
            select(Deployment).where(
                Deployment.state == S.QUEUED, Deployment.updated_at < now - timedelta(seconds=60)
            )
        )
    ).all()
    for dep in stale_queued:
        outbox.enqueue(session, outbox.TOPIC_START_DEPLOYMENT, {"deployment_id": str(dep.id)})
        dep.updated_at = now
        stats["redispatched"] += 1

    stuck_cutoff = now - timedelta(seconds=ctx.settings.deployment_stuck_after_seconds)
    stuck = (
        await session.scalars(
            select(Deployment).where(
                Deployment.state.in_(list(ACTIVE)),
                or_(
                    Deployment.updated_at < stuck_cutoff,
                    and_(Deployment.host_id.is_(None), Deployment.updated_at < stuck_cutoff),
                ),
            )
        )
    ).all()
    for dep in stuck:
        host = await session.get(DockerHost, dep.host_id) if dep.host_id else None
        if host and host.last_seen_at and host.last_seen_at >= offline_cutoff:
            continue  # agent alive and still reporting; not stuck from our point of view
        dep.error = "deployment timed out without agent progress"
        transition(session, dep, S.FAILED, dep.error)
        for task in (
            await session.scalars(
                select(AgentTaskRow).where(
                    AgentTaskRow.deployment_id == dep.id,
                    AgentTaskRow.status.in_([TaskStatus.PENDING, TaskStatus.CLAIMED]),
                )
            )
        ).all():
            task.status = TaskStatus.FAILED
            task.completed_at = now
        stats["timed_out"] += 1

    pending_releases = (
        await session.scalars(
            select(Release).where(
                Release.status == ReleaseStatus.PENDING_VERIFICATION,
                Release.created_at < now - timedelta(minutes=10),
            )
        )
    ).all()
    for rel in pending_releases:
        outbox.enqueue(session, outbox.TOPIC_VERIFY_RELEASE, {"release_id": str(rel.id)})
        stats["reverify"] += 1
    return stats


def deployment_view(dep: Deployment) -> dict[str, Any]:
    return {
        "id": str(dep.id),
        "project_id": str(dep.project_id),
        "environment_id": str(dep.environment_id),
        "release_id": str(dep.release_id),
        "state": dep.state,
        "strategy": dep.strategy,
        "trigger": dep.trigger,
        "host_id": str(dep.host_id) if dep.host_id else None,
        "plan_sha256": dep.plan_sha256,
        "running_digests": dep.running_digests,
        "error": dep.error,
        "cancel_requested": dep.cancel_requested,
        "requested_by_user_id": str(dep.requested_by_user_id) if dep.requested_by_user_id else None,
        "approved_by_user_id": str(dep.approved_by_user_id) if dep.approved_by_user_id else None,
        "rollback_of_id": str(dep.rollback_of_id) if dep.rollback_of_id else None,
        "created_at": dep.created_at.isoformat(),
        "started_at": dep.started_at.isoformat() if dep.started_at else None,
        "finished_at": dep.finished_at.isoformat() if dep.finished_at else None,
    }


async def artifacts_of(session: AsyncSession, release_id: uuid.UUID) -> list[Artifact]:
    return list((await session.scalars(select(Artifact).where(Artifact.release_id == release_id))).all())
