"""Agent protocol.

`/v1/agent/enroll` lives on the public API (bootstrap with a single-use token).
Everything else is served only by the mTLS listener: the peer certificate is
extracted by `udeploy_api.mtls` and mapped to a DockerHost by fingerprint.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from udeploy_domain.plan import ClaimResponse, HostFacts, TaskEvent, TaskResult
from udeploy_domain.states import AGENT_REPORTABLE, InvalidTransition

from ..deps import Ctx, Session, client_ip, rate_limit
from ..errors import APIError, Conflict
from ..models import DockerHost
from ..services import deployments as dsvc
from ..services import hosts as hsvc

public_router = APIRouter(prefix="/v1/agent", tags=["agent-enrolment"])
mtls_router = APIRouter(prefix="/v1/agent", tags=["agent"])


class EnrollIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(max_length=200)
    csr_pem: str = Field(max_length=8000)


@public_router.post("/enroll", status_code=201)
async def enroll(body: EnrollIn, request: Request, ctx: Ctx, session: Session) -> dict[str, Any]:
    await rate_limit(request, f"enroll:{client_ip(request)}", 10)
    host, cert_pem = await hsvc.enroll(ctx, session, body.token, body.csr_pem.encode())
    await session.commit()
    assert ctx.pki is not None
    return {
        "host_id": str(host.id),
        "certificate_pem": cert_pem.decode(),
        "ca_pem": ctx.pki.ca_cert_pem.decode(),
        "agent_api_url": ctx.settings.agent_api_url,
    }


async def current_host(request: Request, session: Session) -> DockerHost:
    der = getattr(request.state, "tls_peer_cert_der", None)
    return await hsvc.host_from_peer_cert(session, der)


Host = Annotated[DockerHost, Depends(current_host)]


@mtls_router.post("/heartbeat")
async def heartbeat(facts: HostFacts, ctx: Ctx, session: Session, host: Host) -> dict[str, Any]:
    hsvc.touch(host, ctx)
    host.facts = facts.model_dump(mode="json")
    await session.commit()
    return {"host_id": str(host.id), "status": host.status}


@mtls_router.post("/tasks/claim", response_model=ClaimResponse)
async def claim_task(ctx: Ctx, session: Session, host: Host, wait: float = 20) -> JSONResponse:
    host_id = host.id
    await session.commit()  # release the identity lookup transaction before long polling
    wait = max(0.0, min(wait, float(ctx.settings.agent_long_poll_seconds)))
    task = await hsvc.claim(ctx, host_id, wait)
    # Secrets are revealed only here, inside the mTLS channel, for this host's task.
    return JSONResponse({"task": task.wire_json() if task else None})


@mtls_router.post("/tasks/{task_id}/events")
async def task_event(
    task_id: uuid.UUID, event: TaskEvent, ctx: Ctx, session: Session, host: Host
) -> dict[str, Any]:
    if event.state not in AGENT_REPORTABLE:
        raise APIError(f"agents cannot report state {event.state}", status_code=422)
    task, deployment = await hsvc.task_for_host(session, host, task_id)
    hsvc.renew_lease(task, ctx)
    hsvc.touch(host, ctx)
    try:
        await dsvc.apply_agent_event(session, deployment, event.state, event.message, event.log)
    except InvalidTransition as exc:
        raise Conflict(str(exc)) from exc
    await session.commit()
    return {
        "cancel_requested": deployment.cancel_requested,
        "lease_seconds": ctx.settings.agent_lease_seconds,
    }


@mtls_router.post("/tasks/{task_id}/complete")
async def task_complete(
    task_id: uuid.UUID, result: TaskResult, ctx: Ctx, session: Session, host: Host
) -> dict[str, Any]:
    task, deployment = await hsvc.task_for_host(session, host, task_id)
    if task.status != "claimed":
        # Idempotent: a retried completion after a network error is acknowledged.
        return {"status": task.status}
    try:
        await dsvc.apply_agent_result(session, task, deployment, result)
    except InvalidTransition as exc:
        raise Conflict(str(exc)) from exc
    hsvc.touch(host, ctx)
    await session.commit()
    return {"status": task.status, "deployment_state": deployment.state}


class RenewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    csr_pem: str = Field(max_length=8000)


@mtls_router.post("/renew")
async def renew_certificate(body: RenewIn, ctx: Ctx, session: Session, host: Host) -> dict[str, Any]:
    cert_pem = await hsvc.renew(ctx, session, host, body.csr_pem.encode())
    await session.commit()
    return {"certificate_pem": cert_pem.decode()}
