from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import CIPrincipal, Perm, Principal, authenticate_ci, authenticate_user
from .context import AppContext
from .errors import APIError, NotFound, RateLimited, Unauthorized
from .models import Environment, Project

log = logging.getLogger("udeploy.api")


def get_ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


async def get_session(ctx: Annotated[AppContext, Depends(get_ctx)]) -> AsyncIterator[AsyncSession]:
    async with ctx.db.session() as session:
        yield session


Ctx = Annotated[AppContext, Depends(get_ctx)]
Session = Annotated[AsyncSession, Depends(get_session)]


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def rate_limit(request: Request, bucket: str, limit: int, window: int = 60) -> None:
    """Fixed-window limiter in Redis. Fails open (logged) if Redis is unavailable."""
    redis = getattr(request.app.state, "redis", None)
    if redis is None or limit <= 0:
        return
    key = f"udeploy:rl:{bucket}:{int(time.time() // window)}"
    try:
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, window + 1)
    except Exception:
        log.warning("rate limiter unavailable; failing open", extra={"bucket": bucket})
        return
    if count > limit:
        raise RateLimited("too many requests")


async def get_principal(request: Request, session: Session, ctx: Ctx) -> Principal:
    try:
        return await authenticate_user(request, session)
    except Unauthorized:
        await rate_limit(
            request, f"authfail:{client_ip(request)}", ctx.settings.auth_failure_limit_per_minute
        )
        raise


async def get_ci(request: Request, session: Session, ctx: Ctx) -> CIPrincipal:
    try:
        return await authenticate_ci(request, session)
    except Unauthorized:
        await rate_limit(
            request, f"authfail:{client_ip(request)}", ctx.settings.auth_failure_limit_per_minute
        )
        raise


CurrentUser = Annotated[Principal, Depends(get_principal)]
CurrentCI = Annotated[CIPrincipal, Depends(get_ci)]


class Page:
    def __init__(
        self,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        order: Annotated[str, Query(pattern="^(asc|desc)$")] = "desc",
    ) -> None:
        self.limit = limit
        self.offset = offset
        self.order = order

    def wrap(self, items: list[Any]) -> dict[str, Any]:
        return {"items": items, "limit": self.limit, "offset": self.offset, "count": len(items)}


async def load_project(
    session: AsyncSession, principal: Principal, project_id: uuid.UUID, perm: Perm
) -> Project:
    project = await session.get(Project, project_id)
    # Not found and not visible are indistinguishable (no cross-tenant enumeration).
    if project is None or not principal.can(Perm.READ, project.organization_id, project.id):
        raise NotFound("project not found")
    principal.require(perm, project.organization_id, project.id)
    return project


async def load_environment(session: AsyncSession, project: Project, name_or_id: str) -> Environment:
    try:
        env_id = uuid.UUID(name_or_id)
        cond = Environment.id == env_id
    except ValueError:
        cond = Environment.name == name_or_id
    env = await session.scalar(select(Environment).where(Environment.project_id == project.id, cond))
    if env is None:
        raise NotFound("environment not found")
    return env


async def read_limited_body(request: Request, max_bytes: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > max_bytes:
                raise APIError("payload too large", status_code=413, code="payload_too_large")
        except ValueError as exc:
            raise APIError("invalid Content-Length", code="invalid_headers") from exc
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            raise APIError("payload too large", status_code=413, code="payload_too_large")
        chunks.append(chunk)
    return b"".join(chunks)
