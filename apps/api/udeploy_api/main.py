"""ASGI applications.

* `create_app()`       public/admin API + webhooks (behind the edge proxy).
* `create_agent_app()` agent protocol, served only through the mTLS listener
                       (`python -m udeploy_api.mtls`).
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .audit import correlation_id_var
from .context import AppContext
from .errors import install_error_handlers
from .logging_setup import configure_logging
from .routers import agent, ingest, operations, projects
from .settings import Settings, get_settings

log = logging.getLogger("udeploy.api")
_CORRELATION = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
API_VERSION = "1.0.0"


def _lifespan(ctx: AppContext | None, settings: Settings) -> Callable[[FastAPI], Any]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        context = ctx or AppContext.from_settings(settings)
        app.state.ctx = context
        app.state.redis = None
        if context.redis_url:
            import redis.asyncio as aioredis

            app.state.redis = aioredis.from_url(context.redis_url, socket_timeout=2)
        try:
            yield
        finally:
            if app.state.redis is not None:
                await app.state.redis.aclose()
            if ctx is None:
                await context.db.dispose()

    return lifespan


def _install_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def correlation_and_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-request-id", "")
        cid = incoming if _CORRELATION.match(incoming) else uuid.uuid4().hex
        request.state.correlation_id = cid
        token = correlation_id_var.set(cid)
        try:
            response = await call_next(request)
        finally:
            correlation_id_var.reset(token)
        response.headers["X-Request-ID"] = cid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


async def _ready(request: Request) -> JSONResponse:
    ctx: AppContext = request.app.state.ctx
    checks: dict[str, str] = {}
    try:
        async with ctx.db.session() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {type(exc).__name__}"
    redis = getattr(request.app.state, "redis", None)
    if redis is not None:
        try:
            await redis.ping()
            checks["redis"] = "ok"
        except Exception as exc:
            checks["redis"] = f"error: {type(exc).__name__}"
    ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        {"status": "ready" if ok else "not_ready", "checks": checks}, status_code=200 if ok else 503
    )


def create_app(ctx: AppContext | None = None, settings: Settings | None = None) -> FastAPI:
    settings = settings or (ctx.settings if ctx else get_settings())
    configure_logging(settings)
    app = FastAPI(
        title="udeploy control plane",
        version=API_VERSION,
        description="Self-hosted CI/CD deployment engine for Docker Engine + Compose V2.",
        lifespan=_lifespan(ctx, settings),
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    install_error_handlers(app)
    _install_middleware(app)
    app.include_router(ingest.router)
    app.include_router(projects.router)
    app.include_router(operations.router)
    app.include_router(agent.public_router)

    @app.get("/health/live", tags=["health"])
    async def live() -> dict[str, str]:
        return {"status": "alive"}

    app.add_api_route("/health/ready", _ready, methods=["GET"], tags=["health"])
    return app


def create_agent_app(ctx: AppContext | None = None, settings: Settings | None = None) -> FastAPI:
    settings = settings or (ctx.settings if ctx else get_settings())
    configure_logging(settings)
    app = FastAPI(
        title="udeploy agent API",
        version=API_VERSION,
        lifespan=_lifespan(ctx, settings),
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    install_error_handlers(app)
    _install_middleware(app)
    app.include_router(agent.mtls_router)

    @app.get("/health/live", tags=["health"])
    async def live() -> dict[str, str]:
        return {"status": "alive"}

    return app
