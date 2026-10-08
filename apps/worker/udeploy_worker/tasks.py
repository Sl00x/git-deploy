"""Celery tasks. Every task is idempotent and replayable; business logic lives
in `udeploy_api.services` and runs in its own short database transaction."""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

from celery import Task
from sqlalchemy import delete, select

from udeploy_api.context import AppContext
from udeploy_api.models import DeadLetter, OutboxMessage, WebhookDelivery
from udeploy_api.services import outbox
from udeploy_api.services.deployments import reconcile, start_deployment
from udeploy_api.services.releases import verify_release
from udeploy_api.settings import get_settings

from .celery_app import app

log = logging.getLogger("udeploy.worker")
T = TypeVar("T")


def _run(fn: Callable[[AppContext], Awaitable[T]]) -> T:
    async def runner() -> T:
        ctx = AppContext.from_settings(get_settings(), null_pool=True)
        try:
            return await fn(ctx)
        finally:
            await ctx.db.dispose()

    return asyncio.run(runner())


class DLQTask(Task):  # type: ignore[misc]
    """After the final retry, the payload is parked in `dead_letters` for operators."""

    autoretry_for = (Exception,)
    retry_backoff = True
    retry_backoff_max = 300
    retry_jitter = True
    max_retries = 5

    def on_failure(self, exc: BaseException, task_id: str, args: Any, kwargs: Any, einfo: Any) -> None:
        async def park(ctx: AppContext) -> None:
            async with ctx.db.session() as s:
                s.add(
                    DeadLetter(
                        task_name=self.name,
                        payload={"args": list(args), "kwargs": kwargs},
                        error=f"{type(exc).__name__}: {str(exc)[:2000]}",
                    )
                )
                await s.commit()

        try:
            _run(park)
        except Exception:
            log.exception("could not write dead letter")


TOPIC_TASKS = {
    outbox.TOPIC_VERIFY_RELEASE: "udeploy.verify_release",
    outbox.TOPIC_START_DEPLOYMENT: "udeploy.start_deployment",
}


async def relay(ctx: AppContext, send: Callable[[str, dict[str, Any]], None]) -> int:
    sent = 0
    async with ctx.db.session() as s:
        rows = (
            await s.scalars(
                select(OutboxMessage)
                .where(OutboxMessage.dispatched_at.is_(None), OutboxMessage.not_before <= datetime.now(UTC))
                .order_by(OutboxMessage.id)
                .limit(ctx.settings.outbox_batch_size)
                .with_for_update(skip_locked=True)
            )
        ).all()
        for msg in rows:
            task_name = TOPIC_TASKS.get(msg.topic)
            msg.attempts += 1
            if task_name is None:
                s.add(DeadLetter(task_name=f"outbox:{msg.topic}", payload=msg.payload, error="unknown topic"))
                msg.dispatched_at = datetime.now(UTC)
                continue
            send(task_name, msg.payload)
            msg.dispatched_at = datetime.now(UTC)
            sent += 1
        await s.commit()
    return sent


@app.task(name="udeploy.relay_outbox", ignore_result=True)
def relay_outbox() -> int:
    return _run(lambda ctx: relay(ctx, lambda name, payload: app.send_task(name, kwargs=payload)))


@app.task(name="udeploy.verify_release", base=DLQTask, ignore_result=True)
def verify_release_task(release_id: str) -> str:
    async def go(ctx: AppContext) -> str:
        async with ctx.db.session() as s:
            outcome = await verify_release(ctx, s, uuid.UUID(release_id))
            await s.commit()
            return outcome.status

    return _run(go)


@app.task(name="udeploy.start_deployment", base=DLQTask, ignore_result=True)
def start_deployment_task(deployment_id: str) -> str:
    async def go(ctx: AppContext) -> str:
        async with ctx.db.session() as s:
            result = await start_deployment(ctx, s, uuid.UUID(deployment_id))
            await s.commit()
            return result

    return _run(go)


@app.task(name="udeploy.reconcile", ignore_result=True)
def reconcile_task() -> dict[str, int]:
    async def go(ctx: AppContext) -> dict[str, int]:
        async with ctx.db.session() as s:
            stats = await reconcile(ctx, s)
            await s.commit()
            return stats

    return _run(go)


@app.task(name="udeploy.prune", ignore_result=True)
def prune_task() -> int:
    async def go(ctx: AppContext) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=ctx.settings.delivery_retention_days)
        async with ctx.db.session() as s:
            await s.execute(delete(OutboxMessage).where(OutboxMessage.dispatched_at < cutoff))
            res = await s.execute(
                delete(WebhookDelivery).where(
                    WebhookDelivery.received_at < cutoff, WebhookDelivery.status != "accepted"
                )
            )
            await s.commit()
            return int(getattr(res, "rowcount", 0) or 0)

    return _run(go)
