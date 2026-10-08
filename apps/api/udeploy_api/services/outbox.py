"""Transactional outbox: work is recorded in the same transaction as the state
change that requires it; a relay (Celery beat) forwards it to the queue."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import OutboxMessage

TOPIC_VERIFY_RELEASE = "release.verify"
TOPIC_START_DEPLOYMENT = "deployment.start"


def enqueue(session: AsyncSession, topic: str, payload: dict[str, Any], *, delay_seconds: float = 0) -> None:
    session.add(
        OutboxMessage(
            topic=topic,
            payload=payload,
            not_before=datetime.now(UTC) + timedelta(seconds=delay_seconds),
        )
    )
