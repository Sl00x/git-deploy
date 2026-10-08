from __future__ import annotations

import json
import uuid
from contextvars import ContextVar
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from udeploy_security.masking import mask

from .models import AuditEvent

correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)

_SENSITIVE_KEYS = {"password", "secret", "token", "value", "private_key", "authorization"}


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("***" if any(s in k.lower() for s in _SENSITIVE_KEYS) else _scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, str):
        return mask(value)
    return value


def record(
    session: AsyncSession,
    action: str,
    *,
    actor_type: str,
    actor_id: str | uuid.UUID | None,
    organization_id: uuid.UUID | None,
    target_type: str | None = None,
    target_id: str | uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Add an audit event to the current transaction (committed atomically with the change)."""
    scrubbed = _scrub(details or {})
    json.dumps(scrubbed, default=str)  # fail fast on non-serialisable details
    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_type=actor_type,
            actor_id=str(actor_id) if actor_id else None,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            details=json.loads(json.dumps(scrubbed, default=str)),
            correlation_id=correlation_id_var.get(),
        )
    )
