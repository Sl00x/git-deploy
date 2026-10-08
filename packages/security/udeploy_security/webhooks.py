"""Webhook authenticity checks. All of them operate on the *raw* body bytes and
must be called before any JSON parsing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time


class WebhookAuthError(Exception):
    pass


def github_signature(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_github(secret: bytes, body: bytes, header: str | None) -> None:
    """GitHub `X-Hub-Signature-256: sha256=<hex hmac>` (constant-time)."""
    if not header or not header.startswith("sha256="):
        raise WebhookAuthError("missing or malformed X-Hub-Signature-256")
    expected = github_signature(secret, body)
    if not hmac.compare_digest(expected.encode(), header.strip().encode()):
        raise WebhookAuthError("signature mismatch")


def verify_gitlab_token(expected_token: bytes, header: str | None) -> None:
    """GitLab `X-Gitlab-Token`.

    This is a shared secret sent in clear (inside TLS); it authenticates the
    sender but does NOT protect the body's integrity. It is therefore only
    accepted together with TLS and, when configured, a signing token.
    """
    if not header:
        raise WebhookAuthError("missing X-Gitlab-Token")
    if not hmac.compare_digest(expected_token, header.encode()):
        raise WebhookAuthError("token mismatch")


def standard_webhook_signature(secret: bytes, msg_id: str, timestamp: str, body: bytes) -> str:
    payload = f"{msg_id}.{timestamp}.".encode() + body
    return "v1," + base64.b64encode(hmac.new(secret, payload, hashlib.sha256).digest()).decode()


def verify_standard_webhook(
    secret: bytes,
    body: bytes,
    msg_id: str | None,
    timestamp: str | None,
    signature_header: str | None,
    *,
    tolerance_seconds: int = 300,
    now: float | None = None,
) -> None:
    """Standard Webhooks signature (used by GitLab "signing tokens").

    `webhook-signature` may contain several space separated `v1,<b64>` values
    (key rotation). The timestamp bounds replay to `tolerance_seconds`.
    """
    if not (msg_id and timestamp and signature_header):
        raise WebhookAuthError("missing webhook-id / webhook-timestamp / webhook-signature")
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise WebhookAuthError("invalid webhook-timestamp") from exc
    current = time.time() if now is None else now
    if abs(current - ts) > tolerance_seconds:
        raise WebhookAuthError("webhook timestamp outside tolerance (possible replay)")
    expected = standard_webhook_signature(secret, msg_id, timestamp, body).encode()
    for candidate in signature_header.split():
        if hmac.compare_digest(expected, candidate.encode()):
            return
    raise WebhookAuthError("signature mismatch")
