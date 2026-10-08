"""Opaque bearer tokens: random, prefixed, stored only as SHA-256 hashes."""

from __future__ import annotations

import hashlib
import hmac
import secrets

PREFIXES = {"user": "udp_", "ci": "udci_", "enroll": "udenr_", "webhook": "udwh_"}


def generate(kind: str) -> str:
    return PREFIXES[kind] + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    # Tokens carry 256 bits of entropy: a plain hash is sufficient (no KDF needed).
    return hashlib.sha256(token.encode()).hexdigest()


def token_matches(token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), stored_hash)


def display_prefix(token: str) -> str:
    return token[:10]
