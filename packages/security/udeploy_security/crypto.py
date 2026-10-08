"""Envelope-less authenticated encryption for secrets stored by the control plane.

AES-256-GCM with a key ring (`kid -> key`) so keys can be rotated: new writes use
the active key, old ciphertexts stay readable until re-encrypted
(`udeploy-admin rotate-master-key`). The associated data binds a ciphertext to
its owner (org/project/environment/path): a ciphertext copied into another
project's row fails authentication instead of decrypting.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(Exception):
    pass


@dataclass(frozen=True)
class KeyRing:
    active_kid: str
    keys: dict[str, bytes]

    @classmethod
    def parse(cls, spec: str) -> KeyRing:
        """`kid1:base64key,kid2:base64key` - the first entry is the active key."""
        keys: dict[str, bytes] = {}
        order: list[str] = []
        for item in spec.split(","):
            item = item.strip()
            if not item:
                continue
            kid, _, b64 = item.partition(":")
            key = base64.b64decode(b64, validate=True)
            if len(key) != 32 or not kid.isalnum():
                raise ValueError("each master key must be `<alnum kid>:<base64 32 bytes>`")
            keys[kid] = key
            order.append(kid)
        if not order:
            raise ValueError("empty key ring")
        return cls(active_kid=order[0], keys=keys)

    @staticmethod
    def generate_entry(kid: str | None = None) -> str:
        return f"{kid or 'k' + secrets.token_hex(4)}:{base64.b64encode(os.urandom(32)).decode()}"


class SecretBox:
    def __init__(self, ring: KeyRing) -> None:
        self._ring = ring

    def encrypt(self, plaintext: bytes, aad: str) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self._ring.keys[self._ring.active_kid]).encrypt(nonce, plaintext, aad.encode())
        return f"{self._ring.active_kid}.{base64.b64encode(nonce + ct).decode()}"

    def decrypt(self, token: str, aad: str) -> bytes:
        kid, _, b64 = token.partition(".")
        key = self._ring.keys.get(kid)
        if key is None:
            raise DecryptionError(f"unknown key id {kid!r}")
        raw = base64.b64decode(b64)
        try:
            return AESGCM(key).decrypt(raw[:12], raw[12:], aad.encode())
        except InvalidTag as exc:
            raise DecryptionError("ciphertext failed authentication") from exc

    def needs_rotation(self, token: str) -> bool:
        return token.partition(".")[0] != self._ring.active_kid
