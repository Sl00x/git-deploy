from __future__ import annotations

import time

import pytest

from udeploy_security import pki
from udeploy_security.crypto import DecryptionError, KeyRing, SecretBox
from udeploy_security.masking import mask
from udeploy_security.tokens import generate, hash_token, token_matches
from udeploy_security.webhooks import (
    WebhookAuthError,
    github_signature,
    standard_webhook_signature,
    verify_github,
    verify_gitlab_token,
    verify_standard_webhook,
)


class TestWebhookSignatures:
    def test_github_valid(self) -> None:
        body = b'{"a":1}'
        verify_github(b"s3cret", body, github_signature(b"s3cret", body))

    @pytest.mark.parametrize("header", [None, "", "sha1=abc", "sha256=" + "0" * 64])
    def test_github_invalid(self, header: str | None) -> None:
        with pytest.raises(WebhookAuthError):
            verify_github(b"s3cret", b"{}", header)

    def test_github_signature_covers_raw_bytes(self) -> None:
        sig = github_signature(b"k", b'{"a": 1}')
        with pytest.raises(WebhookAuthError):
            verify_github(b"k", b'{"a":1}', sig)  # same JSON, different bytes

    def test_gitlab_token(self) -> None:
        verify_gitlab_token(b"tok", "tok")
        with pytest.raises(WebhookAuthError):
            verify_gitlab_token(b"tok", "nope")
        with pytest.raises(WebhookAuthError):
            verify_gitlab_token(b"tok", None)

    def test_standard_webhook_signature_and_replay_window(self) -> None:
        now = int(time.time())
        sig = standard_webhook_signature(b"k", "msg_1", str(now), b"{}")
        verify_standard_webhook(b"k", b"{}", "msg_1", str(now), f"v1,bogus {sig}")
        with pytest.raises(WebhookAuthError, match="replay"):
            verify_standard_webhook(b"k", b"{}", "msg_1", str(now - 3600), sig, now=now)
        with pytest.raises(WebhookAuthError):
            verify_standard_webhook(b"k", b"{ }", "msg_1", str(now), sig)


class TestSecretBox:
    def test_roundtrip_and_aad_binding(self) -> None:
        box = SecretBox(KeyRing.parse(KeyRing.generate_entry("k1")))
        ct = box.encrypt(b"pg://user:pw@db/x", "project-a")
        assert box.decrypt(ct, "project-a") == b"pg://user:pw@db/x"
        with pytest.raises(DecryptionError):
            box.decrypt(ct, "project-b")  # ciphertext moved to another project's row

    def test_rotation(self) -> None:
        old = KeyRing.generate_entry("old")
        new = KeyRing.generate_entry("new")
        ct = SecretBox(KeyRing.parse(old)).encrypt(b"v", "aad")
        box = SecretBox(KeyRing.parse(f"{new},{old}"))
        assert box.decrypt(ct, "aad") == b"v"
        assert box.needs_rotation(ct)
        assert not box.needs_rotation(box.encrypt(b"v", "aad"))

    def test_bad_key_spec(self) -> None:
        with pytest.raises(ValueError):
            KeyRing.parse("k1:dG9vc2hvcnQ=")


class TestPKI:
    def test_agent_csr_signing(self) -> None:
        ca_key, ca_cert = pki.create_ca()
        key = pki.new_private_key_pem()
        cert_pem = pki.sign_agent_csr(ca_key, ca_cert, pki.make_csr(key, "attacker-chosen-cn"), "host-123")
        cert = pki.load_cert(cert_pem)
        assert pki.host_id_from_cert(cert) == "host-123"
        assert "attacker-chosen-cn" not in cert.subject.rfc4514_string()

    def test_invalid_csr(self) -> None:
        ca_key, ca_cert = pki.create_ca()
        with pytest.raises(pki.PKIError):
            pki.sign_agent_csr(ca_key, ca_cert, b"garbage", "h")


def test_tokens() -> None:
    t = generate("ci")
    assert t.startswith("udci_") and token_matches(t, hash_token(t))
    assert not token_matches(t + "x", hash_token(t))


def test_masking() -> None:
    text = (
        "connecting to pg://u:hunter2@db with Authorization: Bearer abc.def and password=xyz udp_" + "a" * 30
    )
    out = mask(text, ["hunter2"])
    for leaked in ("hunter2", "abc.def", "xyz", "a" * 30):
        assert leaked not in out
