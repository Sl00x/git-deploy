"""The real uvicorn mTLS listener: TLS handshake + certificate-to-host mapping."""

from __future__ import annotations

import asyncio
import socket
import ssl
from pathlib import Path

import httpx
import pytest
import uvicorn

from udeploy_api.main import create_agent_app
from udeploy_api.mtls import build_config
from udeploy_security import pki

from ..conftest import World, enroll_host

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def test_mtls_listener(world: World, tmp_path: Path) -> None:
    settings = world.ctx.settings
    app = create_agent_app(world.ctx)
    port = _free_port()
    config = build_config(
        app,
        host="127.0.0.1",
        port=port,
        cert=str(settings.pki_dir / "agent-api.crt"),
        key=str(settings.pki_dir / "agent-api.key"),
        ca=str(settings.ca_cert_path),
        log_level="warning",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.05)
    try:
        # enrolled agent: generate key locally, CSR, signed cert
        r = await world.api.post(
            "/v1/hosts/enroll-token",
            json={"organization_id": world.org_id, "host_name": "h1", "pool": "p"},
            headers={"Authorization": world.owner["Authorization"]},
        )
        key = pki.new_private_key_pem()
        enrolled = await world.api.post(
            "/v1/agent/enroll", json={"token": r.json()["token"], "csr_pem": pki.make_csr(key, "h1").decode()}
        )
        (tmp_path / "a.key").write_bytes(key)
        (tmp_path / "a.crt").write_text(enrolled.json()["certificate_pem"])
        ctx_ok = ssl.create_default_context(cafile=str(settings.ca_cert_path))
        ctx_ok.load_cert_chain(str(tmp_path / "a.crt"), str(tmp_path / "a.key"))
        url = f"https://127.0.0.1:{port}"
        async with httpx.AsyncClient(verify=ctx_ok) as client:
            resp = await client.post(f"{url}/v1/agent/heartbeat", json={"agent_version": "t"})
            assert resp.status_code == 200, resp.text
            assert resp.json()["host_id"] == enrolled.json()["host_id"]

        # no client certificate: the TLS handshake itself fails
        ctx_anon = ssl.create_default_context(cafile=str(settings.ca_cert_path))
        async with httpx.AsyncClient(verify=ctx_anon) as client:
            with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
                await client.post(f"{url}/v1/agent/heartbeat", json={"agent_version": "t"})

        # certificate from another CA: rejected at handshake
        rogue_key, rogue_ca = pki.create_ca("rogue")
        k2 = pki.new_private_key_pem()
        (tmp_path / "r.key").write_bytes(k2)
        (tmp_path / "r.crt").write_bytes(pki.sign_agent_csr(rogue_key, rogue_ca, pki.make_csr(k2, "x"), "x"))
        ctx_rogue = ssl.create_default_context(cafile=str(settings.ca_cert_path))
        ctx_rogue.load_cert_chain(str(tmp_path / "r.crt"), str(tmp_path / "r.key"))
        async with httpx.AsyncClient(verify=ctx_rogue) as client:
            with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
                await client.post(f"{url}/v1/agent/heartbeat", json={"agent_version": "t"})

        # a header can never impersonate a certificate
        async with httpx.AsyncClient(verify=ctx_ok) as client:
            other_host, _ = await enroll_host(world, name="h2", pool="p")
            resp = await client.post(
                f"{url}/v1/agent/heartbeat",
                json={"agent_version": "t"},
                headers={"X-Forwarded-Tls-Client-Cert": "forged", "X-Host-Id": other_host},
            )
            assert resp.json()["host_id"] == enrolled.json()["host_id"]
    finally:
        server.should_exit = True
        await task
