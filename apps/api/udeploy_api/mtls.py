"""mTLS listener for the agent API.

Uvicorn verifies the client certificate against the internal CA
(`CERT_REQUIRED`) but does not expose it to the application. This protocol
subclass copies the verified peer certificate (DER) into the per-connection
ASGI `state`, where `request.state.tls_peer_cert_der` reads it. Nothing a
client sends (headers, body) can influence that value.

Run: `python -m udeploy_api.mtls` (see infra/control-plane.compose.yml).
"""

from __future__ import annotations

import asyncio
import os
import ssl
from typing import Any

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from .main import create_agent_app
from .settings import get_settings


class MTLSH11Protocol(H11Protocol):
    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        # Per-connection copy: never shared between connections.
        self.app_state = {**self.app_state, "tls_peer_cert_der": der}


def build_config(
    app: Any, *, host: str, port: int, cert: str, key: str, ca: str, log_level: str = "info"
) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=host,
        port=port,
        http=MTLSH11Protocol,
        ws="none",
        ssl_certfile=cert,
        ssl_keyfile=key,
        ssl_ca_certs=ca,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        log_level=log_level,
        proxy_headers=False,
        server_header=False,
        timeout_keep_alive=65,
    )


def main() -> None:
    settings = get_settings()
    pki_dir = settings.pki_dir
    config = build_config(
        create_agent_app(settings=settings),
        host=os.environ.get("UDEPLOY_AGENT_API_HOST", "0.0.0.0"),  # noqa: S104 - mTLS-only listener
        port=int(os.environ.get("UDEPLOY_AGENT_API_PORT", "8443")),
        cert=str(pki_dir / "agent-api.crt"),
        key=str(pki_dir / "agent-api.key"),
        ca=str(settings.ca_cert_path),
        log_level=settings.log_level.lower(),
    )
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
