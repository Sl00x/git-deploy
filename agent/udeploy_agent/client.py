"""mTLS client for the control plane's agent API."""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any

import httpx

from udeploy_domain.plan import AgentTask, ClaimResponse, HostFacts, TaskEvent, TaskResult

from .config import AgentConfig

log = logging.getLogger("udeploy.agent.client")


def mtls_context(cfg: AgentConfig) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(cfg.ca_path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cfg.cert_path), str(cfg.key_path))
    return ctx


class ControlPlane:
    def __init__(
        self, cfg: AgentConfig, base_url: str, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.cfg = cfg
        self.base_url = base_url.rstrip("/")
        self._transport = transport
        self._client = self._make_client()

    def _make_client(self) -> httpx.AsyncClient:
        if self._transport is not None:
            return httpx.AsyncClient(base_url=self.base_url, transport=self._transport, timeout=60)
        return httpx.AsyncClient(base_url=self.base_url, verify=mtls_context(self.cfg), timeout=60)

    async def reload_identity(self) -> None:
        await self._client.aclose()
        self._client = self._make_client()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _post(self, path: str, body: Any, *, retries: int = 5, timeout: float = 60) -> dict[str, Any]:
        delay = 1.0
        for attempt in range(retries):
            try:
                resp = await self._client.post(path, json=body, timeout=timeout)
            except httpx.TransportError as exc:
                if attempt == retries - 1:
                    raise
                log.warning("control plane unreachable (%s); retrying", type(exc).__name__)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)
                continue
            if resp.status_code >= 500 and attempt < retries - 1:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)
                continue
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data
        raise RuntimeError("unreachable")

    async def heartbeat(self, facts: HostFacts) -> dict[str, Any]:
        return await self._post("/v1/agent/heartbeat", facts.model_dump(mode="json"), retries=1)

    async def claim(self, wait: float) -> AgentTask | None:
        resp = await self._client.post("/v1/agent/tasks/claim", params={"wait": wait}, timeout=wait + 30)
        resp.raise_for_status()
        return ClaimResponse.model_validate(resp.json()).task

    async def event(self, task_id: str, event: TaskEvent) -> dict[str, Any]:
        try:
            return await self._post(f"/v1/agent/tasks/{task_id}/events", event.model_dump(mode="json"))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 409:
                log.warning("control plane refused state report: %s", exc.response.text[:300])
                return {}
            raise

    async def complete(self, task_id: str, result: TaskResult) -> dict[str, Any]:
        return await self._post(
            f"/v1/agent/tasks/{task_id}/complete", result.model_dump(mode="json"), retries=20
        )

    async def renew(self, csr_pem: str) -> str:
        data = await self._post("/v1/agent/renew", {"csr_pem": csr_pem}, retries=3)
        return str(data["certificate_pem"])
