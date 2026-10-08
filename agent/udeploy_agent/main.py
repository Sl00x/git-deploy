"""`udeploy-agent enroll | run`."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import platform
import signal
from datetime import UTC, datetime, timedelta

import httpx

from udeploy_domain.plan import AgentTask, HostFacts, TaskEvent, TaskResult
from udeploy_domain.states import DeploymentState
from udeploy_security import pki

from .client import ControlPlane
from .config import AgentConfig
from .docker import DockerCLI
from .executor import Executor, _write_atomic

log = logging.getLogger("udeploy.agent")
AGENT_VERSION = "0.1.0"


def enroll(cfg: AgentConfig, url: str, token: str, ca_bundle: str | None) -> dict[str, str]:
    """Generate the key locally, send only a CSR, store the signed certificate."""
    cfg.identity_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not cfg.key_path.exists():
        _write_atomic(cfg.key_path, pki.new_private_key_pem(), 0o600)
    csr = pki.make_csr(cfg.key_path.read_bytes(), "udeploy-agent")
    verify: str | bool = ca_bundle if ca_bundle else True
    resp = httpx.post(
        f"{url.rstrip('/')}/v1/agent/enroll",
        json={"token": token, "csr_pem": csr.decode()},
        verify=verify,
        timeout=30,
    )
    if resp.status_code != 201:
        raise SystemExit(f"enrolment failed: HTTP {resp.status_code} {resp.text[:300]}")
    data = resp.json()
    _write_atomic(cfg.cert_path, data["certificate_pem"].encode(), 0o644)
    _write_atomic(cfg.ca_path, data["ca_pem"].encode(), 0o644)
    identity = {"host_id": data["host_id"], "agent_api_url": data["agent_api_url"]}
    _write_atomic(cfg.identity_file, json.dumps(identity).encode(), 0o600)
    return identity


class Agent:
    def __init__(
        self, cfg: AgentConfig, control_plane: ControlPlane, docker: DockerCLI, host_id: str
    ) -> None:
        self.cfg = cfg
        self.cp = control_plane
        self.docker = docker
        self.host_id = host_id
        self.executor = Executor(cfg, docker, host_id)
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def facts(self) -> HostFacts:
        return HostFacts(
            agent_version=AGENT_VERSION,
            docker_version=await self.docker.version(),
            compose_version=await self.docker.compose_version(),
            architecture=platform.machine(),
            cpus=os.cpu_count(),
        )

    async def heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.cp.heartbeat(await self.facts())
                await self.maybe_renew()
            except Exception as exc:
                log.warning("heartbeat failed: %s", type(exc).__name__)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.cfg.heartbeat_seconds)
            except TimeoutError:
                pass

    async def maybe_renew(self) -> None:
        cert = pki.load_cert(self.cfg.cert_path.read_bytes())
        if pki.not_after(cert) - datetime.now(UTC) > timedelta(days=30):
            return
        new_key = pki.new_private_key_pem()
        cert_pem = await self.cp.renew(pki.make_csr(new_key, "udeploy-agent").decode())
        _write_atomic(self.cfg.key_path, new_key, 0o600)
        _write_atomic(self.cfg.cert_path, cert_pem.encode(), 0o644)
        await self.cp.reload_identity()
        log.info("agent certificate renewed")

    async def execute(self, task: AgentTask) -> TaskResult:
        async def report(state: DeploymentState, message: str, output: str) -> bool:
            resp = await self.cp.event(
                task.task_id, TaskEvent(state=state, message=message[:4000], log=output[-64000:])
            )
            return bool(resp.get("cancel_requested"))

        log.info(
            "executing task %s (deployment %s, attempt %d)",
            task.task_id,
            task.plan.deployment_id,
            task.attempt,
        )
        result = await self.executor.run(task, report)
        await self.cp.complete(task.task_id, result)
        log.info("task %s finished: %s", task.task_id, result.outcome)
        return result

    async def run_once(self, wait: float = 20) -> TaskResult | None:
        task = await self.cp.claim(wait)
        if task is None:
            return None
        return await self.execute(task)

    async def run(self) -> None:
        if not await self.docker.image_present(self.cfg.probe_image):
            await self.docker.pull(
                self.cfg.probe_image, "linux/" + ("arm64" if platform.machine() == "aarch64" else "amd64")
            )
        hb = asyncio.create_task(self.heartbeat_loop())
        backoff = 1.0
        try:
            while not self._stop.is_set():
                try:
                    await self.run_once()
                    backoff = 1.0
                except Exception as exc:
                    log.warning("agent loop error: %s: %s", type(exc).__name__, str(exc)[:300])
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 60)
        finally:
            self._stop.set()
            await hb


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        level=os.environ.get("UDEPLOY_AGENT_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = argparse.ArgumentParser(prog="udeploy-agent")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("enroll")
    p.add_argument("--url", required=True, help="public control plane URL")
    p.add_argument("--token", default=os.environ.get("UDEPLOY_ENROLL_TOKEN"))
    p.add_argument("--ca-bundle", help="CA bundle for the public URL (default: system trust store)")
    sub.add_parser("run")
    args = parser.parse_args(argv)
    cfg = AgentConfig.from_env()
    if args.cmd == "enroll":
        if not args.token:
            raise SystemExit("--token (or UDEPLOY_ENROLL_TOKEN) is required")
        identity = enroll(cfg, args.url, args.token, args.ca_bundle)
        print(f"enrolled as host {identity['host_id']}")
        return
    if not cfg.allowed_registries:
        raise SystemExit("UDEPLOY_AGENT_ALLOWED_REGISTRIES must list the registries this host may pull from")
    identity = cfg.load_identity()
    url = os.environ.get("UDEPLOY_AGENT_API_URL", identity["agent_api_url"])
    agent = Agent(cfg, ControlPlane(cfg, url), DockerCLI(cfg.docker_bin), identity["host_id"])

    async def runner() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, agent.stop)
        await agent.run()

    asyncio.run(runner())


if __name__ == "__main__":
    main()
