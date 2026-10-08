"""Executes one DeploymentPlan with the `recreate` strategy.

Order of operations guarantees that the running release is untouched until
every new image is pulled and verified by digest. After `compose up`, any
failure (health, routing, cancellation) restores the previous release's
compose file, secrets and routes. Volumes are external and never removed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from udeploy_compose.renderer import (
    HostLayout,
    backend_network,
    dump_yaml,
    edge_network,
    labels_for,
    render_compose,
    render_traefik_routes,
    secret_host_path,
    volume_name,
)
from udeploy_domain.plan import AgentTask, DeploymentPlan, ServicePlan, TaskResult
from udeploy_domain.states import DeploymentState as S
from udeploy_planner.policy import AgentPolicy, PlanRejected, check_plan_for_agent
from udeploy_security.masking import mask

from .config import AgentConfig
from .docker import ContainerInfo, DockerCLI, DockerError

log = logging.getLogger("udeploy.agent.executor")

Reporter = Callable[[S, str, str], Awaitable[bool]]  # returns cancel_requested


class Cancelled(Exception):
    pass


class StepFailed(Exception):
    def __init__(self, message: str, output: str = "") -> None:
        super().__init__(message)
        self.output = output


def _write_atomic(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


class Executor:
    def __init__(self, cfg: AgentConfig, docker: DockerCLI, host_id: str) -> None:
        self.cfg = cfg
        self.docker = docker
        self.policy = AgentPolicy(
            host_id=host_id,
            allowed_registries=frozenset(cfg.allowed_registries),
            max_memory_bytes=cfg.max_memory_bytes,
        )
        self.layout = HostLayout(secrets_dir=str(cfg.secrets_dir), cert_resolver=cfg.cert_resolver)

    # ------------------------------------------------------------ paths
    def project_dir(self, plan: DeploymentPlan) -> Path:
        return self.cfg.projects_dir / plan.compose_project

    def release_dir(self, plan: DeploymentPlan, deployment_id: str | None = None) -> Path:
        return self.project_dir(plan) / "releases" / (deployment_id or plan.deployment_id)

    def routes_file(self, plan: DeploymentPlan) -> Path:
        return self.cfg.traefik_dynamic_dir / f"udeploy-{plan.compose_project}.yml"

    # ------------------------------------------------------------ main entry
    async def run(self, task: AgentTask, report: Reporter) -> TaskResult:
        plan = task.plan
        secret_values = [v.get_secret_value() for v in task.secrets.values()]

        async def step(state: S, message: str = "", output: str = "") -> None:
            cancel = await report(state, message, mask(output, secret_values))
            if cancel:
                raise Cancelled("cancellation requested")

        # 0. Local re-validation (defense in depth): reject before touching anything.
        if plan.sha256() != task.plan_sha256:
            return TaskResult(outcome="failed", error="plan checksum mismatch")
        try:
            check_plan_for_agent(plan, self.policy)
        except PlanRejected as exc:
            return TaskResult(outcome="failed", error=f"plan rejected by host policy: {exc}")

        started = False
        try:
            await step(S.PREPARING, f"preparing {plan.compose_project}")
            compose_file = await self._prepare(task)

            await step(S.PULLING, "pulling images by digest")
            pulled = await self._pull(plan)

            await step(S.VERIFYING, "verifying local digests", pulled)
            await self._verify(plan)

            await step(S.STARTING, "starting containers (recreate)")
            started = True
            out = await self.docker.compose_up(plan.compose_project, str(compose_file))

            await step(S.HEALTHCHECKING, "waiting for readiness", out)
            containers = await self._wait_healthy(plan, compose_file)

            await step(S.SWITCHING, "publishing routes")
            await self._switch_routes(plan, containers)

            self._mark_current(plan)
            self._gc(plan)
            await report(S.SWITCHING, "release is live", "")
            return TaskResult(outcome="succeeded", running_digests={s.name: s.digest for s in plan.services})
        except (StepFailed, DockerError, Cancelled, OSError) as exc:
            output = getattr(exc, "output", "")
            reason = f"{type(exc).__name__}: {exc}"
            log.warning("deployment %s failed: %s", plan.deployment_id, reason)
            if not started:
                # Nothing changed at runtime: the previous release still serves traffic.
                detail = mask(f"{reason}\n{output}".strip(), secret_values)
                return TaskResult(outcome="failed", error=detail[:4000])
            return await self._rollback(plan, reason, mask(output, secret_values), report)

    # ------------------------------------------------------------ steps
    async def _prepare(self, task: AgentTask) -> Path:
        plan = task.plan
        rel = self.release_dir(plan)
        rel.mkdir(parents=True, exist_ok=True, mode=0o700)
        (rel / "plan.json").write_text(plan.model_dump_json(indent=2))
        for svc in plan.services:
            for secret in svc.secrets:
                value = task.secrets.get(secret.ref)
                if value is None:
                    raise StepFailed(f"secret {secret.ref} missing from task envelope")
                path = Path(secret_host_path(self.layout, plan, svc.name, secret.file_name))
                mode, owner = 0o444, None
                if svc.user:
                    uid, _, gid = svc.user.partition(":")
                    owner = (int(uid), int(gid or uid))
                    mode = 0o400
                _write_atomic(path, value.get_secret_value().encode(), mode)
                if owner and os.geteuid() == 0:
                    os.chown(path, *owner)
            # Secret directories are 0700 on the host: only root and the bind mount can reach the files.
        for svc in plan.services:
            for vol in svc.volumes:
                await self.docker.volume_ensure(volume_name(plan.compose_project, vol.name), labels_for(plan))
        compose = render_compose(plan, self.layout)
        compose_file = rel / "compose.yml"
        _write_atomic(compose_file, dump_yaml(compose).encode(), 0o600)
        return compose_file

    async def _pull(self, plan: DeploymentPlan) -> str:
        outputs = []
        for svc in plan.services:
            if await self.docker.image_present(svc.image):
                outputs.append(f"{svc.name}: already present")
                continue
            last: DockerError | None = None
            for attempt in range(3):  # bounded retries; the running release is untouched meanwhile
                try:
                    outputs.append(await self.docker.pull(svc.image, svc.platform))
                    last = None
                    break
                except DockerError as exc:
                    last = exc
                    await asyncio.sleep(2 * (attempt + 1))
            if last is not None:
                raise StepFailed(f"pull failed for {svc.name}", last.output)
        return "\n".join(outputs)

    async def _verify(self, plan: DeploymentPlan) -> None:
        for svc in plan.services:
            digests = await self.docker.image_repo_digests(svc.image)
            if not any(d.endswith("@" + svc.digest) for d in digests):
                raise StepFailed(f"{svc.name}: local image does not carry digest {svc.digest}")

    async def _containers(self, plan: DeploymentPlan, compose_file: Path) -> dict[str, list[ContainerInfo]]:
        by_service: dict[str, list[ContainerInfo]] = {}
        for c in await self.docker.compose_ps(plan.compose_project, str(compose_file)):
            by_service.setdefault(c.service, []).append(c)
        return by_service

    async def _wait_healthy(self, plan: DeploymentPlan, compose_file: Path) -> dict[str, list[str]]:
        deadline_global = time.monotonic() + max(s.health_timeout_seconds for s in plan.services)
        ready: dict[str, list[str]] = {}
        for svc in plan.services:
            if svc.replicas == 0:
                ready[svc.name] = []
                continue
            deadline = min(deadline_global, time.monotonic() + svc.health_timeout_seconds)
            ready[svc.name] = await self._wait_service(plan, svc, compose_file, deadline)
        return ready

    async def _wait_service(
        self, plan: DeploymentPlan, svc: ServicePlan, compose_file: Path, deadline: float
    ) -> list[str]:
        hc = svc.healthcheck
        if hc and hc.start_period_seconds:
            await asyncio.sleep(min(hc.start_period_seconds, max(0.0, deadline - time.monotonic())))
        last_problem = "no container started"
        while time.monotonic() < deadline:
            containers = (await self._containers(plan, compose_file)).get(svc.name, [])
            running = [c for c in containers if c.state == "running"]
            if len(running) < svc.replicas:
                bad = [c for c in containers if c.state in ("exited", "dead")]
                last_problem = f"{len(running)}/{svc.replicas} running" + (
                    f" ({', '.join(c.name + ':' + c.state for c in bad)})" if bad else ""
                )
            elif any(c.health == "unhealthy" for c in running):
                last_problem = "container healthcheck reports unhealthy"
            elif any(c.health == "starting" for c in running):
                last_problem = "container healthcheck still starting"
            elif hc is None:
                # No HTTP probe declared: require containers to stay up for a short stability window.
                await asyncio.sleep(3)
                again = (await self._containers(plan, compose_file)).get(svc.name, [])
                if sum(1 for c in again if c.state == "running") >= svc.replicas:
                    return sorted(c.name for c in again if c.state == "running")
                last_problem = "containers did not stay running"
            else:
                failures = []
                for c in running:
                    ok, out = await self.docker.probe_http(
                        probe_image=self.cfg.probe_image,
                        network=backend_network(plan.compose_project),
                        container=c.name,
                        port=hc.port,
                        path=hc.path,
                        timeout=hc.timeout_seconds,
                    )
                    if not ok:
                        failures.append(f"{c.name}: {out or 'probe failed'}")
                if not failures:
                    return sorted(c.name for c in running)
                last_problem = "; ".join(failures)
            await asyncio.sleep(hc.interval_seconds if hc else 2)
        raise StepFailed(f"{svc.name} not ready before timeout: {last_problem}")

    async def _switch_routes(self, plan: DeploymentPlan, containers: dict[str, list[str]]) -> None:
        routes = render_traefik_routes(plan, containers, self.layout)
        target = self.routes_file(plan)
        if not routes:
            if target.exists():
                target.unlink()
            return
        if not await self.docker.container_running(self.cfg.traefik_container):
            raise StepFailed(f"reverse proxy container {self.cfg.traefik_container!r} is not running")
        await self.docker.network_connect(edge_network(plan.compose_project), self.cfg.traefik_container)
        # Atomic rename: Traefik never reads a half-written file.
        _write_atomic(target, dump_yaml(routes).encode(), 0o644)

    def _mark_current(self, plan: DeploymentPlan) -> None:
        _write_atomic(
            self.project_dir(plan) / "current.json",
            json.dumps({"deployment_id": plan.deployment_id, "release": plan.release.version}).encode(),
            0o600,
        )

    def _gc(self, plan: DeploymentPlan) -> None:
        """Keep the newest N release directories (and their secrets). Never touches volumes."""
        releases = self.project_dir(plan) / "releases"
        keep = {plan.deployment_id}
        if plan.previous:
            keep.add(plan.previous.deployment_id)
        dirs = sorted(
            (d for d in releases.iterdir() if d.is_dir()), key=lambda d: d.stat().st_mtime, reverse=True
        )
        for d in dirs[self.cfg.keep_releases :]:
            if d.name in keep:
                continue
            shutil.rmtree(d, ignore_errors=True)
            shutil.rmtree(Path(self.cfg.secrets_dir) / plan.compose_project / d.name, ignore_errors=True)

    # ------------------------------------------------------------ rollback
    async def _rollback(self, plan: DeploymentPlan, reason: str, output: str, report: Reporter) -> TaskResult:
        try:
            await report(S.ROLLBACK_PENDING, f"rolling back: {reason}", output)
        except Exception:
            log.exception("could not report rollback_pending")
        new_compose = self.release_dir(plan) / "compose.yml"
        previous = plan.previous
        prev_compose = self.release_dir(plan, previous.deployment_id) / "compose.yml" if previous else None
        try:
            if prev_compose is None or not prev_compose.exists():
                # First release on this host: nothing to restore; stop the failed containers.
                await self.docker.compose_stop(plan.compose_project, str(new_compose))
                return TaskResult(
                    outcome="failed", error=f"{reason}; no previous release, new containers stopped"
                )
            await self.docker.compose_up(plan.compose_project, str(prev_compose))
            prev_plan = DeploymentPlan.model_validate_json((prev_compose.parent / "plan.json").read_text())
            containers = await self._wait_healthy(prev_plan, prev_compose)
            await self._switch_routes(prev_plan, containers)
            self._mark_current(prev_plan)
            return TaskResult(
                outcome="rolled_back",
                running_digests={s.name: s.digest for s in prev_plan.services},
                error=f"{reason}; restored {previous.release_version if previous else '?'}"[:4000],
            )
        except Exception as exc:
            log.exception("rollback failed")
            return TaskResult(
                outcome="failed",
                error=(
                    f"{reason}; ROLLBACK FAILED: {type(exc).__name__}: {exc}; manual intervention required"
                )[:4000],
            )
