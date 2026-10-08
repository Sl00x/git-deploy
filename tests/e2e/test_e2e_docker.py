"""End-to-end on a real Docker Engine:

git tag -> build -> registry push -> CI notification -> digest verification (real
registry) -> approval -> plan -> real agent over real mTLS -> pull by digest ->
compose up (hardened) -> HTTP readiness -> Traefik route -> broken release ->
automatic rollback with traffic and volumes intact.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from udeploy_agent.client import ControlPlane
from udeploy_agent.config import AgentConfig
from udeploy_agent.docker import DockerCLI
from udeploy_agent.main import Agent
from udeploy_api.context import AppContext, default_registry_factory
from udeploy_api.main import create_agent_app
from udeploy_api.mtls import build_config
from udeploy_domain.naming import compose_project_name
from udeploy_security import pki

from ..conftest import World, auth, build_world, drain

pytestmark = [pytest.mark.e2e, pytest.mark.integration]

ROOT = Path(__file__).resolve().parents[2]
RUN = uuid.uuid4().hex[:6]
COMMIT1 = "1" * 40
COMMIT2 = "2" * 40
TRAEFIK_IMAGE = "traefik:v3.5"


def sh(*args: str, input_text: str | None = None, check: bool = True) -> str:
    res = subprocess.run(list(args), input=input_text, capture_output=True, text=True, check=False)
    if check and res.returncode != 0:
        raise AssertionError(f"{' '.join(args)} failed: {res.stdout}\n{res.stderr}")
    return res.stdout.strip()


def published_port(container: str, port: str) -> int:
    """Docker Desktop may report a provisional port right after `run -d`: wait until it is stable."""
    previous = None
    for _ in range(40):
        current = sh("docker", "port", container, port, check=False).splitlines()
        if current and current == previous:
            return int(current[0].rsplit(":", 1)[-1])
        previous = current
        time.sleep(0.5)
    raise AssertionError(f"no stable published port for {container}")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def e2e_manifest() -> dict[str, Any]:
    return {
        "apiVersion": "deploy.udeploy.io/v1",
        "kind": "Application",
        "project": "shop",
        "source": {"provider": "github", "repository": "acme/shop"},
        "build": {"registryRef": "registry-production"},
        "release": {
            "requireScanPass": True,
            "environments": {"production": {"tags": ["v*"], "requireApproval": True}},
        },
        "services": {
            "api": {
                "internalPort": 8000,
                "replicas": 2,
                "user": "1000:1000",
                "healthcheck": {
                    "path": "/health/ready",
                    "intervalSeconds": 1,
                    "startPeriodSeconds": 1,
                    "timeoutSeconds": 2,
                },
                "resources": {"memory": "64m", "cpus": 0.25, "pids": 64},
                "secretRefs": {"DATABASE_URL": "shop/database-url"},
                "volumes": [{"name": "data", "mountPath": "/data"}],
                "routes": [{"host": "api.shop.test", "tls": False}],
                "deploy": {"healthTimeoutSeconds": 20},
            },
            "worker": {
                "command": [
                    "sh",
                    "-c",
                    "while true; do test -r /run/secrets/database_url || exit 3; sleep 2; done",
                ],
                "secretRefs": {"DATABASE_URL": "shop/database-url"},
                "resources": {"memory": "32m", "cpus": 0.1, "pids": 32},
                "deploy": {"healthTimeoutSeconds": 20},
            },
            "frontend": {
                "internalPort": 8080,
                "user": "1000:1000",
                "healthcheck": {"path": "/", "intervalSeconds": 1, "startPeriodSeconds": 0},
                "resources": {"memory": "32m", "cpus": 0.1, "pids": 32},
                "routes": [{"host": "shop.test", "tls": False}],
                "deploy": {"healthTimeoutSeconds": 20},
            },
        },
        "targets": {"production": {"hostPool": "production-docker"}},
    }


def dockerfile(service: str, version: str, commit: str, *, healthy: bool = True) -> str:
    health = "mkdir -p /www/health && echo ok > /www/health/ready && " if healthy else ""
    port = {"api": 8000, "frontend": 8080}.get(service)
    cmd = f'CMD ["httpd", "-f", "-p", "{port}", "-h", "/www"]' if port else 'CMD ["sh"]'
    return (
        "FROM busybox:1.37\n"
        f"LABEL org.opencontainers.image.revision={commit}\n"
        f"RUN mkdir -p /www /data && {health}echo '{service} {version}' > /www/index.html "
        "&& chown 1000:1000 /data\n"
        f"{cmd}\n"
    )


def build_and_push(registry: str, service: str, version: str, commit: str, healthy: bool = True) -> str:
    ref = f"{registry}/prod/shop_{service}:{version}"
    sh(
        "docker",
        "build",
        "-q",
        "--platform",
        "linux/amd64",
        "-t",
        ref,
        "-",
        input_text=dockerfile(service, version, commit, healthy=healthy),
    )
    out = sh("docker", "push", ref)
    digest = next(p for p in out.split() if p.startswith("sha256:"))
    sh("docker", "rmi", ref, check=False)  # the agent must pull it by digest itself
    return digest


@pytest.fixture(scope="module")
def docker_env() -> Iterator[dict[str, Any]]:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    workdir = ROOT / ".e2e" / RUN
    dynamic = workdir / "traefik"
    dynamic.mkdir(parents=True)
    registry_name = f"udeploy-e2e-registry-{RUN}"
    traefik_name = f"udeploy-e2e-traefik-{RUN}"
    sh("docker", "pull", "-q", "busybox:1.37")
    sh("docker", "run", "-d", "--rm", "--name", registry_name, "-p", "127.0.0.1::5000", "registry:2")
    registry = f"localhost:{published_port(registry_name, '5000/tcp')}"
    sh(
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        traefik_name,
        "-p",
        "127.0.0.1::80",
        "-v",
        f"{dynamic}:/dynamic:ro",
        TRAEFIK_IMAGE,
        "--providers.file.directory=/dynamic",
        "--providers.file.watch=true",
        "--entrypoints.web.address=:80",
        "--entrypoints.websecure.address=:443",
        "--log.level=INFO",
    )
    traefik_port = published_port(traefik_name, "80/tcp")
    try:
        yield {
            "workdir": workdir,
            "dynamic": dynamic,
            "registry": registry,
            "traefik": traefik_name,
            "traefik_port": traefik_port,
        }
    finally:
        if not os.environ.get("UDEPLOY_E2E_KEEP"):  # keep everything running for inspection
            _cleanup(workdir, registry_name, traefik_name, registry)


def _cleanup(workdir: Path, registry_name: str, traefik_name: str, registry: str) -> None:
    project = compose_project_name("acme", "shop", "production")
    for cid in sh(
        "docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}", check=False
    ).split():
        sh("docker", "rm", "-f", cid, check=False)
    sh("docker", "rm", "-f", traefik_name, registry_name, check=False)
    for net in (f"{project}_backend", f"{project}_edge"):
        sh("docker", "network", "rm", net, check=False)
    sh("docker", "volume", "rm", f"{project}_data", check=False)
    for img in sh(
        "docker", "images", "--format", "{{.Repository}}@{{.Digest}}", f"{registry}/prod/*", check=False
    ).split():
        sh("docker", "rmi", img, check=False)
    shutil.rmtree(workdir, ignore_errors=True)
    with contextlib.suppress(OSError):
        workdir.parent.rmdir()  # .e2e/ if no other run is using it


@pytest.fixture
async def mtls_server(world_e2e: World) -> AsyncIterator[str]:
    settings = world_e2e.ctx.settings
    port = free_port()
    server = uvicorn.Server(
        build_config(
            create_agent_app(world_e2e.ctx),
            host="127.0.0.1",
            port=port,
            cert=str(settings.pki_dir / "agent-api.crt"),
            key=str(settings.pki_dir / "agent-api.key"),
            ca=str(settings.ca_cert_path),
            log_level="warning",
        )
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    yield f"https://127.0.0.1:{port}"
    server.should_exit = True
    await task


@pytest.fixture
async def world_e2e(ctx: AppContext, api: Any, docker_env: dict[str, Any]) -> World:
    ctx.registry_factory = default_registry_factory  # the real OCI client against registry:2
    from udeploy_api.models import Organization

    w = await build_world(ctx, api, manifest_doc=_with_registry_placeholder(), slug="acme")
    async with ctx.db.session() as s:
        org = await s.get(Organization, uuid.UUID(w.org_id))
        assert org is not None
        org.allowed_domains = ["shop.test"]
        await s.commit()
    r = await api.post(
        "/v1/registries",
        json={
            "organization_id": w.org_id,
            "name": "e2e",
            "host": docker_env["registry"],
            "namespace": "prod",
            "insecure_http": True,
        },
        headers=auth(w.owner),
    )
    assert r.status_code == 201, r.text
    doc = e2e_manifest()
    doc["build"]["registryRef"] = "e2e"
    r = await api.put(
        f"/v1/projects/{w.project_id}/manifest",
        content=json.dumps(doc),
        headers={**auth(w.owner), "Content-Type": "application/json"},
    )
    assert r.status_code == 200, r.text
    r = await api.put(
        f"/v1/projects/{w.project_id}/environments/production/secrets/shop/database-url",
        json={"value": "postgres://shop:e2e-secret-pw@db/shop"},
        headers=auth(w.owner),
    )
    assert r.status_code == 204
    return w


def _with_registry_placeholder() -> dict[str, Any]:
    # Initial project creation: the e2e registry is registered right after, then the manifest re-applied.
    doc = e2e_manifest()
    doc["services"]["api"]["routes"] = []
    doc["services"]["frontend"]["routes"] = []
    return doc


def make_agent(w: World, env: dict[str, Any], url: str, host_id: str, cert: bytes, key: bytes) -> Agent:
    state = env["workdir"] / "state"
    cfg = AgentConfig(
        state_dir=state,
        secrets_dir=state / "secrets",
        allowed_registries=[env["registry"]],
        traefik_container=env["traefik"],
        traefik_dynamic_dir=env["dynamic"],
        cert_resolver=None,
        probe_image="busybox:1.37",
    )
    cfg.identity_dir.mkdir(parents=True, exist_ok=True)
    cfg.key_path.write_bytes(key)
    cfg.cert_path.write_bytes(cert)
    cfg.ca_path.write_bytes(w.ctx.settings.ca_cert_path.read_bytes())
    return Agent(cfg, ControlPlane(cfg, url), DockerCLI(), host_id)


def http_get(port: int, host: str, path: str = "/") -> tuple[int, str]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Host": host})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:  # noqa: S310 - fixed local URL
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except OSError:
        return 0, ""


async def wait_http(traefik: str, host: str, expected: str, timeout: float = 30) -> str:
    body = ""
    for _ in range(int(timeout * 2)):
        # Re-resolved every time: Docker Desktop can re-map ephemeral host ports.
        port = int(sh("docker", "port", traefik, "80/tcp").splitlines()[0].rsplit(":", 1)[-1])
        status, body = http_get(port, host)
        if status == 200 and expected in body:
            return body
        await asyncio.sleep(0.5)
    raise AssertionError(f"{host} never served {expected!r} (last: {body!r})")


async def release(w: World, env: dict[str, Any], version: str, commit: str, digests: dict[str, str]) -> str:
    body = {
        "version": version,
        "commit_sha": commit,
        "tag": f"v{version}",
        "build_id": "e2e",
        "artifacts": [
            {
                "service": s,
                "registry": "e2e",
                "image": f"prod/shop_{s}",
                "tag": version,
                "digest": d,
                "scan": {"status": "passed"},
            }
            for s, d in digests.items()
        ],
    }
    r = await w.api.post(
        "/v1/ci/artifacts/published", json=body, headers={"Authorization": f"Bearer {w.ci_token}"}
    )
    assert r.status_code == 202, r.text
    await drain(w.ctx)
    rel = (await w.api.get(f"/v1/releases/{r.json()['release_id']}", headers=auth(w.owner))).json()
    assert rel["status"] == "verified", rel
    return str(rel["id"])


async def deploy_and_run(w: World, agent: Agent, release_id: str) -> dict[str, Any]:
    r = await w.api.post(
        "/v1/deployments",
        json={"project_id": w.project_id, "environment": "production", "release_id": release_id},
        headers=auth(w.deployer),
    )
    dep = r.json()
    assert dep["state"] == "awaiting_approval", dep
    await w.api.post(f"/v1/deployments/{dep['id']}/approve", headers=auth(w.owner))
    await drain(w.ctx)
    result = await agent.run_once(wait=5)
    assert result is not None
    return dict((await w.api.get(f"/v1/deployments/{dep['id']}", headers=auth(w.owner))).json())


def inspect(container: str) -> dict[str, Any]:
    return dict(json.loads(sh("docker", "inspect", container))[0])


async def test_tag_to_production_with_rollback(
    world_e2e: World, docker_env: dict[str, Any], mtls_server: str
) -> None:
    w, env = world_e2e, docker_env
    registry = env["registry"]
    project = compose_project_name("acme", "shop", "production")

    # --- git tag v1.0.0 -> CI builds and pushes three services (same tag, different digests)
    v1 = {s: build_and_push(registry, s, "1.0.0", COMMIT1) for s in ("api", "worker", "frontend")}
    assert len(set(v1.values())) == 3
    rel1 = await release(w, env, "1.0.0", COMMIT1, v1)

    # --- enrol the host agent (key generated locally, CSR signed by the control plane)
    tok = (
        await w.api.post(
            "/v1/hosts/enroll-token",
            json={"organization_id": w.org_id, "host_name": "vps-e2e", "pool": "production-docker"},
            headers=auth(w.owner),
        )
    ).json()["token"]
    key = pki.new_private_key_pem()
    enrolled = (
        await w.api.post(
            "/v1/agent/enroll", json={"token": tok, "csr_pem": pki.make_csr(key, "vps-e2e").decode()}
        )
    ).json()
    agent = make_agent(w, env, mtls_server, enrolled["host_id"], enrolled["certificate_pem"].encode(), key)
    await agent.cp.heartbeat(await agent.facts())

    # --- deploy v1
    dep1 = await deploy_and_run(w, agent, rel1)
    assert dep1["state"] == "succeeded", dep1
    assert await wait_http(env["traefik"], "api.shop.test", "api 1.0.0")
    assert await wait_http(env["traefik"], "shop.test", "frontend 1.0.0")

    # runtime hardening really applied
    api1 = inspect(f"{project}-api-1")
    hc = api1["HostConfig"]
    assert hc["Privileged"] is False and hc["ReadonlyRootfs"] is True and hc["CapDrop"] == ["ALL"]
    assert "no-new-privileges:true" in hc["SecurityOpt"]
    assert not hc.get("PortBindings") and hc["PidsLimit"] == 64 and hc["Memory"] == 64 * 1024**2
    assert api1["Config"]["Image"] == f"{registry}/prod/shop_api@{v1['api']}"
    assert all("docker.sock" not in m.get("Source", "") for m in api1["Mounts"])
    assert set(api1["NetworkSettings"]["Networks"]) == {f"{project}_backend", f"{project}_edge"}
    worker = inspect(f"{project}-worker-1")
    assert set(worker["NetworkSettings"]["Networks"]) == {f"{project}_backend"}
    assert worker["State"]["Running"] is True  # it exits(3) if the secret file is unreadable
    assert "e2e-secret-pw" not in json.dumps(worker["Config"]["Env"])  # secret is a file, not an env value

    # persistent data written by v1
    sh("docker", "exec", f"{project}-api-1", "sh", "-c", "echo keep-me > /data/marker")

    # --- git tag v2.0.0 with a broken api (readiness endpoint missing)
    v2 = {
        "api": build_and_push(registry, "api", "2.0.0", COMMIT2, healthy=False),
        "worker": build_and_push(registry, "worker", "2.0.0", COMMIT2),
        "frontend": build_and_push(registry, "frontend", "2.0.0", COMMIT2),
    }
    rel2 = await release(w, env, "2.0.0", COMMIT2, v2)
    dep2 = await deploy_and_run(w, agent, rel2)
    assert dep2["state"] == "rolled_back", dep2
    assert "api not ready" in (dep2["error"] or "")
    assert dep2["running_digests"] == v1

    # traffic is served by v1 again, volume content survived, nothing leaked
    assert await wait_http(env["traefik"], "api.shop.test", "api 1.0.0")
    assert await wait_http(env["traefik"], "shop.test", "frontend 1.0.0")
    assert sh("docker", "exec", f"{project}-api-1", "cat", "/data/marker") == "keep-me"
    assert inspect(f"{project}-api-1")["Config"]["Image"].endswith(v1["api"])
    logs = (await w.api.get(f"/v1/deployments/{dep2['id']}/logs", headers=auth(w.owner))).json()
    events = (await w.api.get(f"/v1/deployments/{dep2['id']}/events", headers=auth(w.owner))).json()
    assert "e2e-secret-pw" not in json.dumps(logs) + json.dumps(events)
    states = [e["state"] for e in events["items"]]
    assert "healthchecking" in states and "rollback_pending" in states and states[-1] == "rolled_back"
    await agent.cp.aclose()
