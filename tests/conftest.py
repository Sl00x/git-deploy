"""Integration fixtures: real PostgreSQL + Redis (testcontainers), real migrations."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import text

from udeploy_api.context import AppContext, PKIMaterial
from udeploy_api.main import create_agent_app, create_app
from udeploy_api.models import ApiToken, Membership, Organization, User
from udeploy_api.settings import Settings
from udeploy_providers.registry import (
    DigestMismatch,
    ImageConfig,
    ManifestInfo,
    ManifestNotFound,
    RegistryUnavailable,
)
from udeploy_security import pki
from udeploy_security.crypto import KeyRing
from udeploy_security.tokens import display_prefix, generate, hash_token

from .factories import COMMIT

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ containers


@pytest.fixture(scope="session")
def pg_url() -> Iterator[str]:
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer(
        "postgres:17-alpine", username="udeploy", password="udeploy", dbname="udeploy"
    ) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql+asyncpg://")
        from alembic import command
        from alembic.config import Config

        os.environ["UDEPLOY_DATABASE_URL"] = url
        command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
        yield url


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    from testcontainers.community.redis import RedisContainer

    with RedisContainer("redis:7-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}/0"


# ------------------------------------------------------------------ fake registry


@dataclass
class FakeImage:
    platform: str = "linux/amd64"
    labels: dict[str, str] = field(default_factory=lambda: {"org.opencontainers.image.revision": COMMIT})


class FakeRegistry:
    """In-memory OCI registry used by API-level tests (the real one is exercised in e2e)."""

    def __init__(self) -> None:
        self.images: dict[tuple[str, str], FakeImage] = {}
        self.tags: dict[tuple[str, str], str] = {}
        self.unavailable = False
        self.calls = 0

    def publish(self, repo: str, digest: str, tag: str | None = None, **kw: Any) -> None:
        self.images[(repo, digest)] = FakeImage(**kw)
        if tag:
            self.tags[(repo, tag)] = digest

    async def resolve(self, repository: str, reference: str) -> ManifestInfo:
        self.calls += 1
        if self.unavailable:
            raise RegistryUnavailable("registry returned 503")
        digest = self.tags.get((repository, reference), reference)
        if (repository, digest) not in self.images:
            raise ManifestNotFound(f"{repository}:{reference} not found in registry")
        return ManifestInfo(digest=digest, media_type="application/vnd.oci.image.manifest.v1+json", size=1)

    async def image_config(self, repository: str, digest: str, platform: str) -> ImageConfig:
        self.calls += 1
        if self.unavailable:
            raise RegistryUnavailable("registry returned 503")
        img = self.images.get((repository, digest))
        if img is None:
            raise ManifestNotFound(f"{repository}@{digest} not found in registry")
        if img.platform == "tampered":
            raise DigestMismatch("served content does not match digest")
        return ImageConfig(manifest_digest=digest, platform=img.platform, labels=img.labels)

    async def aclose(self) -> None:
        return None


# ------------------------------------------------------------------ context & clients


@pytest.fixture(scope="session")
def pki_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("pki")
    key, cert = pki.create_ca()
    (d / "ca.key").write_bytes(key)
    (d / "ca.crt").write_bytes(cert)
    skey, scert = pki.issue_server_cert(key, cert, ["localhost"], ips=["127.0.0.1"])
    (d / "agent-api.key").write_bytes(skey)
    (d / "agent-api.crt").write_bytes(scert)
    return d


@pytest.fixture(scope="session")
def settings(pg_url: str, redis_url: str, pki_dir: Path) -> Settings:
    return Settings(
        database_url=pg_url,
        redis_url=redis_url,
        master_keys=SecretStr(KeyRing.generate_entry("test")),
        public_base_url="https://deploy.test",
        agent_api_url="https://localhost:8443",
        pki_dir=pki_dir,
        reserved_hosts=["deploy.inkerflow.example"],
        release_verify_max_retries=3,
        release_verify_backoff_seconds=0,
        agent_lease_seconds=30,
        log_json=False,
    )


@pytest.fixture
async def ctx(settings: Settings) -> AsyncIterator[AppContext]:
    context = AppContext.from_settings(settings, null_pool=True)
    context.pki = PKIMaterial.load(settings.ca_key_path, settings.ca_cert_path)
    registry = FakeRegistry()
    context.registry_factory = lambda _reg, _box: registry  # type: ignore[assignment,return-value]
    context.fake_registry = registry  # type: ignore[attr-defined]
    async with context.db.session() as s:
        tables = (
            (
                await s.execute(
                    text(
                        "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'alembic_version'"
                    )
                )
            )
            .scalars()
            .all()
        )
        await s.execute(text(f"TRUNCATE {', '.join(tables)} RESTART IDENTITY CASCADE"))
        await s.commit()
    yield context
    await context.db.dispose()


@pytest.fixture
async def api(ctx: AppContext) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(ctx)
    app.state.ctx = ctx
    app.state.redis = None
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://deploy.test"
    ) as client:
        yield client


def agent_client(ctx: AppContext, cert_pem: bytes | None) -> httpx.AsyncClient:
    """Agent API client; simulates the verified peer certificate the mTLS listener would inject."""
    inner = create_agent_app(ctx)
    inner.state.ctx = ctx
    inner.state.redis = None
    der = pki.load_cert(cert_pem).public_bytes(pki.serialization.Encoding.DER) if cert_pem else None

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            scope.setdefault("state", {})["tls_peer_cert_der"] = der
        await inner(scope, receive, send)

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://agent.test")


# ------------------------------------------------------------------ world builder


@dataclass
class World:
    ctx: AppContext
    api: httpx.AsyncClient
    org_id: str
    owner: dict[str, str]
    deployer: dict[str, str]
    developer: dict[str, str]
    project_id: str = ""
    ci_token: str = ""
    webhook: dict[str, Any] = field(default_factory=dict)
    host_id: str = ""
    host_cert: bytes = b""

    @property
    def registry(self) -> FakeRegistry:
        return self.ctx.fake_registry  # type: ignore[attr-defined, no-any-return]


async def make_user(ctx: AppContext, org_id: uuid.UUID, email: str, role: str) -> dict[str, str]:
    async with ctx.db.session() as s:
        user = User(email=email)
        s.add(user)
        await s.flush()
        s.add(Membership(user_id=user.id, organization_id=org_id, role=role))
        token = generate("user")
        s.add(ApiToken(user_id=user.id, name="t", token_hash=hash_token(token), prefix=display_prefix(token)))
        await s.commit()
        return {"Authorization": f"Bearer {token}", "user_id": str(user.id)}


def auth(headers: dict[str, str]) -> dict[str, str]:
    return {"Authorization": headers["Authorization"]}


async def build_world(
    ctx: AppContext, api: httpx.AsyncClient, *, manifest_doc: dict[str, Any] | None = None, slug: str = "acme"
) -> World:
    from .factories import manifest

    async with ctx.db.session() as s:
        org = Organization(slug=slug, name=slug, allowed_domains=["inkerflow.example", "other.example"])
        s.add(org)
        await s.commit()
        org_id = org.id
    owner = await make_user(ctx, org_id, f"owner@{slug}.test", "owner")
    deployer = await make_user(ctx, org_id, f"deployer@{slug}.test", "deployer")
    developer = await make_user(ctx, org_id, f"dev@{slug}.test", "developer")
    w = World(ctx=ctx, api=api, org_id=str(org_id), owner=owner, deployer=deployer, developer=developer)

    r = await api.post(
        "/v1/registries",
        json={
            "organization_id": w.org_id,
            "name": "registry-production",
            "host": "registry.example.com",
            "namespace": "prod",
            "username": "ci",
            "password": "registry-password",
        },
        headers=auth(owner),
    )
    assert r.status_code == 201, r.text
    doc = manifest_doc or manifest()
    r = await api.post(
        "/v1/projects",
        json={
            "organization_id": w.org_id,
            "slug": doc["project"],
            "name": doc["project"],
            "source_provider": doc["source"]["provider"],
            "repository": doc["source"]["repository"],
            "manifest": doc,
        },
        headers=auth(owner),
    )
    assert r.status_code == 201, r.text
    w.project_id = r.json()["id"]
    r = await api.post(f"/v1/projects/{w.project_id}/ci-tokens", json={"name": "gitlab"}, headers=auth(owner))
    w.ci_token = r.json()["token"]
    r = await api.post(
        f"/v1/projects/{w.project_id}/webhook-endpoints",
        json={"provider": doc["source"]["provider"]},
        headers=auth(owner),
    )
    w.webhook = r.json()
    for env in doc["targets"]:
        r = await api.put(
            f"/v1/projects/{w.project_id}/environments/{env}/secrets/{doc['project']}/database-url",
            json={"value": f"postgres://app:{env}-pw@db/{doc['project']}"},
            headers=auth(owner),
        )
        assert r.status_code == 204, r.text
    return w


async def enroll_host(w: World, name: str = "vps-1", pool: str = "production-docker") -> tuple[str, bytes]:
    r = await w.api.post(
        "/v1/hosts/enroll-token",
        json={"organization_id": w.org_id, "host_name": name, "pool": pool},
        headers=auth(w.owner),
    )
    assert r.status_code == 201, r.text
    key = pki.new_private_key_pem()
    r = await w.api.post(
        "/v1/agent/enroll", json={"token": r.json()["token"], "csr_pem": pki.make_csr(key, name).decode()}
    )
    assert r.status_code == 201, r.text
    return r.json()["host_id"], r.json()["certificate_pem"].encode()


async def drain(ctx: AppContext, *, rounds: int = 5, ignore_delay: bool = True) -> list[tuple[str, Any]]:
    """Run the outbox relay and execute dispatched tasks inline (same code as Celery tasks)."""
    from udeploy_api.services.deployments import start_deployment
    from udeploy_api.services.releases import verify_release
    from udeploy_worker.tasks import relay

    results: list[tuple[str, Any]] = []
    for _ in range(rounds):
        if ignore_delay:
            async with ctx.db.session() as s:
                await s.execute(text("UPDATE outbox SET not_before = now() WHERE dispatched_at IS NULL"))
                await s.commit()
        sent: list[tuple[str, dict[str, Any]]] = []
        await relay(ctx, lambda name, payload: sent.append((name, payload)))
        if not sent:
            break
        for name, payload in sent:
            async with ctx.db.session() as s:
                if name == "udeploy.verify_release":
                    out: Any = await verify_release(ctx, s, uuid.UUID(payload["release_id"]))
                else:
                    out = await start_deployment(ctx, s, uuid.UUID(payload["deployment_id"]))
                await s.commit()
            results.append((name, out))
    return results


def release_body(
    version: str,
    *,
    commit: str = COMMIT,
    tag: str | None = None,
    branch: str | None = None,
    digests: dict[str, str] | None = None,
    scan: str = "passed",
) -> dict[str, Any]:
    from .factories import digest

    digests = digests or {s: digest(f"{s}-{version}") for s in ("api", "worker", "frontend")}
    return {
        "version": version,
        "commit_sha": commit,
        "tag": tag,
        "branch": branch,
        "build_id": "42",
        "artifacts": [
            {
                "service": s,
                "registry": "registry-production",
                "image": f"prod/inkerflow_{s}",
                "tag": version,
                "digest": d,
                "scan": {"status": scan},
            }
            for s, d in digests.items()
        ],
    }


def publish_release(w: World, body: dict[str, Any]) -> None:
    for art in body["artifacts"]:
        w.registry.publish(
            art["image"],
            art["digest"],
            art["tag"],
            labels={"org.opencontainers.image.revision": body["commit_sha"]},
        )


@pytest.fixture
async def world(ctx: AppContext, api: httpx.AsyncClient) -> World:
    return await build_world(ctx, api)
