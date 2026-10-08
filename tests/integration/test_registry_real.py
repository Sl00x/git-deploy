"""OCIRegistryClient against a real `registry:2` container."""

from __future__ import annotations

import subprocess
import uuid
from collections.abc import Iterator

import pytest

from udeploy_providers.registry import ManifestNotFound, OCIRegistryClient

pytestmark = pytest.mark.integration


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture(scope="module")
def registry() -> Iterator[str]:
    name = f"udeploy-test-registry-{uuid.uuid4().hex[:6]}"
    _docker("run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::5000", "registry:2")
    from ..e2e.test_e2e_docker import published_port

    port = published_port(name, "5000/tcp")
    try:
        yield f"localhost:{port}"
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


def _push(registry: str, repo: str, tag: str, revision: str) -> str:
    ref = f"{registry}/{repo}:{tag}"
    dockerfile = f"FROM busybox:1.37\nLABEL org.opencontainers.image.revision={revision}\n"
    subprocess.run(
        ["docker", "build", "-q", "-t", ref, "-"],
        input=dockerfile,
        text=True,
        check=True,
        capture_output=True,
    )
    out = _docker("push", ref)
    subprocess.run(["docker", "rmi", ref], capture_output=True, check=False)
    return next(part for part in out.split() if part.startswith("sha256:"))


async def test_resolve_and_labels(registry: str) -> None:
    digest = _push(registry, "prod/demo_api", "1.0.0", "d" * 40)
    async with OCIRegistryClient(registry, insecure_http=True) as client:
        info = await client.resolve("prod/demo_api", "1.0.0")
        assert info.digest == digest
        cfg = await client.image_config("prod/demo_api", digest, "linux/amd64")
        assert cfg.labels["org.opencontainers.image.revision"] == "d" * 40
        with pytest.raises(ManifestNotFound):
            await client.resolve("prod/demo_api", "sha256:" + "0" * 64)
        with pytest.raises(ManifestNotFound):
            await client.resolve("prod/never_pushed", "1.0.0")
