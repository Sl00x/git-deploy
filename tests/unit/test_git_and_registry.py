from __future__ import annotations

import hashlib
import json

import httpx
import pytest

from udeploy_providers.git import EventKind, UnsupportedEvent, normalize_github, normalize_gitlab
from udeploy_providers.registry import (
    DigestMismatch,
    ManifestNotFound,
    OCIRegistryClient,
    RegistryUnavailable,
)

SHA = "c" * 40


def test_github_push_and_tag() -> None:
    push = normalize_github(
        "push",
        {
            "ref": "refs/heads/main",
            "after": SHA,
            "repository": {"full_name": "o/r"},
            "sender": {"login": "u"},
        },
    )
    assert (push.kind, push.branch, push.commit_sha) == (EventKind.PUSH, "main", SHA)
    tag = normalize_github(
        "push", {"ref": "refs/tags/v1.0.0", "after": SHA, "repository": {"full_name": "o/r"}}
    )
    assert (tag.kind, tag.tag) == (EventKind.TAG, "v1.0.0")


def test_github_workflow_run() -> None:
    ev = normalize_github(
        "workflow_run",
        {
            "action": "completed",
            "workflow_run": {"conclusion": "failure", "head_sha": SHA, "id": 7},
            "repository": {"full_name": "o/r"},
        },
    )
    assert ev.kind == EventKind.PIPELINE_FAILURE


def test_gitlab_pipeline() -> None:
    ev = normalize_gitlab(
        "Pipeline Hook",
        {
            "object_kind": "pipeline",
            "project": {"path_with_namespace": "g/r"},
            "object_attributes": {"status": "success", "ref": "v1.2.0", "tag": True, "sha": SHA, "id": 9},
        },
    )
    assert (ev.kind, ev.tag, ev.branch) == (EventKind.PIPELINE_SUCCESS, "v1.2.0", None)
    with pytest.raises(UnsupportedEvent):
        normalize_gitlab(
            "Pipeline Hook",
            {
                "object_kind": "pipeline",
                "project": {"path_with_namespace": "g/r"},
                "object_attributes": {"status": "running"},
            },
        )


def _registry(
    manifest_body: bytes, config_body: bytes, *, header_digest: str | None = None
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/manifests/" in request.url.path:
            headers = {"content-type": "application/vnd.oci.image.manifest.v1+json"}
            if header_digest:
                headers["docker-content-digest"] = header_digest
            return httpx.Response(200, content=manifest_body, headers=headers)
        if "/blobs/" in request.url.path:
            return httpx.Response(200, content=config_body)
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _image() -> tuple[bytes, bytes, str]:
    config = json.dumps(
        {
            "os": "linux",
            "architecture": "amd64",
            "config": {"Labels": {"org.opencontainers.image.revision": SHA}},
        }
    ).encode()
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": config_digest, "size": len(config)},
            "layers": [],
        }
    ).encode()
    return manifest, config, "sha256:" + hashlib.sha256(manifest).hexdigest()


async def test_registry_reads_config_labels() -> None:
    manifest, config, dig = _image()
    client = OCIRegistryClient("r.example", transport=_registry(manifest, config))
    cfg = await client.image_config("p/app", dig, "linux/amd64")
    assert cfg.platform == "linux/amd64"
    assert cfg.labels["org.opencontainers.image.revision"] == SHA


async def test_registry_detects_content_not_matching_requested_digest() -> None:
    manifest, config, _ = _image()
    client = OCIRegistryClient("r.example", transport=_registry(manifest, config))
    with pytest.raises(DigestMismatch):
        await client.image_config("p/app", "sha256:" + "0" * 64, "linux/amd64")


async def test_registry_errors_are_classified() -> None:
    def h404(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    def h503(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with pytest.raises(ManifestNotFound):
        await OCIRegistryClient("r", transport=httpx.MockTransport(h404)).resolve("p/a", "1.0")
    with pytest.raises(RegistryUnavailable):
        await OCIRegistryClient("r", transport=httpx.MockTransport(h503)).resolve("p/a", "1.0")


async def test_registry_bearer_token_flow() -> None:
    manifest, config, dig = _image()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "auth.example":
            seen.append(request.headers.get("authorization", ""))
            return httpx.Response(200, json={"token": "T"})
        if request.headers.get("authorization") != "Bearer T":
            return httpx.Response(
                401, headers={"www-authenticate": 'Bearer realm="https://auth.example/token",service="r"'}
            )
        return httpx.Response(
            200, content=manifest, headers={"content-type": "application/vnd.oci.image.manifest.v1+json"}
        )

    client = OCIRegistryClient(
        "r.example", username="u", password="p", transport=httpx.MockTransport(handler)
    )
    info = await client.resolve("p/app", dig)
    assert info.digest == dig
    assert seen and seen[0].startswith("Basic ")
