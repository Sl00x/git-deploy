"""OCI Distribution (Docker Registry HTTP API V2) client.

One implementation covers every V2/OCI-compatible registry: Docker Hub, GHCR,
GitLab Container Registry, Harbor, AWS ECR (basic auth `AWS:<login password>`),
Azure ACR (service principal / token) and self-hosted `registry`.
The control plane uses it to *verify* that a digest really exists and to read
the image config (OCI labels, platform) before any deployment is planned.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

import httpx

from udeploy_domain.naming import is_digest

MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 8 * 1024 * 1024
_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')


class RegistryKind(StrEnum):
    GENERIC = "generic"
    DOCKERHUB = "dockerhub"
    GHCR = "ghcr"
    GITLAB = "gitlab"
    HARBOR = "harbor"
    ECR = "ecr"
    ACR = "acr"


class RegistryError(Exception):
    retryable = False


class RegistryUnavailable(RegistryError):
    retryable = True


class ManifestNotFound(RegistryError):
    # Retryable: CI may notify slightly before the registry is consistent,
    # but retries are bounded by the caller.
    retryable = True


class RegistryAuthError(RegistryError):
    pass


class DigestMismatch(RegistryError):
    pass


@dataclass(frozen=True)
class ManifestInfo:
    digest: str
    media_type: str
    size: int


@dataclass(frozen=True)
class ImageConfig:
    manifest_digest: str
    platform: str
    labels: dict[str, str] = field(default_factory=dict)


class RegistryProvider(Protocol):
    async def resolve(self, repository: str, reference: str) -> ManifestInfo: ...

    async def image_config(self, repository: str, digest: str, platform: str) -> ImageConfig: ...

    async def aclose(self) -> None: ...


def api_host(host: str) -> str:
    return "registry-1.docker.io" if host in {"docker.io", "index.docker.io"} else host


class OCIRegistryClient:
    def __init__(
        self,
        host: str,
        *,
        username: str | None = None,
        password: str | None = None,
        insecure_http: bool = False,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        scheme = "http" if insecure_http else "https"
        self._base = f"{scheme}://{api_host(host)}"
        self._username = username
        self._password = password
        self._tokens: dict[str, str] = {}
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": "udeploy/0.1"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> OCIRegistryClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ auth
    def _basic(self) -> httpx.BasicAuth | None:
        if self._username is not None and self._password is not None:
            return httpx.BasicAuth(self._username, self._password)
        return None

    async def _bearer_token(self, challenge: str, scope_hint: str) -> str:
        params = dict(_CHALLENGE.findall(challenge))
        realm = params.pop("realm", None)
        if not realm or not realm.startswith(("https://", "http://")):
            raise RegistryAuthError("registry returned an unusable auth challenge")
        params.setdefault("scope", scope_hint)
        try:
            resp = await self._client.get(realm, params=params, auth=self._basic())
        except httpx.HTTPError as exc:
            raise RegistryUnavailable(f"token endpoint unreachable: {type(exc).__name__}") from exc
        if resp.status_code in (401, 403):
            raise RegistryAuthError("registry rejected the configured credentials")
        if resp.status_code >= 500:
            raise RegistryUnavailable(f"token endpoint returned {resp.status_code}")
        if resp.status_code != 200:
            raise RegistryAuthError(f"token endpoint returned {resp.status_code}")
        body = resp.json()
        token = body.get("token") or body.get("access_token")
        if not isinstance(token, str):
            raise RegistryAuthError("token endpoint returned no token")
        return token

    async def _request(
        self, method: str, path: str, repository: str, *, headers: dict[str, str] | None = None
    ) -> httpx.Response:
        url = f"{self._base}{path}"
        scope = f"repository:{repository}:pull"
        hdrs = dict(headers or {})
        for attempt in range(2):
            auth: httpx.BasicAuth | None = None
            if scope in self._tokens:
                hdrs["Authorization"] = f"Bearer {self._tokens[scope]}"
            else:
                auth = self._basic()
            try:
                resp = await self._client.request(method, url, headers=hdrs, auth=auth)
                # Blob downloads usually redirect to object storage; follow without credentials.
                hops = 0
                while resp.status_code in (301, 302, 303, 307, 308) and hops < 3:
                    location = resp.headers.get("location", "")
                    target = httpx.URL(url).join(location)
                    resp = await self._client.request(
                        method, target, headers={"Accept": hdrs.get("Accept", "*/*")}
                    )
                    hops += 1
            except httpx.HTTPError as exc:
                raise RegistryUnavailable(f"registry unreachable: {type(exc).__name__}") from exc
            if resp.status_code == 401 and attempt == 0:
                challenge = resp.headers.get("www-authenticate", "")
                if challenge.lower().startswith("bearer"):
                    self._tokens[scope] = await self._bearer_token(challenge, scope)
                    continue
                raise RegistryAuthError("registry requires credentials")
            return resp
        raise RegistryAuthError("registry rejected the bearer token")

    @staticmethod
    def _check(resp: httpx.Response, what: str) -> None:
        if resp.status_code == 404:
            raise ManifestNotFound(f"{what} not found in registry")
        if resp.status_code in (401, 403):
            raise RegistryAuthError(f"access to {what} denied")
        if resp.status_code == 429 or resp.status_code >= 500:
            raise RegistryUnavailable(f"registry returned {resp.status_code} for {what}")
        if resp.status_code >= 400:
            raise RegistryError(f"registry returned {resp.status_code} for {what}")

    # -------------------------------------------------------------- manifests
    async def _get_manifest(self, repository: str, reference: str) -> tuple[ManifestInfo, dict[str, Any]]:
        resp = await self._request(
            "GET", f"/v2/{repository}/manifests/{reference}", repository, headers={"Accept": MANIFEST_ACCEPT}
        )
        self._check(resp, f"{repository}:{reference}")
        body = resp.content
        if len(body) > MAX_MANIFEST_BYTES:
            raise RegistryError("manifest too large")
        computed = "sha256:" + hashlib.sha256(body).hexdigest()
        header = resp.headers.get("docker-content-digest")
        if header and header != computed:
            raise DigestMismatch("registry digest header does not match manifest content")
        if is_digest(reference) and computed != reference:
            raise DigestMismatch(f"registry served content {computed} for {reference}")
        media_type = resp.headers.get("content-type", "").split(";")[0]
        doc = json.loads(body)
        media_type = doc.get("mediaType") or media_type
        return ManifestInfo(digest=computed, media_type=media_type, size=len(body)), doc

    async def resolve(self, repository: str, reference: str) -> ManifestInfo:
        """Resolve a tag or digest to the content-addressed manifest digest."""
        info, _ = await self._get_manifest(repository, reference)
        return info

    async def image_config(self, repository: str, digest: str, platform: str) -> ImageConfig:
        info, doc = await self._get_manifest(repository, digest)
        manifest_digest = info.digest
        if info.media_type in INDEX_TYPES:
            os_name, arch = platform.split("/", 1)
            chosen = None
            for entry in doc.get("manifests", []):
                plat = entry.get("platform") or {}
                if plat.get("os") == os_name and plat.get("architecture") == arch:
                    chosen = entry
                    break
            if chosen is None:
                raise RegistryError(f"image index {digest} has no {platform} manifest")
            info, doc = await self._get_manifest(repository, chosen["digest"])
        config_desc = doc.get("config") or {}
        config_digest = config_desc.get("digest")
        if not isinstance(config_digest, str) or not is_digest(config_digest):
            raise RegistryError("manifest has no config descriptor")
        resp = await self._request("GET", f"/v2/{repository}/blobs/{config_digest}", repository)
        self._check(resp, f"config blob {config_digest}")
        if len(resp.content) > MAX_CONFIG_BYTES:
            raise RegistryError("config blob too large")
        if "sha256:" + hashlib.sha256(resp.content).hexdigest() != config_digest:
            raise DigestMismatch("config blob content does not match its digest")
        config = json.loads(resp.content)
        actual_platform = f"{config.get('os', '?')}/{config.get('architecture', '?')}"
        labels = (config.get("config") or {}).get("Labels") or {}
        return ImageConfig(
            manifest_digest=manifest_digest,
            platform=actual_platform,
            labels={str(k): str(v) for k, v in labels.items()},
        )
