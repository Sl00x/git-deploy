"""Versioned, declarative Application manifest (deploy.udeploy.io/v1).

The manifest is a *request*. It is parsed with `extra="forbid"` everywhere, so a
field that the schema does not know (``privileged``, ``network_mode``, ``cap_add``…)
is an error rather than something passed through to Docker. Server-side policy
(`udeploy_planner.policy`) is applied on top of this schema.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .naming import is_env_var_name, is_slug

API_VERSION = "deploy.udeploy.io/v1"

_MEMORY = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([kmg]?)b?$", re.IGNORECASE)
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_SECRET_PATH = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*){0,7}$")
_SAFE_PATH = re.compile(r"^/(?:[A-Za-z0-9._-]+/?)*$")
_HTTP_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*$")
_USER = re.compile(r"^[0-9]{1,10}(?::[0-9]{1,10})?$")
_GLOB = re.compile(r"^[A-Za-z0-9._/*-]{1,200}$")

Slug = Annotated[str, Field(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


def parse_memory(value: str | int) -> int:
    if isinstance(value, int):
        return value
    match = _MEMORY.match(value.strip())
    if not match:
        raise ValueError(f"invalid memory quantity {value!r}")
    number, unit = float(match.group(1)), match.group(2).lower()
    factor = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[unit]
    return int(number * factor)


class Source(_Strict):
    provider: Literal["github", "gitlab"]
    repository: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$")
    default_branch: str = Field("main", alias="defaultBranch", max_length=255)


class Build(_Strict):
    mode: Literal["external_ci", "managed_build"] = "external_ci"
    tag_template: str = Field("{semver}", alias="tagTemplate", max_length=100)
    registry_ref: Slug = Field(alias="registryRef")


class EnvironmentRule(_Strict):
    branches: list[Annotated[str, Field(pattern=_GLOB.pattern)]] = Field(default_factory=list)
    tags: list[Annotated[str, Field(pattern=_GLOB.pattern)]] = Field(default_factory=list)
    auto_deploy: bool = Field(False, alias="autoDeploy")
    require_approval: bool = Field(False, alias="requireApproval")


class ReleasePolicy(_Strict):
    trigger: Literal["pipeline_success", "artifact_published", "manual"] = "artifact_published"
    require_registry_digest: Literal[True] = Field(True, alias="requireRegistryDigest")
    require_signed_artifact: bool = Field(False, alias="requireSignedArtifact")
    require_scan_pass: bool = Field(True, alias="requireScanPass")
    environments: dict[Slug, EnvironmentRule] = Field(default_factory=dict)


class HealthCheck(_Strict):
    path: str = Field(max_length=512)
    interval_seconds: int = Field(10, alias="intervalSeconds", ge=1, le=300)
    timeout_seconds: int = Field(3, alias="timeoutSeconds", ge=1, le=60)
    start_period_seconds: int = Field(5, alias="startPeriodSeconds", ge=0, le=600)
    retries: int = Field(3, ge=1, le=20)

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        # Only a path: the agent decides *where* to probe (SSRF protection).
        if not _HTTP_PATH.match(v) or "//" in v or ".." in v:
            raise ValueError("healthcheck.path must be an absolute URL path without scheme or host")
        return v


class Resources(_Strict):
    memory: str | int = "512m"
    cpus: float = Field(0.5, gt=0, le=64)
    pids: int = Field(256, ge=16, le=32768)

    @field_validator("memory")
    @classmethod
    def _mem(cls, v: str | int) -> str | int:
        parsed = parse_memory(v)
        if parsed < 16 * 1024**2:
            raise ValueError("memory must be at least 16m")
        return v

    @property
    def memory_bytes(self) -> int:
        return parse_memory(self.memory)


class Route(_Strict):
    host: str = Field(max_length=253)
    path_prefix: str = Field("/", alias="pathPrefix", max_length=256)
    tls: bool = True
    # Environments this route applies to; empty = every environment. A host can
    # only be claimed once platform-wide, so staging and production need distinct hosts.
    environments: list[Slug] = Field(default_factory=list)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.lower().rstrip(".")
        if not _HOSTNAME.match(v):
            raise ValueError(f"invalid route host {v!r}")
        return v

    @field_validator("path_prefix")
    @classmethod
    def _prefix(cls, v: str) -> str:
        if not _HTTP_PATH.match(v) or ".." in v or "`" in v:
            raise ValueError("pathPrefix must be an absolute URL path")
        return v


class Volume(_Strict):
    """Named, platform-managed volume. Host bind mounts are not expressible."""

    name: Slug
    mount_path: str = Field(alias="mountPath", max_length=256)
    read_only: bool = Field(False, alias="readOnly")

    @field_validator("mount_path")
    @classmethod
    def _mount(cls, v: str) -> str:
        if not _SAFE_PATH.match(v) or ".." in v or v.rstrip("/") in {"", "/proc", "/sys", "/dev", "/etc"}:
            raise ValueError(f"invalid mountPath {v!r}")
        return v.rstrip("/") or "/"


class DeploySpec(_Strict):
    strategy: Literal["recreate", "rolling", "blue_green"] = "recreate"
    health_timeout_seconds: int = Field(120, alias="healthTimeoutSeconds", ge=5, le=1800)
    drain_timeout_seconds: int = Field(30, alias="drainTimeoutSeconds", ge=0, le=600)


class ServiceSpec(_Strict):
    image_name: str = Field("{repository}_{service}", alias="imageName", max_length=200)
    command: list[Annotated[str, Field(max_length=4096)]] | None = Field(None, max_length=64)
    internal_port: int | None = Field(None, alias="internalPort", ge=1, le=65535)
    replicas: int = Field(1, ge=0, le=20)
    healthcheck: HealthCheck | None = None
    resources: Resources = Field(default_factory=Resources)
    env: dict[str, Annotated[str, Field(max_length=8192)]] = Field(default_factory=dict)
    secret_refs: dict[str, str] = Field(default_factory=dict, alias="secretRefs")
    routes: list[Route] = Field(default_factory=list, max_length=20)
    volumes: list[Volume] = Field(default_factory=list, max_length=10)
    tmpfs: list[str] = Field(default_factory=lambda: ["/tmp"], max_length=10)  # noqa: S108
    read_only_root_filesystem: bool = Field(True, alias="readOnlyRootFilesystem")
    user: str | None = Field(None, description="numeric uid[:gid]")
    platform: Literal["linux/amd64", "linux/arm64"] = "linux/amd64"
    deploy: DeploySpec = Field(default_factory=DeploySpec)

    @field_validator("env")
    @classmethod
    def _env(cls, v: dict[str, str]) -> dict[str, str]:
        for key in v:
            if not is_env_var_name(key):
                raise ValueError(f"invalid environment variable name {key!r}")
        return v

    @field_validator("secret_refs")
    @classmethod
    def _secrets(cls, v: dict[str, str]) -> dict[str, str]:
        for key, ref in v.items():
            if not is_env_var_name(key):
                raise ValueError(f"invalid secret variable name {key!r}")
            if not _SECRET_PATH.match(ref):
                raise ValueError(f"invalid secret reference {ref!r}")
        return v

    @field_validator("tmpfs")
    @classmethod
    def _tmpfs(cls, v: list[str]) -> list[str]:
        for path in v:
            if not _SAFE_PATH.match(path) or ".." in path or path == "/":
                raise ValueError(f"invalid tmpfs path {path!r}")
        return v

    @field_validator("user")
    @classmethod
    def _user(cls, v: str | None) -> str | None:
        if v is not None and not _USER.match(v):
            raise ValueError("user must be a numeric uid or uid:gid")
        return v

    @model_validator(mode="after")
    def _consistency(self) -> ServiceSpec:
        overlap = set(self.env) & set(self.secret_refs)
        if overlap:
            raise ValueError(f"variables defined both in env and secretRefs: {sorted(overlap)}")
        if self.routes and self.internal_port is None:
            raise ValueError("a service with routes needs internalPort")
        if self.healthcheck and self.internal_port is None:
            raise ValueError("an HTTP healthcheck needs internalPort")
        mounts = [vol.mount_path for vol in self.volumes] + list(self.tmpfs)
        if len(mounts) != len(set(mounts)):
            raise ValueError("duplicate mount paths")
        return self


class Target(_Strict):
    host_pool: Slug = Field(alias="hostPool")


class ApplicationManifest(_Strict):
    api_version: Literal["deploy.udeploy.io/v1"] = Field(alias="apiVersion")
    kind: Literal["Application"]
    project: Slug
    source: Source
    build: Build
    release: ReleasePolicy = Field(default_factory=ReleasePolicy)
    services: dict[str, ServiceSpec] = Field(min_length=1, max_length=50)
    targets: dict[Slug, Target] = Field(default_factory=dict)

    @field_validator("services")
    @classmethod
    def _service_names(cls, v: dict[str, ServiceSpec]) -> dict[str, ServiceSpec]:
        for name in v:
            if not is_slug(name) or len(name) > 40:
                raise ValueError(f"invalid service name {name!r}")
        return v

    @model_validator(mode="after")
    def _targets(self) -> ApplicationManifest:
        missing = set(self.release.environments) - set(self.targets)
        if missing:
            raise ValueError(f"environments without target: {sorted(missing)}")
        envs = set(self.targets)
        seen: set[tuple[str, str]] = set()
        for service in self.services.values():
            for route in service.routes:
                unknown = set(route.environments) - envs
                if unknown:
                    raise ValueError(f"route {route.host} targets unknown environments {sorted(unknown)}")
                for _env in route.environments or sorted(envs):
                    key = (route.host, route.path_prefix)
                    if key in seen:
                        raise ValueError(
                            f"{route.host}{route.path_prefix} is claimed more than once "
                            "(restrict the route with `environments:` or use one host per environment)"
                        )
                    seen.add(key)
        return self

    def routes_for(self, service: str, environment: str) -> list[Route]:
        return [
            r for r in self.services[service].routes if not r.environments or environment in r.environments
        ]


def load_manifest_yaml(text: str) -> dict[str, object]:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("manifest must be a YAML mapping")
    return data
