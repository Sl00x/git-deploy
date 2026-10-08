"""Typed, immutable deployment plan exchanged between control plane and agent.

The agent only ever executes a `DeploymentPlan`. There is no "run this command"
message type in the protocol. Secret *values* never appear in a plan: the plan
carries references, and values travel separately in the task envelope.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    SerializationInfo,
    field_serializer,
    field_validator,
)

from .naming import is_digest, is_env_var_name, is_slug, split_image_ref
from .states import DeploymentState

PLAN_SCHEMA_VERSION = 1


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SecretMount(_Frozen):
    variable: str
    ref: str
    file_name: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,99}$")

    @field_validator("variable")
    @classmethod
    def _var(cls, v: str) -> str:
        if not is_env_var_name(v):
            raise ValueError("invalid variable name")
        return v


class HealthProbe(_Frozen):
    path: str
    port: int = Field(ge=1, le=65535)
    interval_seconds: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)
    start_period_seconds: int = Field(ge=0)
    retries: int = Field(ge=1)


class RoutePlan(_Frozen):
    host: str
    path_prefix: str
    tls: bool


class VolumePlan(_Frozen):
    name: str
    mount_path: str
    read_only: bool


class ServicePlan(_Frozen):
    name: str
    image: str  # registry/path@sha256:...
    digest: str
    platform: str
    command: list[str] | None
    internal_port: int | None
    replicas: int = Field(ge=0, le=20)
    env: dict[str, str]
    secrets: list[SecretMount]
    healthcheck: HealthProbe | None
    memory_bytes: int = Field(ge=16 * 1024**2)
    cpus: float = Field(gt=0)
    pids: int = Field(ge=16)
    routes: list[RoutePlan]
    volumes: list[VolumePlan]
    tmpfs: list[str]
    read_only: bool
    user: str | None
    health_timeout_seconds: int
    drain_timeout_seconds: int

    @field_validator("image")
    @classmethod
    def _image(cls, v: str) -> str:
        split_image_ref(v)  # raises unless pinned by digest
        return v

    @field_validator("digest")
    @classmethod
    def _digest(cls, v: str) -> str:
        if not is_digest(v):
            raise ValueError("invalid digest")
        return v


class ReleaseRef(_Frozen):
    id: str
    version: str
    commit_sha: str


class PreviousRelease(_Frozen):
    deployment_id: str
    release_version: str
    digests: dict[str, str]


class DeploymentPlan(_Frozen):
    schema_version: Literal[1] = 1
    plan_id: str
    deployment_id: str
    host_id: str
    organization: str
    project: str
    environment: str
    compose_project: str
    strategy: Literal["recreate"]
    release: ReleaseRef
    services: list[ServicePlan] = Field(min_length=1)
    previous: PreviousRelease | None
    allowed_registries: list[str]
    created_at: datetime

    @field_validator("organization", "project", "environment")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not is_slug(v):
            raise ValueError("not a slug")
        return v

    def canonical_json(self) -> bytes:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json()).hexdigest()


# ----------------------------------------------------------------- agent wire protocol


class AgentTask(_Frozen):
    task_id: str
    kind: Literal["deploy"]
    attempt: int
    plan: DeploymentPlan
    plan_sha256: str
    secrets: dict[str, SecretStr]  # secret ref -> value, scoped to this plan only
    lease_seconds: int

    @field_serializer("secrets")
    def _secrets(self, value: dict[str, SecretStr], info: SerializationInfo) -> dict[str, str]:
        # Masked by default (logs, reprs, accidental dumps); revealed only for the agent wire format.
        reveal = bool(info.context and info.context.get("reveal_secrets"))
        return {k: (v.get_secret_value() if reveal else "**********") for k, v in value.items()}

    def wire_json(self) -> dict[str, object]:
        return self.model_dump(mode="json", context={"reveal_secrets": True})


class ClaimResponse(BaseModel):
    task: AgentTask | None


class TaskEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: DeploymentState
    message: Annotated[str, Field(max_length=4000)] = ""
    log: Annotated[str, Field(max_length=64_000)] = ""


class TaskResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: Literal["succeeded", "failed", "rolled_back"]
    running_digests: dict[str, str] = Field(default_factory=dict)
    error: Annotated[str, Field(max_length=4000)] | None = None


class HostFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_version: str
    docker_version: str | None = None
    compose_version: str | None = None
    architecture: str | None = None
    cpus: int | None = None
    memory_bytes: int | None = None
