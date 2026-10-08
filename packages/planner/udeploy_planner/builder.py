"""Pure construction of a DeploymentPlan from configuration snapshots."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from udeploy_domain.manifest import ServiceSpec
from udeploy_domain.naming import compose_project_name, image_ref_by_digest
from udeploy_domain.plan import (
    DeploymentPlan,
    HealthProbe,
    PreviousRelease,
    ReleaseRef,
    RoutePlan,
    SecretMount,
    ServicePlan,
    VolumePlan,
)

from .policy import SUPPORTED_STRATEGIES, PlanRejected


@dataclass(frozen=True)
class ArtifactRef:
    registry_host: str
    repository_path: str
    digest: str
    platform: str


@dataclass(frozen=True)
class PlanInputs:
    plan_id: str
    deployment_id: str
    host_id: str
    organization: str
    project: str
    environment: str
    release: ReleaseRef
    services: Mapping[str, ServiceSpec]
    routes: Mapping[str, list[RoutePlan]]
    artifacts: Mapping[str, ArtifactRef]
    previous: PreviousRelease | None
    previous_artifacts: Mapping[str, ArtifactRef]
    allowed_registries: frozenset[str]
    available_secrets: frozenset[str]


def _secret_file_name(variable: str) -> str:
    return variable.lower()


def build_plan(inputs: PlanInputs, *, now: datetime | None = None) -> DeploymentPlan:
    errors: list[str] = []
    services: list[ServicePlan] = []
    strategies = {spec.deploy.strategy for spec in inputs.services.values()}
    unsupported = strategies - SUPPORTED_STRATEGIES
    if unsupported:
        raise PlanRejected(f"unsupported strategies {sorted(unsupported)}")

    for name in sorted(inputs.services):
        spec = inputs.services[name]
        artifact = inputs.artifacts.get(name) or inputs.previous_artifacts.get(name)
        if artifact is None:
            errors.append(f"{name}: the release has no artifact and nothing is deployed yet")
            continue
        if artifact.registry_host not in inputs.allowed_registries:
            errors.append(f"{name}: registry {artifact.registry_host} is not approved for this organization")
            continue
        if artifact.platform != spec.platform:
            errors.append(f"{name}: artifact platform {artifact.platform} != requested {spec.platform}")
            continue
        missing = sorted(ref for ref in spec.secret_refs.values() if ref not in inputs.available_secrets)
        if missing:
            errors.append(f"{name}: secrets not provisioned in {inputs.environment}: {missing}")
            continue
        hc = spec.healthcheck
        services.append(
            ServicePlan(
                name=name,
                image=image_ref_by_digest(artifact.registry_host, artifact.repository_path, artifact.digest),
                digest=artifact.digest,
                platform=artifact.platform,
                command=list(spec.command) if spec.command else None,
                internal_port=spec.internal_port,
                replicas=spec.replicas,
                env=dict(sorted(spec.env.items())),
                secrets=[
                    SecretMount(variable=var, ref=ref, file_name=_secret_file_name(var))
                    for var, ref in sorted(spec.secret_refs.items())
                ],
                healthcheck=HealthProbe(
                    path=hc.path,
                    port=spec.internal_port or 0,
                    interval_seconds=hc.interval_seconds,
                    timeout_seconds=hc.timeout_seconds,
                    start_period_seconds=hc.start_period_seconds,
                    retries=hc.retries,
                )
                if hc and spec.internal_port
                else None,
                memory_bytes=spec.resources.memory_bytes,
                cpus=spec.resources.cpus,
                pids=spec.resources.pids,
                routes=list(inputs.routes.get(name, [])),
                volumes=[
                    VolumePlan(name=v.name, mount_path=v.mount_path, read_only=v.read_only)
                    for v in spec.volumes
                ],
                tmpfs=list(spec.tmpfs),
                read_only=spec.read_only_root_filesystem,
                user=spec.user,
                health_timeout_seconds=spec.deploy.health_timeout_seconds,
                drain_timeout_seconds=spec.deploy.drain_timeout_seconds,
            )
        )
    if errors:
        raise PlanRejected("; ".join(errors))
    return DeploymentPlan(
        plan_id=inputs.plan_id,
        deployment_id=inputs.deployment_id,
        host_id=inputs.host_id,
        organization=inputs.organization,
        project=inputs.project,
        environment=inputs.environment,
        compose_project=compose_project_name(inputs.organization, inputs.project, inputs.environment),
        strategy="recreate",
        release=inputs.release,
        services=services,
        previous=inputs.previous,
        allowed_registries=sorted(inputs.allowed_registries),
        created_at=now or datetime.now(UTC),
    )
