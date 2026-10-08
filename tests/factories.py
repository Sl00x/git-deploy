"""Shared builders for tests."""

from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime
from typing import Any

from udeploy_domain.manifest import ServiceSpec
from udeploy_domain.plan import DeploymentPlan, ReleaseRef, RoutePlan
from udeploy_planner.builder import ArtifactRef, PlanInputs, build_plan

COMMIT = "a" * 40
COMMIT_B = "b" * 40


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def manifest(
    project: str = "inkerflow",
    repository: str = "group/inkerflow",
    provider: str = "gitlab",
    domain: str = "inkerflow.example",
    *,
    registry_ref: str = "registry-production",
    require_scan: bool = True,
    staging_auto: bool = True,
    production_approval: bool = True,
) -> dict[str, Any]:
    return {
        "apiVersion": "deploy.udeploy.io/v1",
        "kind": "Application",
        "project": project,
        "source": {"provider": provider, "repository": repository, "defaultBranch": "main"},
        "build": {"mode": "external_ci", "tagTemplate": "{semver}", "registryRef": registry_ref},
        "release": {
            "trigger": "artifact_published",
            "requireRegistryDigest": True,
            "requireSignedArtifact": False,
            "requireScanPass": require_scan,
            "environments": {
                "staging": {"branches": ["develop", "main"], "autoDeploy": staging_auto},
                "production": {"tags": ["v*"], "autoDeploy": False, "requireApproval": production_approval},
            },
        },
        "services": {
            "api": {
                "internalPort": 8000,
                "replicas": 2,
                "healthcheck": {"path": "/health/ready", "intervalSeconds": 2},
                "resources": {"memory": "256m", "cpus": 0.5, "pids": 128},
                "env": {"APP_ENV": "production"},
                "secretRefs": {"DATABASE_URL": f"{project}/database-url"},
                "routes": [
                    {"host": f"api.{domain}", "environments": ["production"]},
                    {"host": f"api.staging.{domain}", "environments": ["staging"]},
                ],
                "volumes": [{"name": "uploads", "mountPath": "/data/uploads"}],
                "user": "1000:1000",
            },
            "worker": {"command": ["celery", "-A", "app", "worker"], "replicas": 1},
            "frontend": {
                "internalPort": 80,
                "routes": [
                    {"host": domain, "environments": ["production"]},
                    {"host": f"staging.{domain}", "environments": ["staging"]},
                ],
            },
        },
        "targets": {
            "staging": {"hostPool": "staging-docker"},
            "production": {"hostPool": "production-docker"},
        },
    }


def hostile(base: dict[str, Any]) -> dict[str, Any]:
    m = copy.deepcopy(base)
    api = m["services"]["api"]
    api["privileged"] = True
    api["network_mode"] = "host"
    api["cap_add"] = ["SYS_ADMIN"]
    api["volumes"] = ["/var/run/docker.sock:/var/run/docker.sock", "/:/host"]
    api["pid"] = "host"
    api["ports"] = ["22:22"]
    return m


def plan(
    *,
    host_id: str = "host-1",
    registry: str = "registry.example.com",
    deployment_id: str = "dep-1",
    with_previous: bool = False,
) -> DeploymentPlan:
    m = manifest()
    services = {k: ServiceSpec.model_validate(v) for k, v in m["services"].items()}
    artifacts = {
        name: ArtifactRef(registry, f"prod/inkerflow_{name}", digest(name), "linux/amd64")
        for name in services
    }
    return build_plan(
        PlanInputs(
            plan_id="plan-1",
            deployment_id=deployment_id,
            host_id=host_id,
            organization="acme",
            project="inkerflow",
            environment="production",
            release=ReleaseRef(id="rel-1", version="1.5.0", commit_sha=COMMIT),
            services=services,
            routes={
                "api": [RoutePlan(host="api.inkerflow.example", path_prefix="/", tls=True)],
                "frontend": [RoutePlan(host="inkerflow.example", path_prefix="/", tls=True)],
            },
            artifacts=artifacts,
            previous=None,
            previous_artifacts={},
            allowed_registries=frozenset({registry}),
            available_secrets=frozenset({"inkerflow/database-url"}),
        ),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
