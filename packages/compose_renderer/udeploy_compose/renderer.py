"""Deterministic, hardened Compose V2 + Traefik dynamic configuration rendering.

The output is generated exclusively from a validated `DeploymentPlan`; a
repository's own docker-compose.yml is never executed. Every service gets the
same hardening baseline and there is no input field that can switch it off
except `read_only` (which the policy can forbid).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import yaml

from udeploy_domain.plan import DeploymentPlan, ServicePlan

LABEL_PREFIX = "io.udeploy"
SECRETS_TARGET_DIR = "/run/secrets"


@dataclass(frozen=True)
class HostLayout:
    """Host-specific settings owned by the agent, never by the plan."""

    secrets_dir: str  # <secrets_dir>/<compose_project>/<deployment_id>/<service>/<file>
    log_max_size: str = "10m"
    log_max_file: int = 3
    nofile_limit: int = 65536
    tmpfs_size: str = "64m"
    cert_resolver: str | None = "letsencrypt"
    https_entrypoint: str = "websecure"
    http_entrypoint: str = "web"


def backend_network(compose_project: str) -> str:
    return f"{compose_project}_backend"


def edge_network(compose_project: str) -> str:
    return f"{compose_project}_edge"


def volume_name(compose_project: str, volume: str) -> str:
    return f"{compose_project}_{volume}"


def secret_host_path(layout: HostLayout, plan: DeploymentPlan, service: str, file_name: str) -> str:
    # Per deployment: a rollback re-uses the exact secret values of the release it restores.
    return str(
        PurePosixPath(layout.secrets_dir) / plan.compose_project / plan.deployment_id / service / file_name
    )


def labels_for(plan: DeploymentPlan, svc: ServicePlan | None = None) -> dict[str, str]:
    labels = {
        f"{LABEL_PREFIX}.managed": "true",
        f"{LABEL_PREFIX}.organization": plan.organization,
        f"{LABEL_PREFIX}.project": plan.project,
        f"{LABEL_PREFIX}.environment": plan.environment,
        f"{LABEL_PREFIX}.deployment": plan.deployment_id,
        f"{LABEL_PREFIX}.release": plan.release.version,
        f"{LABEL_PREFIX}.commit": plan.release.commit_sha,
    }
    if svc is not None:
        labels[f"{LABEL_PREFIX}.service"] = svc.name
        labels[f"{LABEL_PREFIX}.digest"] = svc.digest
    return dict(sorted(labels.items()))


def _service(plan: DeploymentPlan, svc: ServicePlan, layout: HostLayout) -> dict[str, Any]:
    env = dict(svc.env)
    for secret in svc.secrets:
        # Values are files; the application reads <VAR>_FILE (12-factor convention).
        env[f"{secret.variable}_FILE"] = f"{SECRETS_TARGET_DIR}/{secret.file_name}"
    networks: dict[str, Any] = {"backend": {"aliases": [svc.name]}}
    if svc.routes:
        networks["edge"] = {}
    volumes: list[dict[str, Any]] = [
        {"type": "volume", "source": v.name, "target": v.mount_path, "read_only": v.read_only}
        for v in svc.volumes
    ]
    out: dict[str, Any] = {
        "image": svc.image,
        "platform": svc.platform,
        "pull_policy": "never",  # the agent pulls by digest and verifies before `up`
        "restart": "unless-stopped",
        "init": True,
        "read_only": svc.read_only,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": svc.memory_bytes,
        "memswap_limit": svc.memory_bytes,
        "cpus": svc.cpus,
        "pids_limit": svc.pids,
        "ulimits": {"nofile": {"soft": layout.nofile_limit, "hard": layout.nofile_limit}},
        "tmpfs": [f"{p}:rw,noexec,nosuid,nodev,size={layout.tmpfs_size}" for p in svc.tmpfs],
        "logging": {
            "driver": "json-file",
            "options": {"max-size": layout.log_max_size, "max-file": str(layout.log_max_file)},
        },
        "stop_grace_period": f"{max(svc.drain_timeout_seconds, 1)}s",
        "environment": dict(sorted(env.items())),
        "networks": networks,
        "labels": labels_for(plan, svc),
        "deploy": {"replicas": svc.replicas},
    }
    if svc.command:
        out["command"] = list(svc.command)
    if svc.user:
        out["user"] = svc.user
    if volumes:
        out["volumes"] = volumes
    if svc.secrets:
        out["secrets"] = [
            {"source": f"{svc.name}__{s.file_name}", "target": s.file_name} for s in svc.secrets
        ]
    return out


def render_compose(plan: DeploymentPlan, layout: HostLayout) -> dict[str, Any]:
    services = {svc.name: _service(plan, svc, layout) for svc in sorted(plan.services, key=lambda s: s.name)}
    networks: dict[str, Any] = {
        "backend": {
            "name": backend_network(plan.compose_project),
            "driver": "bridge",
            "labels": labels_for(plan),
        }
    }
    if any(svc.routes for svc in plan.services):
        networks["edge"] = {
            "name": edge_network(plan.compose_project),
            "driver": "bridge",
            "labels": labels_for(plan),
        }
    doc: dict[str, Any] = {"name": plan.compose_project, "services": services, "networks": networks}
    volumes = sorted({v.name for svc in plan.services for v in svc.volumes})
    if volumes:
        # External: compose can never delete them (no `down -v` accident possible).
        doc["volumes"] = {
            v: {"name": volume_name(plan.compose_project, v), "external": True} for v in volumes
        }
    secrets = {
        f"{svc.name}__{s.file_name}": {"file": secret_host_path(layout, plan, svc.name, s.file_name)}
        for svc in plan.services
        for s in svc.secrets
    }
    if secrets:
        doc["secrets"] = dict(sorted(secrets.items()))
    return doc


def dump_yaml(doc: dict[str, Any]) -> str:
    return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False, width=1000)


def _rule(host: str, prefix: str) -> str:
    rule = f"Host(`{host}`)"
    if prefix and prefix != "/":
        rule += f" && PathPrefix(`{prefix}`)"
    return rule


def render_traefik_routes(
    plan: DeploymentPlan, containers: dict[str, list[str]], layout: HostLayout
) -> dict[str, Any]:
    """Traefik file-provider config pointing at the concrete, healthy containers.

    `containers` maps service name -> container names on the project's edge network.
    """
    routers: dict[str, Any] = {}
    tservices: dict[str, Any] = {}
    middlewares: dict[str, Any] = {
        f"{plan.compose_project}-secure-headers": {
            "headers": {
                "frameDeny": True,
                "contentTypeNosniff": True,
                "browserXssFilter": True,
                "referrerPolicy": "strict-origin-when-cross-origin",
                "stsSeconds": 31536000,
                "stsIncludeSubdomains": True,
            }
        }
    }
    for svc in sorted(plan.services, key=lambda s: s.name):
        if not svc.routes or svc.internal_port is None:
            continue
        names = sorted(containers.get(svc.name, []))
        if not names:
            continue
        service_key = f"{plan.compose_project}-{svc.name}"
        tservices[service_key] = {
            "loadBalancer": {
                "passHostHeader": True,
                "servers": [{"url": f"http://{name}:{svc.internal_port}"} for name in names],
            }
        }
        for idx, route in enumerate(svc.routes):
            router: dict[str, Any] = {
                "rule": _rule(route.host, route.path_prefix),
                "service": service_key,
                "entryPoints": [layout.https_entrypoint if route.tls else layout.http_entrypoint],
                "middlewares": [f"{plan.compose_project}-secure-headers"],
            }
            if route.tls:
                router["tls"] = {"certResolver": layout.cert_resolver} if layout.cert_resolver else {}
            routers[f"{service_key}-{idx}"] = router
    if not routers:
        return {}
    return {"http": {"routers": routers, "services": tservices, "middlewares": middlewares}}
