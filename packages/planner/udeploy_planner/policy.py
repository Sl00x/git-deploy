"""Server-side, deny-by-default runtime policy.

Applied twice: by the control plane when a manifest is registered / a plan is
built, and again by the agent before it touches Docker (defense in depth: a
compromised control-plane database must not be enough to run a privileged
container).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from udeploy_domain.manifest import ApplicationManifest
from udeploy_domain.naming import NamingError, compose_project_name, split_image_ref
from udeploy_domain.plan import DeploymentPlan

SUPPORTED_STRATEGIES: frozenset[str] = frozenset({"recreate"})

# Keys that express host-level privileges in Docker/Compose/Kubernetes vocabularies.
# They are rejected with an explicit message wherever they appear in a service.
FORBIDDEN_KEYS: Mapping[str, str] = {
    "privileged": "privileged containers are forbidden",
    "pid": "sharing the host PID namespace is forbidden",
    "ipc": "sharing the host IPC namespace is forbidden",
    "network_mode": "custom network modes (host networking) are forbidden",
    "networkmode": "custom network modes (host networking) are forbidden",
    "hostnetwork": "host networking is forbidden",
    "hostpid": "sharing the host PID namespace is forbidden",
    "hostipc": "sharing the host IPC namespace is forbidden",
    "userns_mode": "disabling user namespace remapping is forbidden",
    "usernsmode": "disabling user namespace remapping is forbidden",
    "devices": "device access is forbidden",
    "cap_add": "adding Linux capabilities is forbidden",
    "capadd": "adding Linux capabilities is forbidden",
    "security_opt": "overriding security options (seccomp/apparmor) is forbidden",
    "securityopt": "overriding security options (seccomp/apparmor) is forbidden",
    "ports": "publishing host ports is forbidden: expose services through routes",
    "hostport": "publishing host ports is forbidden: expose services through routes",
    "cgroup_parent": "custom cgroup parents are forbidden",
    "cgroupparent": "custom cgroup parents are forbidden",
    "hostpath": "host path mounts are forbidden",
    "bind": "host bind mounts are forbidden",
    "volumes_from": "volumes_from is forbidden",
    "sysctls": "sysctls are forbidden",
    "runtime": "selecting a container runtime is forbidden",
    "extra_hosts": "extra_hosts is forbidden",
}

DANGEROUS_VALUE_MARKERS: tuple[str, ...] = (
    "docker.sock",
    "/var/run/docker",
    "/run/containerd",
    "seccomp=unconfined",
    "apparmor=unconfined",
    "apparmor:unconfined",
)


class ManifestRejected(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


class PlanRejected(ValueError):
    pass


@dataclass(frozen=True)
class PlatformPolicy:
    allowed_registries: frozenset[str] = frozenset()
    allowed_route_domains: frozenset[str] = frozenset()
    reserved_hosts: frozenset[str] = frozenset()
    max_memory_bytes: int = 8 * 1024**3
    max_cpus: float = 8.0
    max_pids: int = 4096
    max_replicas: int = 10
    allow_root_user: bool = False
    allow_writable_rootfs: bool = True
    supported_strategies: frozenset[str] = field(default=SUPPORTED_STRATEGIES)


def _walk(node: Any, path: str) -> Iterable[tuple[str, Any, Any]]:
    if isinstance(node, Mapping):
        for key, value in node.items():
            yield f"{path}.{key}", key, value
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            yield f"{path}[{idx}]", None, value
            yield from _walk(value, f"{path}[{idx}]")


def scan_hostile(raw: Mapping[str, Any]) -> list[str]:
    """Explicit errors for privilege-escalation attempts in a raw manifest."""
    errors: list[str] = []
    services = raw.get("services")
    if not isinstance(services, Mapping):
        return errors
    for location, key, value in _walk(services, "services"):
        if isinstance(key, str):
            reason = FORBIDDEN_KEYS.get(key.lower().replace("-", "_")) or FORBIDDEN_KEYS.get(
                key.lower().replace("-", "").replace("_", "")
            )
            if reason:
                errors.append(f"{location}: {reason}")
        if isinstance(value, str):
            lowered = value.lower()
            for marker in DANGEROUS_VALUE_MARKERS:
                if marker in lowered:
                    errors.append(f"{location}: reference to {marker!r} is forbidden")
    return errors


def _format_validation(exc: ValidationError) -> list[str]:
    out = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        if err["type"] == "extra_forbidden":
            out.append(f"{loc}: unknown field (not allowed by the manifest schema)")
        else:
            out.append(f"{loc}: {err['msg']}")
    return out


def _domain_allowed(host: str, domains: frozenset[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def validate_manifest(raw: Mapping[str, Any], policy: PlatformPolicy) -> ApplicationManifest:
    errors = scan_hostile(raw)
    manifest: ApplicationManifest | None = None
    try:
        manifest = ApplicationManifest.model_validate(raw)
    except ValidationError as exc:
        errors.extend(_format_validation(exc))
    if manifest is None:
        raise ManifestRejected(errors or ["invalid manifest"])

    for name, svc in manifest.services.items():
        where = f"services.{name}"
        if svc.deploy.strategy not in policy.supported_strategies:
            errors.append(
                f"{where}.deploy.strategy: {svc.deploy.strategy!r} is not available in this release "
                f"(supported: {sorted(policy.supported_strategies)})"
            )
        if svc.resources.memory_bytes > policy.max_memory_bytes:
            errors.append(f"{where}.resources.memory exceeds the platform maximum")
        if svc.resources.cpus > policy.max_cpus:
            errors.append(f"{where}.resources.cpus exceeds the platform maximum")
        if svc.resources.pids > policy.max_pids:
            errors.append(f"{where}.resources.pids exceeds the platform maximum")
        if svc.replicas > policy.max_replicas:
            errors.append(f"{where}.replicas exceeds the platform maximum")
        if not policy.allow_root_user and svc.user is not None and svc.user.split(":")[0] == "0":
            errors.append(f"{where}.user: running as root (uid 0) is forbidden")
        if not policy.allow_writable_rootfs and not svc.read_only_root_filesystem:
            errors.append(f"{where}.readOnlyRootFilesystem: writable root filesystems are forbidden")
        for route in svc.routes:
            if route.host in policy.reserved_hosts:
                errors.append(f"{where}.routes: host {route.host} is reserved by the platform")
            elif not _domain_allowed(route.host, policy.allowed_route_domains):
                errors.append(f"{where}.routes: host {route.host} is outside the organization's domains")
    if errors:
        raise ManifestRejected(errors)
    return manifest


@dataclass(frozen=True)
class AgentPolicy:
    host_id: str
    allowed_registries: frozenset[str]  # local allow-list configured on the host itself
    max_memory_bytes: int = 32 * 1024**3
    allow_root_user: bool = False


def check_plan_for_agent(plan: DeploymentPlan, policy: AgentPolicy) -> None:
    """Re-validate a plan on the host before execution. Raises PlanRejected."""
    if plan.host_id != policy.host_id:
        raise PlanRejected(f"plan targets host {plan.host_id}, this agent is {policy.host_id}")
    if plan.strategy not in SUPPORTED_STRATEGIES:
        raise PlanRejected(f"unsupported strategy {plan.strategy}")
    expected = compose_project_name(plan.organization, plan.project, plan.environment)
    if plan.compose_project != expected:
        raise PlanRejected("compose project name does not match organization/project/environment")
    registries = set(plan.allowed_registries) & set(policy.allowed_registries)
    names = [s.name for s in plan.services]
    if len(names) != len(set(names)):
        raise PlanRejected("duplicate service names")
    for svc in plan.services:
        try:
            host, _path, digest = split_image_ref(svc.image)
        except NamingError as exc:
            raise PlanRejected(str(exc)) from exc
        if digest != svc.digest:
            raise PlanRejected(f"{svc.name}: image digest and declared digest differ")
        if host not in registries:
            raise PlanRejected(f"{svc.name}: registry {host} is not allowed on this host")
        if svc.memory_bytes > policy.max_memory_bytes:
            raise PlanRejected(f"{svc.name}: memory above host limit")
        if not policy.allow_root_user and svc.user is not None and svc.user.split(":")[0] == "0":
            raise PlanRejected(f"{svc.name}: root user forbidden")
        for value in [
            *(svc.command or []),
            *svc.env.values(),
            *svc.tmpfs,
            *(v.mount_path for v in svc.volumes),
        ]:
            if any(marker in value.lower() for marker in DANGEROUS_VALUE_MARKERS):
                raise PlanRejected(f"{svc.name}: forbidden reference in plan")
        refs = [s.ref for s in svc.secrets]
        if len(refs) != len(set(refs)):
            raise PlanRejected(f"{svc.name}: duplicate secret refs")
