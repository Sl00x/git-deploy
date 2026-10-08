"""Apply an approved Application manifest to the project's stored configuration."""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from udeploy_domain.manifest import ApplicationManifest
from udeploy_domain.naming import image_repository_name
from udeploy_planner.policy import PlatformPolicy, validate_manifest

from ..errors import Conflict, PolicyViolation
from ..models import Environment, Organization, Project, Registry, Route, Service
from ..settings import Settings


async def platform_policy(session: AsyncSession, org: Organization, settings: Settings) -> PlatformPolicy:
    hosts = (await session.scalars(select(Registry.host).where(Registry.organization_id == org.id))).all()
    return PlatformPolicy(
        allowed_registries=frozenset(hosts),
        allowed_route_domains=frozenset(d.lower() for d in org.allowed_domains or []),
        reserved_hosts=frozenset(h.lower() for h in settings.reserved_hosts),
    )


async def apply_manifest(
    session: AsyncSession, project: Project, raw: dict[str, Any], settings: Settings
) -> ApplicationManifest:
    org = project.organization
    policy = await platform_policy(session, org, settings)
    try:
        manifest = validate_manifest(raw, policy)
    except ValueError as exc:
        errors = getattr(exc, "errors", [str(exc)])
        raise PolicyViolation("manifest rejected", details=errors) from exc

    if manifest.project != project.slug:
        raise PolicyViolation("manifest.project does not match the project slug")
    if (
        manifest.source.provider != project.source_provider
        or manifest.source.repository != project.repository
    ):
        raise PolicyViolation("manifest.source does not match the repository registered for this project")
    registry = await session.scalar(
        select(Registry).where(
            Registry.organization_id == org.id, Registry.name == manifest.build.registry_ref
        )
    )
    if registry is None:
        raise PolicyViolation(
            f"registryRef {manifest.build.registry_ref!r} is not a registry of this organization"
        )

    # --- services
    existing = {
        s.name: s for s in (await session.scalars(select(Service).where(Service.project_id == project.id)))
    }
    for name, spec in manifest.services.items():
        image = image_repository_name(
            spec.image_name, repository=project.repository, service=name, project=project.slug
        )
        dumped = spec.model_dump(mode="json", by_alias=True)
        if name in existing:
            existing[name].spec = dumped
            existing[name].image_repository = image
        else:
            svc = Service(project_id=project.id, name=name, image_repository=image, spec=dumped)
            session.add(svc)
            existing[name] = svc
    for name in set(existing) - set(manifest.services):
        await session.delete(existing.pop(name))
    await session.flush()

    # --- environments
    envs = {
        e.name: e
        for e in (await session.scalars(select(Environment).where(Environment.project_id == project.id)))
    }
    for env_name, target in manifest.targets.items():
        rule = manifest.release.environments.get(env_name)
        env = envs.get(env_name)
        if env is None:
            env = Environment(project_id=project.id, name=env_name, host_pool=target.host_pool)
            session.add(env)
            envs[env_name] = env
        if env.pinned_host_id is not None and env.host_pool != target.host_pool:
            raise Conflict(f"environment {env_name} is pinned to a host; moving pools is not automatic")
        env.host_pool = target.host_pool
        env.branches = list(rule.branches) if rule else []
        env.tags = list(rule.tags) if rule else []
        env.auto_deploy = bool(rule and rule.auto_deploy)
        env.require_approval = bool(rule and rule.require_approval)
    # Environments removed from the manifest are kept (they may hold data volumes); they get no routes.
    await session.flush()

    # --- routes (platform-wide unique host+path)
    env_ids = [e.id for e in envs.values()]
    await session.execute(delete(Route).where(Route.environment_id.in_(env_ids)))
    await session.flush()
    for env_name, env in envs.items():
        if env_name not in manifest.targets:
            continue
        for svc_name in manifest.services:
            for route in manifest.routes_for(svc_name, env_name):
                clash = await session.scalar(
                    select(Route).where(Route.host == route.host, Route.path_prefix == route.path_prefix)
                )
                if clash is not None:
                    raise Conflict(
                        f"route {route.host}{route.path_prefix} is already claimed by another project"
                    )
                session.add(
                    Route(
                        environment_id=env.id,
                        service_id=existing[svc_name].id,
                        host=route.host,
                        path_prefix=route.path_prefix,
                        tls=route.tls,
                    )
                )
    await session.flush()
    project.manifest = manifest.model_dump(mode="json", by_alias=True)
    project.manifest_version += 1
    return manifest
