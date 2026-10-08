"""Secret storage behind a provider interface.

`LocalEncryptedSecrets` stores AES-256-GCM ciphertexts in PostgreSQL, each bound
(AAD) to its organization/project/environment/path. Values are write-only
through the API: there is no endpoint returning a value; only the agent task
envelope of a deployment of *that* environment carries them.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from udeploy_security.crypto import SecretBox

from ..models import Environment, Project, SecretValue


class SecretProvider(Protocol):
    async def available_paths(self, environment_id: uuid.UUID) -> frozenset[str]: ...

    async def resolve(self, environment: Environment, project: Project, refs: set[str]) -> dict[str, str]: ...


def secret_aad(org_id: uuid.UUID, project_id: uuid.UUID, env_id: uuid.UUID, path: str) -> str:
    return f"udeploy:secret:v1:{org_id}:{project_id}:{env_id}:{path}"


class LocalEncryptedSecrets:
    def __init__(self, session: AsyncSession, box: SecretBox) -> None:
        self.session = session
        self.box = box

    async def put(self, project: Project, environment: Environment, path: str, value: str) -> SecretValue:
        if environment.project_id != project.id:
            raise ValueError("environment does not belong to project")
        aad = secret_aad(project.organization_id, project.id, environment.id, path)
        ciphertext = self.box.encrypt(value.encode(), aad)
        existing = await self.session.scalar(
            select(SecretValue).where(SecretValue.environment_id == environment.id, SecretValue.path == path)
        )
        if existing:
            existing.ciphertext = ciphertext
            existing.version += 1
            return existing
        row = SecretValue(
            organization_id=project.organization_id,
            project_id=project.id,
            environment_id=environment.id,
            path=path,
            ciphertext=ciphertext,
        )
        self.session.add(row)
        return row

    async def available_paths(self, environment_id: uuid.UUID) -> frozenset[str]:
        rows = await self.session.scalars(
            select(SecretValue.path).where(SecretValue.environment_id == environment_id)
        )
        return frozenset(rows.all())

    async def resolve(self, environment: Environment, project: Project, refs: set[str]) -> dict[str, str]:
        if not refs:
            return {}
        rows = (
            await self.session.scalars(
                select(SecretValue).where(
                    SecretValue.environment_id == environment.id,
                    SecretValue.project_id == project.id,
                    SecretValue.path.in_(refs),
                )
            )
        ).all()
        out: dict[str, str] = {}
        for row in rows:
            aad = secret_aad(project.organization_id, project.id, environment.id, row.path)
            out[row.path] = self.box.decrypt(row.ciphertext, aad).decode()
        missing = refs - set(out)
        if missing:
            raise KeyError(f"missing secrets: {sorted(missing)}")
        return out
