"""Process-wide dependencies shared by the API, the agent API and the worker."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from udeploy_providers.registry import OCIRegistryClient, RegistryProvider
from udeploy_security.crypto import KeyRing, SecretBox

from .db import Database
from .models import Registry
from .settings import Settings

RegistryFactory = Callable[[Registry, SecretBox], RegistryProvider]


def default_registry_factory(registry: Registry, box: SecretBox) -> RegistryProvider:
    password = None
    if registry.password_ciphertext:
        password = box.decrypt(registry.password_ciphertext, registry_aad(registry)).decode()
    return OCIRegistryClient(
        registry.host, username=registry.username, password=password, insecure_http=registry.insecure_http
    )


def registry_aad(registry: Registry) -> str:
    return f"udeploy:registry:v1:{registry.organization_id}:{registry.id}"


def webhook_aad(endpoint_id: object, field_name: str) -> str:
    return f"udeploy:webhook:v1:{endpoint_id}:{field_name}"


@dataclass
class PKIMaterial:
    ca_key_pem: bytes
    ca_cert_pem: bytes

    @classmethod
    def load(cls, key_path: Path, cert_path: Path) -> PKIMaterial | None:
        if not key_path.exists() or not cert_path.exists():
            return None
        return cls(ca_key_pem=key_path.read_bytes(), ca_cert_pem=cert_path.read_bytes())


@dataclass
class AppContext:
    settings: Settings
    db: Database
    box: SecretBox
    pki: PKIMaterial | None
    registry_factory: RegistryFactory = field(default=default_registry_factory)
    redis_url: str | None = None

    @classmethod
    def from_settings(cls, settings: Settings, *, null_pool: bool = False) -> AppContext:
        spec = settings.master_keys.get_secret_value()
        if not spec:
            raise RuntimeError("UDEPLOY_MASTER_KEYS is not configured (see `udeploy-admin gen-master-key`)")
        return cls(
            settings=settings,
            db=Database.from_settings(settings, null_pool=null_pool),
            box=SecretBox(KeyRing.parse(spec)),
            pki=PKIMaterial.load(settings.ca_key_path, settings.ca_cert_path),
            redis_url=settings.redis_url,
        )
