from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="UDEPLOY_", env_file=".env", extra="ignore")

    environment: str = "production"
    database_url: str = "postgresql+asyncpg://udeploy:udeploy@localhost:5432/udeploy"
    redis_url: str = "redis://localhost:6379/0"
    # `kid:base64(32 bytes)[,kid:...]` - first key is active. Generate with `udeploy-admin gen-master-key`.
    master_keys: SecretStr = SecretStr("")
    public_base_url: str = "http://localhost:8000"
    agent_api_url: str = "https://localhost:8443"
    pki_dir: Path = Path("/var/lib/udeploy/pki")
    # Hostnames applications may never claim (the control plane's own domains).
    reserved_hosts: list[str] = Field(default_factory=list)

    webhook_max_body_bytes: int = 1024 * 1024
    api_max_body_bytes: int = 2 * 1024 * 1024
    webhook_rate_limit_per_minute: int = 600
    auth_failure_limit_per_minute: int = 30
    delivery_retention_days: int = 30

    agent_lease_seconds: int = 60
    agent_offline_after_seconds: int = 90
    agent_long_poll_seconds: int = 25
    agent_cert_days: int = 90
    task_max_attempts: int = 3
    deployment_stuck_after_seconds: int = 1800
    enroll_token_ttl_seconds: int = 3600

    release_verify_max_retries: int = 6
    release_verify_backoff_seconds: int = 5
    outbox_batch_size: int = 100
    docs_enabled: bool = True
    log_level: str = "INFO"
    log_json: bool = True

    @property
    def ca_key_path(self) -> Path:
        return self.pki_dir / "ca.key"

    @property
    def ca_cert_path(self) -> Path:
        return self.pki_dir / "ca.crt"


@lru_cache
def get_settings() -> Settings:
    return Settings()
