from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


def _list(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


@dataclass
class AgentConfig:
    """Host-local configuration. Nothing here comes from the control plane except
    the identity files written during enrolment."""

    state_dir: Path = Path("/var/lib/udeploy-agent")
    # Must be the SAME absolute path on the host and inside the agent container:
    # the Docker daemon resolves compose `secrets.file` paths on the host.
    secrets_dir: Path = Path("/var/lib/udeploy-agent/secrets")
    allowed_registries: list[str] = field(default_factory=list)
    traefik_container: str = "udeploy-traefik"
    traefik_dynamic_dir: Path = Path("/var/lib/udeploy-agent/traefik")
    cert_resolver: str | None = "letsencrypt"
    probe_image: str = "busybox:1.37"
    docker_bin: str = "docker"
    heartbeat_seconds: int = 15
    keep_releases: int = 5
    max_memory_bytes: int = 32 * 1024**3

    @classmethod
    def from_env(cls) -> AgentConfig:
        env = os.environ
        state = Path(env.get("UDEPLOY_AGENT_STATE_DIR", "/var/lib/udeploy-agent"))
        return cls(
            state_dir=state,
            secrets_dir=Path(env.get("UDEPLOY_AGENT_SECRETS_DIR", str(state / "secrets"))),
            allowed_registries=_list(env.get("UDEPLOY_AGENT_ALLOWED_REGISTRIES")),
            traefik_container=env.get("UDEPLOY_AGENT_TRAEFIK_CONTAINER", "udeploy-traefik"),
            traefik_dynamic_dir=Path(env.get("UDEPLOY_AGENT_TRAEFIK_DYNAMIC_DIR", str(state / "traefik"))),
            cert_resolver=env.get("UDEPLOY_AGENT_CERT_RESOLVER", "letsencrypt") or None,
            probe_image=env.get("UDEPLOY_AGENT_PROBE_IMAGE", "busybox:1.37"),
            docker_bin=env.get("UDEPLOY_AGENT_DOCKER_BIN", "docker"),
            heartbeat_seconds=int(env.get("UDEPLOY_AGENT_HEARTBEAT_SECONDS", "15")),
            keep_releases=int(env.get("UDEPLOY_AGENT_KEEP_RELEASES", "5")),
        )

    # ---- identity files (written by `udeploy-agent enroll`)
    @property
    def identity_dir(self) -> Path:
        return self.state_dir / "identity"

    @property
    def key_path(self) -> Path:
        return self.identity_dir / "agent.key"

    @property
    def cert_path(self) -> Path:
        return self.identity_dir / "agent.crt"

    @property
    def ca_path(self) -> Path:
        return self.identity_dir / "ca.crt"

    @property
    def identity_file(self) -> Path:
        return self.identity_dir / "identity.json"

    def load_identity(self) -> dict[str, str]:
        data: dict[str, str] = json.loads(self.identity_file.read_text())
        return data

    @property
    def projects_dir(self) -> Path:
        return self.state_dir / "projects"
