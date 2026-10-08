"""Thin, allow-listed wrapper around the Docker CLI.

Only the operations below exist. Arguments are passed as argv (never through a
shell) and every value has been validated upstream by the plan schema/policy.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("udeploy.agent.docker")


class DockerError(Exception):
    def __init__(self, message: str, output: str = "") -> None:
        super().__init__(message)
        self.output = output


@dataclass(frozen=True)
class ContainerInfo:
    name: str
    service: str
    state: str
    health: str


class DockerCLI:
    def __init__(self, binary: str = "docker") -> None:
        self.binary = binary

    async def _run(self, *args: str, timeout: float = 300, check: bool = True) -> tuple[int, str]:
        proc = await asyncio.create_subprocess_exec(
            self.binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise DockerError(f"docker {args[0]} timed out after {timeout}s") from exc
        text = out.decode(errors="replace")
        if check and proc.returncode != 0:
            raise DockerError(f"docker {' '.join(args[:2])} failed (exit {proc.returncode})", text[-8000:])
        return proc.returncode or 0, text

    async def version(self) -> str | None:
        try:
            _, out = await self._run("version", "--format", "{{.Server.Version}}", timeout=20)
            return out.strip()
        except DockerError:
            return None

    async def compose_version(self) -> str | None:
        try:
            _, out = await self._run("compose", "version", "--short", timeout=20)
            return out.strip()
        except DockerError:
            return None

    async def pull(self, image: str, platform: str) -> str:
        _, out = await self._run("pull", "--quiet", "--platform", platform, image, timeout=1800)
        return out

    async def image_repo_digests(self, image: str) -> list[str]:
        code, out = await self._run(
            "image", "inspect", "--format", "{{json .RepoDigests}}", image, check=False
        )
        if code != 0:
            return []
        value = json.loads(out.strip() or "[]")
        return [str(v) for v in value or []]

    async def image_present(self, image: str) -> bool:
        code, _ = await self._run("image", "inspect", "--format", "{{.Id}}", image, check=False, timeout=30)
        return code == 0

    async def volume_ensure(self, name: str, labels: dict[str, str]) -> None:
        code, _ = await self._run("volume", "inspect", name, check=False, timeout=30)
        if code == 0:
            return
        args = ["volume", "create"]
        for k, v in sorted(labels.items()):
            args += ["--label", f"{k}={v}"]
        await self._run(*args, name, timeout=60)

    async def network_connect(self, network: str, container: str) -> None:
        code, out = await self._run("network", "connect", network, container, check=False, timeout=60)
        if code != 0 and "already exists" not in out and "already attached" not in out:
            raise DockerError(f"cannot connect {container} to {network}", out)

    async def container_running(self, name: str) -> bool:
        code, out = await self._run(
            "inspect", "--format", "{{.State.Running}}", name, check=False, timeout=30
        )
        return code == 0 and out.strip() == "true"

    async def compose_up(self, project: str, compose_file: str) -> str:
        _, out = await self._run(
            "compose", "-p", project, "-f", compose_file, "up", "--detach", "--remove-orphans", timeout=900
        )
        return out

    async def compose_stop(self, project: str, compose_file: str) -> str:
        _, out = await self._run(
            "compose", "-p", project, "-f", compose_file, "stop", timeout=600, check=False
        )
        return out

    async def compose_ps(self, project: str, compose_file: str) -> list[ContainerInfo]:
        _, out = await self._run(
            "compose", "-p", project, "-f", compose_file, "ps", "--all", "--format", "json", timeout=60
        )
        items: list[dict[str, Any]] = []
        text = out.strip()
        if text.startswith("["):
            items = json.loads(text)
        else:
            items = [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]
        return [
            ContainerInfo(
                name=str(i.get("Name")),
                service=str(i.get("Service")),
                state=str(i.get("State", "")).lower(),
                health=str(i.get("Health", "")).lower(),
            )
            for i in items
        ]

    async def probe_http(
        self, *, probe_image: str, network: str, container: str, port: int, path: str, timeout: int
    ) -> tuple[bool, str]:
        """HTTP readiness probe from a throw-away, fully confined container on the
        project's private network. The target is built by the agent (container
        name + plan port + validated path): no user-supplied URL, no SSRF."""
        url = f"http://{container}:{port}{path}"
        code, out = await self._run(
            "run",
            "--rm",
            "--network",
            network,
            "--cap-drop",
            "ALL",
            "--read-only",
            "--security-opt",
            "no-new-privileges:true",
            "--memory",
            "32m",
            "--pids-limit",
            "32",
            "--user",
            "65534:65534",
            "--label",
            "io.udeploy.probe=true",
            probe_image,
            "wget",
            "-q",
            "-T",
            str(timeout),
            "-O",
            "/dev/null",
            url,
            check=False,
            timeout=timeout + 30,
        )
        return code == 0, out.strip()[-500:]
