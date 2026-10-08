"""infra/backup/backup.sh + restore.sh round trip on a real Docker volume."""

from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.integration]
ROOT = Path(__file__).resolve().parents[2]


def sh(*args: str) -> str:
    res = subprocess.run(list(args), capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"{args}: {res.stdout}{res.stderr}"
    return res.stdout.strip()


def test_volume_backup_and_restore(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    vol = f"udeploy-test-{uuid.uuid4().hex[:8]}_data"
    sh("docker", "volume", "create", "--label", "io.udeploy.managed=true", vol)
    try:
        sh(
            "docker",
            "run",
            "--rm",
            "-v",
            f"{vol}:/data",
            "busybox:1.37",
            "sh",
            "-c",
            "mkdir -p /data/sub && echo precious > /data/sub/file.txt",
        )
        out = sh(str(ROOT / "infra/backup/backup.sh"), "--out", str(tmp_path), "--volumes")
        assert vol in out
        archive = next(tmp_path.glob(f"*/volume-{vol}.tgz"))
        sums = (archive.parent / "SHA256SUMS").read_text()
        assert archive.name in sums

        sh("docker", "volume", "rm", vol)  # disaster
        sh(str(ROOT / "infra/backup/restore.sh"), "--volume", vol, str(archive))
        restored = sh(
            "docker", "run", "--rm", "-v", f"{vol}:/data:ro", "busybox:1.37", "cat", "/data/sub/file.txt"
        )
        assert restored == "precious"
        labels = sh("docker", "volume", "inspect", vol, "--format", "{{json .Labels}}")
        assert "io.udeploy.managed" in labels
    finally:
        subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True, check=False)
