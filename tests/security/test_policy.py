"""Hostile manifests and plans must be refused automatically."""

from __future__ import annotations

import pytest

from udeploy_planner.policy import (
    AgentPolicy,
    ManifestRejected,
    PlanRejected,
    PlatformPolicy,
    check_plan_for_agent,
    validate_manifest,
)

from ..factories import digest, hostile, manifest, plan

POLICY = PlatformPolicy(
    allowed_registries=frozenset({"registry.example.com"}),
    allowed_route_domains=frozenset({"inkerflow.example"}),
    reserved_hosts=frozenset({"deploy.inkerflow.example"}),
)


def test_valid_manifest_passes() -> None:
    assert validate_manifest(manifest(), POLICY).project == "inkerflow"


def test_hostile_repository_is_refused_with_explicit_reasons() -> None:
    with pytest.raises(ManifestRejected) as exc:
        validate_manifest(hostile(manifest()), POLICY)
    text = "\n".join(exc.value.errors)
    for expected in (
        "privileged containers are forbidden",
        "host networking",
        "adding Linux capabilities",
        "docker.sock",
        "host PID namespace",
        "publishing host ports",
    ):
        assert expected in text, expected
    # The bind of "/" is not expressible either: volumes must be named mappings.
    assert "services.api.volumes" in text


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("security_opt", ["seccomp=unconfined"]),
        ("devices", ["/dev/sda"]),
        ("ipc", "host"),
        ("userns_mode", "host"),
        ("hostNetwork", True),
        ("extra_hosts", ["a:1.2.3.4"]),
    ],
)
def test_each_dangerous_option_is_refused(key: str, value: object) -> None:
    raw = manifest()
    raw["services"]["worker"][key] = value
    with pytest.raises(ManifestRejected):
        validate_manifest(raw, POLICY)


def test_env_value_pointing_to_docker_socket_is_refused() -> None:
    raw = manifest()
    raw["services"]["worker"]["env"] = {"DOCKER_HOST": "unix:///var/run/docker.sock"}
    with pytest.raises(ManifestRejected, match="docker.sock"):
        validate_manifest(raw, POLICY)


def test_root_user_refused() -> None:
    raw = manifest()
    raw["services"]["api"]["user"] = "0:0"
    with pytest.raises(ManifestRejected, match="root"):
        validate_manifest(raw, POLICY)


def test_route_outside_org_domains_or_reserved() -> None:
    raw = manifest()
    raw["services"]["frontend"]["routes"][0]["host"] = "bank.example.org"
    with pytest.raises(ManifestRejected, match="outside the organization"):
        validate_manifest(raw, POLICY)
    raw = manifest()
    raw["services"]["frontend"]["routes"][0]["host"] = "deploy.inkerflow.example"
    with pytest.raises(ManifestRejected, match="reserved"):
        validate_manifest(raw, POLICY)


def test_unsupported_strategy_is_explicit() -> None:
    raw = manifest()
    raw["services"]["api"]["deploy"] = {"strategy": "blue_green"}
    with pytest.raises(ManifestRejected, match="not available in this release"):
        validate_manifest(raw, POLICY)


def test_resource_caps() -> None:
    raw = manifest()
    raw["services"]["api"]["resources"]["memory"] = "64g"
    with pytest.raises(ManifestRejected, match="memory"):
        validate_manifest(raw, POLICY)


class TestAgentSidePolicy:
    def policy(self, **kw: object) -> AgentPolicy:
        base: dict[str, object] = {
            "host_id": "host-1",
            "allowed_registries": frozenset({"registry.example.com"}),
        }
        base.update(kw)
        return AgentPolicy(**base)  # type: ignore[arg-type]

    def test_valid_plan(self) -> None:
        check_plan_for_agent(plan(), self.policy())

    def test_plan_for_another_host(self) -> None:
        with pytest.raises(PlanRejected, match="targets host"):
            check_plan_for_agent(plan(host_id="host-2"), self.policy())

    def test_registry_not_allowed_locally(self) -> None:
        with pytest.raises(PlanRejected, match="not allowed on this host"):
            check_plan_for_agent(plan(), self.policy(allowed_registries=frozenset({"other.example.com"})))

    def test_tampered_digest(self) -> None:
        p = plan()
        svc = p.services[0].model_copy(update={"digest": digest("evil")})
        tampered = p.model_copy(update={"services": [svc, *p.services[1:]]})
        with pytest.raises(PlanRejected, match="digest"):
            check_plan_for_agent(tampered, self.policy())

    def test_tampered_compose_project(self) -> None:
        tampered = plan().model_copy(update={"compose_project": "other-project"})
        with pytest.raises(PlanRejected, match="compose project"):
            check_plan_for_agent(tampered, self.policy())
