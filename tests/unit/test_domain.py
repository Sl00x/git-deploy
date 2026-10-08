from __future__ import annotations

import pytest

from udeploy_domain.manifest import ApplicationManifest
from udeploy_domain.naming import (
    NamingError,
    compose_project_name,
    image_ref_by_digest,
    image_repository_name,
    normalize_tag,
    split_image_ref,
)
from udeploy_domain.states import DeploymentState as S
from udeploy_domain.states import InvalidTransition, can_transition, check_transition

from ..factories import digest, manifest


class TestNaming:
    def test_compose_name_is_collision_proof(self) -> None:
        a = compose_project_name("a-b", "c", "prod")
        b = compose_project_name("a", "b-c", "prod")
        assert a.startswith("a-b-c-prod-") and b.startswith("a-b-c-prod-")
        assert a != b

    def test_compose_name_length(self) -> None:
        name = compose_project_name("o" * 60, "p" * 60, "production")
        assert len(name) <= 63

    def test_compose_name_rejects_non_slug(self) -> None:
        with pytest.raises(NamingError):
            compose_project_name("Acme", "x", "prod")

    def test_image_name_template(self) -> None:
        assert (
            image_repository_name(
                "{repository}_{service}", repository="group/InkerFlow", service="api", project="p"
            )
            == "inkerflow_api"
        )

    def test_branch_tag_normalisation(self) -> None:
        assert normalize_tag("feature/Foo bar") == "feature-Foo-bar"
        assert normalize_tag("-weird") == "weird"
        assert len(normalize_tag("x" * 300)) <= 128

    def test_digest_refs(self) -> None:
        ref = image_ref_by_digest("Registry.Example.com", "prod/app", digest("a"))
        assert split_image_ref(ref) == ("registry.example.com", "prod/app", digest("a"))
        with pytest.raises(NamingError):
            split_image_ref("registry.example.com/prod/app:latest")
        with pytest.raises(NamingError):
            split_image_ref("registry.example.com/prod/app:1@" + digest("a"))


class TestManifest:
    def test_example_manifest_is_valid(self) -> None:
        m = ApplicationManifest.model_validate(manifest())
        assert m.services["api"].resources.memory_bytes == 256 * 1024**2
        assert [r.host for r in m.routes_for("api", "staging")] == ["api.staging.inkerflow.example"]

    def test_same_host_in_two_environments_is_refused(self) -> None:
        raw = manifest()
        raw["services"]["frontend"]["routes"] = [{"host": "inkerflow.example"}]
        with pytest.raises(ValueError, match="claimed more than once"):
            ApplicationManifest.model_validate(raw)

    def test_healthcheck_path_cannot_be_a_url(self) -> None:
        raw = manifest()
        raw["services"]["api"]["healthcheck"]["path"] = "http://169.254.169.254/latest"
        with pytest.raises(ValueError):
            ApplicationManifest.model_validate(raw)

    def test_env_and_secret_overlap_refused(self) -> None:
        raw = manifest()
        raw["services"]["api"]["env"]["DATABASE_URL"] = "x"
        with pytest.raises(ValueError, match="both in env and secretRefs"):
            ApplicationManifest.model_validate(raw)


class TestStateMachine:
    def test_happy_path(self) -> None:
        path = [
            S.RECEIVED,
            S.VALIDATED,
            S.QUEUED,
            S.PREPARING,
            S.PULLING,
            S.VERIFYING,
            S.STARTING,
            S.HEALTHCHECKING,
            S.SWITCHING,
            S.SUCCEEDED,
        ]
        for a, b in zip(path, path[1:], strict=False):
            check_transition(a, b)

    def test_terminal_states_are_final(self) -> None:
        for t in (S.SUCCEEDED, S.FAILED, S.ROLLED_BACK, S.CANCELLED):
            assert not can_transition(t, S.QUEUED)

    def test_no_backwards_moves(self) -> None:
        with pytest.raises(InvalidTransition):
            check_transition(S.HEALTHCHECKING, S.PULLING)

    def test_rollback(self) -> None:
        check_transition(S.HEALTHCHECKING, S.ROLLBACK_PENDING)
        check_transition(S.ROLLBACK_PENDING, S.ROLLED_BACK)
