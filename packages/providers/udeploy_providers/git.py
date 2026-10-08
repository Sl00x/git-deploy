"""Normalisation of GitHub / GitLab webhook payloads into one event model.

Normalised events are *facts about the source repository* (a push, a tag, a
pipeline result). None of them is sufficient on its own to deploy anything:
deployments require a verified release whose digests exist in the registry.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from udeploy_domain.naming import is_commit_sha

ZERO_SHA = "0" * 40


class EventKind(StrEnum):
    PUSH = "push"
    TAG = "tag"
    RELEASE = "release"
    PIPELINE_SUCCESS = "pipeline_success"
    PIPELINE_FAILURE = "pipeline_failure"
    ARTIFACT_PUBLISHED = "artifact_published"
    MANUAL_DEPLOY = "manual_deploy"
    PING = "ping"


class NormalizedEvent(BaseModel):
    provider: str
    kind: EventKind
    repository: str
    ref: str | None = None
    branch: str | None = None
    tag: str | None = None
    commit_sha: str | None = None
    pipeline_id: str | None = None
    actor: str | None = None
    deleted: bool = False


class UnsupportedEvent(Exception):
    pass


def _ref_parts(ref: str | None) -> tuple[str | None, str | None]:
    if not ref:
        return None, None
    if ref.startswith("refs/heads/"):
        return ref[len("refs/heads/") :], None
    if ref.startswith("refs/tags/"):
        return None, ref[len("refs/tags/") :]
    return None, None


def _sha(value: Any) -> str | None:
    return value if isinstance(value, str) and is_commit_sha(value) else None


def normalize_github(event: str, payload: dict[str, Any]) -> NormalizedEvent:
    repo = (payload.get("repository") or {}).get("full_name")
    if not isinstance(repo, str):
        raise UnsupportedEvent("payload has no repository.full_name")
    actor = (payload.get("sender") or {}).get("login")
    if event == "ping":
        return NormalizedEvent(provider="github", kind=EventKind.PING, repository=repo, actor=actor)
    if event == "push":
        ref = payload.get("ref")
        branch, tag = _ref_parts(ref)
        after = payload.get("after")
        return NormalizedEvent(
            provider="github",
            kind=EventKind.TAG if tag else EventKind.PUSH,
            repository=repo,
            ref=ref,
            branch=branch,
            tag=tag,
            commit_sha=_sha(after),
            actor=actor,
            deleted=bool(payload.get("deleted")) or after == ZERO_SHA,
        )
    if event == "release":
        release = payload.get("release") or {}
        return NormalizedEvent(
            provider="github",
            kind=EventKind.RELEASE,
            repository=repo,
            tag=release.get("tag_name"),
            ref=f"refs/tags/{release.get('tag_name')}",
            commit_sha=_sha(release.get("target_commitish")),
            actor=actor,
        )
    if event == "workflow_run":
        run = payload.get("workflow_run") or {}
        if payload.get("action") != "completed":
            raise UnsupportedEvent("workflow_run not completed")
        conclusion = run.get("conclusion")
        head_branch = run.get("head_branch")
        return NormalizedEvent(
            provider="github",
            kind=EventKind.PIPELINE_SUCCESS if conclusion == "success" else EventKind.PIPELINE_FAILURE,
            repository=repo,
            branch=head_branch,
            commit_sha=_sha(run.get("head_sha")),
            pipeline_id=str(run.get("id")),
            actor=actor,
        )
    raise UnsupportedEvent(f"GitHub event {event!r} is not handled")


def normalize_gitlab(event_header: str, payload: dict[str, Any]) -> NormalizedEvent:
    project = payload.get("project") or {}
    repo = project.get("path_with_namespace")
    if not isinstance(repo, str):
        raise UnsupportedEvent("payload has no project.path_with_namespace")
    kind = payload.get("object_kind")
    actor = payload.get("user_username") or (payload.get("user") or {}).get("username")
    if kind in ("push", "tag_push"):
        ref = payload.get("ref")
        branch, tag = _ref_parts(ref)
        after = payload.get("checkout_sha") or payload.get("after")
        return NormalizedEvent(
            provider="gitlab",
            kind=EventKind.TAG if kind == "tag_push" else EventKind.PUSH,
            repository=repo,
            ref=ref,
            branch=branch,
            tag=tag,
            commit_sha=_sha(after),
            actor=actor,
            deleted=payload.get("after") == ZERO_SHA,
        )
    if kind == "release":
        tag = payload.get("tag")
        return NormalizedEvent(
            provider="gitlab",
            kind=EventKind.RELEASE,
            repository=repo,
            tag=tag,
            ref=f"refs/tags/{tag}",
            commit_sha=_sha((payload.get("commit") or {}).get("id")),
            actor=actor,
        )
    if kind == "pipeline":
        attrs = payload.get("object_attributes") or {}
        status = attrs.get("status")
        if status not in ("success", "failed", "canceled"):
            raise UnsupportedEvent(f"pipeline status {status!r} is not final")
        is_tag = bool(attrs.get("tag"))
        ref = attrs.get("ref")
        return NormalizedEvent(
            provider="gitlab",
            kind=EventKind.PIPELINE_SUCCESS if status == "success" else EventKind.PIPELINE_FAILURE,
            repository=repo,
            ref=ref,
            branch=None if is_tag else ref,
            tag=ref if is_tag else None,
            commit_sha=_sha(attrs.get("sha")),
            pipeline_id=str(attrs.get("id")),
            actor=actor,
        )
    raise UnsupportedEvent(f"GitLab event {event_header!r}/{kind!r} is not handled")
