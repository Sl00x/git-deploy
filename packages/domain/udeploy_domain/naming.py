"""Normalisation of every externally visible identifier.

Docker/OCI/Compose names have strict grammars. Every name the platform derives
from user input goes through this module so that two different inputs can never
silently collapse onto the same runtime object (collision-proof slugs).
"""

from __future__ import annotations

import hashlib
import re
import unicodedata

# OCI distribution spec: path components are [a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*
_OCI_COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
# Tag grammar: [\w][\w.-]{0,127}
_OCI_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_COMMIT_SHA = re.compile(r"^[a-f0-9]{40}([a-f0-9]{24})?$")
# Registry host[:port], lower-case, no scheme.
_REGISTRY_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?$")
_ENV_VAR = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")

COMPOSE_PROJECT_MAX = 63


class NamingError(ValueError):
    """Raised when an identifier cannot be normalised safely."""


def _ascii_fold(value: str) -> str:
    return unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")


def _short_hash(value: str, length: int = 8) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def slugify(value: str, *, max_length: int = 63) -> str:
    """Lower-case DNS-label style slug. Raises if nothing usable remains."""
    folded = _ascii_fold(value).lower()
    slug = re.sub(r"[^a-z0-9]+", "-", folded).strip("-")
    if not slug:
        raise NamingError(f"cannot derive a slug from {value!r}")
    if len(slug) > max_length:
        suffix = _short_hash(value)
        slug = slug[: max_length - len(suffix) - 1].rstrip("-") + "-" + suffix
    return slug


def is_slug(value: str) -> bool:
    return bool(_SLUG.match(value))


def require_slug(value: str, what: str = "identifier") -> str:
    if not is_slug(value):
        raise NamingError(f"{what} {value!r} must match {_SLUG.pattern}")
    return value


def compose_project_name(org: str, project: str, environment: str) -> str:
    """`<org>-<project>-<environment>`.

    Slugs are joined with '-', and since slugs may themselves contain '-',
    ("a-b", "c") and ("a", "b-c") would collide. A short hash of the
    unambiguous tuple is therefore always appended.
    """
    for part, what in ((org, "organization"), (project, "project"), (environment, "environment")):
        require_slug(part, what)
    digest = _short_hash(f"{org}\x00{project}\x00{environment}", 6)
    base = f"{org}-{project}-{environment}"
    budget = COMPOSE_PROJECT_MAX - len(digest) - 1
    if len(base) > budget:
        base = base[:budget].rstrip("-")
    return f"{base}-{digest}"


def oci_component(value: str) -> str:
    """Normalise one path component of an OCI repository name."""
    folded = _ascii_fold(value).lower()
    comp = re.sub(r"[^a-z0-9._-]+", "-", folded)
    comp = re.sub(r"[._-]*([._])[._-]*", r"\1", comp)  # collapse separator runs
    comp = comp.strip("._-")
    if not comp or not _OCI_COMPONENT.match(comp):
        raise NamingError(f"cannot derive an OCI path component from {value!r}")
    return comp


def image_repository_name(template: str, *, repository: str, service: str, project: str) -> str:
    """Render the image name template (default `{repository}_{service}`)."""
    repo_leaf = repository.rsplit("/", 1)[-1]
    try:
        raw = template.format(repository=repo_leaf, service=service, project=project)
    except (KeyError, IndexError) as exc:
        raise NamingError(f"unknown placeholder in image template {template!r}: {exc}") from exc
    return "/".join(oci_component(part) for part in raw.split("/") if part)


def normalize_tag(value: str) -> str:
    """Turn a branch/ref into a valid OCI tag (branches are NOT release ids)."""
    tag = re.sub(r"[^A-Za-z0-9_.-]+", "-", _ascii_fold(value)).strip("-.")
    if not tag:
        raise NamingError(f"cannot derive a tag from {value!r}")
    if not re.match(r"[A-Za-z0-9_]", tag[0]):
        tag = "v" + tag
    if len(tag) > 128:
        tag = tag[:119] + "-" + _short_hash(value)
    if not _OCI_TAG.match(tag):
        raise NamingError(f"invalid tag {tag!r}")
    return tag


def is_digest(value: str) -> bool:
    return bool(_DIGEST.match(value))


def require_digest(value: str) -> str:
    if not is_digest(value):
        raise NamingError(f"{value!r} is not a sha256 digest")
    return value


def is_commit_sha(value: str) -> bool:
    return bool(_COMMIT_SHA.match(value))


def normalize_registry_host(value: str) -> str:
    host = value.strip().lower()
    for scheme in ("https://", "http://"):
        if host.startswith(scheme):
            host = host[len(scheme) :]
    host = host.rstrip("/")
    if not _REGISTRY_HOST.match(host):
        raise NamingError(f"invalid registry host {value!r}")
    return host


def image_ref_by_digest(registry: str, repository_path: str, digest: str) -> str:
    require_digest(digest)
    return f"{normalize_registry_host(registry)}/{repository_path}@{digest}"


def split_image_ref(ref: str) -> tuple[str, str, str]:
    """Split `host/path@sha256:...` into (host, path, digest). Tags are refused."""
    if "@" not in ref:
        raise NamingError(f"image reference {ref!r} is not pinned by digest")
    name, digest = ref.split("@", 1)
    require_digest(digest)
    if "/" not in name:
        raise NamingError(f"image reference {ref!r} has no registry host")
    host, path = name.split("/", 1)
    if ":" in path:
        raise NamingError(f"image reference {ref!r} mixes tag and digest")
    return normalize_registry_host(host), path, digest


def is_env_var_name(value: str) -> bool:
    return bool(_ENV_VAR.match(value))
