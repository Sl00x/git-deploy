"""Redaction of secret values in any text that may reach logs, events or errors."""

from __future__ import annotations

import re
from collections.abc import Iterable

REDACTED = "***"
_GENERIC = [
    re.compile(r"(?i)(authorization:\s*)(bearer|basic)\s+[^\s\"']+"),
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s\"'&]+"),
    re.compile(r"(udp_|udci_|udenr_|udwh_)[A-Za-z0-9_-]{16,}"),
]


def mask(text: str, secrets: Iterable[str] = ()) -> str:
    for value in sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True):
        text = text.replace(value, REDACTED)
    text = _GENERIC[0].sub(lambda m: m.group(1) + m.group(2) + " " + REDACTED, text)
    text = _GENERIC[1].sub(lambda m: m.group(1) + REDACTED, text)
    text = _GENERIC[2].sub(lambda m: m.group(1) + REDACTED, text)
    return text
