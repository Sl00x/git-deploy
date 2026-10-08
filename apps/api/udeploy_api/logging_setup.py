from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

from udeploy_security.masking import mask

from .audit import correlation_id_var
from .settings import Settings


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": mask(record.getMessage()),
            "correlation_id": correlation_id_var.get(),
        }
        if record.exc_info:
            payload["exc"] = mask(self.formatException(record.exc_info))
        return json.dumps(payload)


def configure_logging(settings: Settings) -> None:
    root = logging.getLogger()
    if getattr(root, "_udeploy_configured", False):
        return
    handler = logging.StreamHandler(sys.stdout)
    if settings.log_json:
        handler.setFormatter(JsonFormatter())
    root.handlers = [handler]
    root.setLevel(settings.log_level)
    root._udeploy_configured = True  # type: ignore[attr-defined]
