"""
Process-wide logging configuration.

TRON_LOG_FORMAT=json emits one JSON object per line (for log shippers); the default is a
human-readable line. TRON_LOG_LEVEL sets the threshold (default INFO).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            entry["request_id"] = request_id
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


class _RequestIdFilter(logging.Filter):
    """Attach the current request ID (if any) to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            from flask import g, has_request_context
            record.request_id = getattr(g, "request_id", "") if has_request_context() else ""
        except Exception:
            record.request_id = ""
        return True


def configure() -> None:
    root = logging.getLogger()
    if getattr(root, "_tron_configured", False):
        return
    level = getattr(logging, os.getenv("TRON_LOG_LEVEL", "INFO").upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(_RequestIdFilter())
    if os.getenv("TRON_LOG_FORMAT", "text").lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Werkzeug's per-request lines duplicate the access log in production setups.
    logging.getLogger("werkzeug").setLevel(logging.WARNING if level > logging.DEBUG else logging.INFO)
    # httpx logs full request URLs at INFO; Telegram URLs embed the bot token.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    root._tron_configured = True  # type: ignore[attr-defined]
