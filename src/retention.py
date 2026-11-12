"""
Data retention: delete detection data once it is older than the configured period.

Periods are per data class, in days; 0 keeps that class forever. Nothing is deleted until
an administrator sets a period (the only non-zero default is expired console sessions).
The audit log is never pruned.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Dict, Optional

log = logging.getLogger("tron.retention")

SETTING_KEY = "retention_days"
DATA_CLASSES = {
    "events": "Detection events (including the encrypted payload sample)",
    "scan_results": "Scan results and their findings",
    "artifacts": "Captured files (blocked uploads) and their metadata",
    "screenshots": "Screenshots captured by the browser extension",
    "operational_logs": "Agent operational logs",
    "closed_incidents": "Closed incidents",
    "auth_sessions": "Expired console sessions",
}
DEFAULTS: Dict[str, int] = {**{k: 0 for k in DATA_CLASSES}, "auth_sessions": 30}
MAX_DAYS = 3650


def normalize(raw: object) -> Dict[str, int]:
    """Validate a retention config from the console; unknown keys are ignored."""
    if not isinstance(raw, dict):
        raise ValueError("retention must be an object of data class -> days")
    out = dict(DEFAULTS)
    for key in DATA_CLASSES:
        if key not in raw:
            continue
        value = raw[key]
        if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= MAX_DAYS):
            raise ValueError(f"{key}: days must be an integer between 0 and {MAX_DAYS}")
        out[key] = value
    return out


def current(database) -> Dict[str, int]:
    stored = database.get_platform_setting(SETTING_KEY)
    merged = dict(DEFAULTS)
    if isinstance(stored, dict):
        merged.update({k: int(v) for k, v in stored.items() if k in DATA_CLASSES and isinstance(v, int)})
    return merged


def run_once(database, artifacts_root: Optional[Path] = None) -> Dict[str, int]:
    """Apply the retention policy now. Returns deleted row counts per data class."""
    result = database.purge_older_than(current(database))
    paths = result.pop("artifact_paths", [])
    root = Path(artifacts_root).resolve() if artifacts_root else None
    removed_files = 0
    for raw_path in paths:
        try:
            path = Path(raw_path).resolve()
            # Only ever delete inside the artifact store, whatever the row says.
            if root is not None and root not in path.parents:
                log.warning("skipping artifact outside the artifact store: %s", raw_path)
                continue
            if path.is_file():
                os.unlink(path)
                removed_files += 1
        except OSError as exc:
            log.warning("could not delete artifact %s: %s", raw_path, exc)
    result["artifact_files"] = removed_files
    counts = {k: int(v) for k, v in result.items()}
    if any(counts.values()):
        log.info("retention removed %s", ", ".join(f"{k}={v}" for k, v in counts.items() if v))
        database.add_audit_entry("retention_applied", "platform", "retention", "system",
                                 __import__("json").dumps(counts))
        database.set_platform_setting("retention_last_run", {"counts": counts}, actor="system")
    return counts


class RetentionWorker:
    def __init__(self, database, artifacts_root: Optional[Path] = None, interval_seconds: int = 3600):
        self.db = database
        self.artifacts_root = artifacts_root
        self.interval = interval_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        def loop():
            # First pass shortly after start, then hourly.
            delay = 60
            while not self._stop.wait(delay):
                delay = self.interval
                try:
                    run_once(self.db, self.artifacts_root)
                except Exception:
                    log.exception("retention run failed")

        self._thread = threading.Thread(target=loop, name="tron-retention", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
