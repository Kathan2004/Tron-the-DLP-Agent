"""
Prometheus metrics (text exposition format 0.0.4), served at /api/metrics.

Process counters live in memory; gauges are read from the database at scrape time.
The endpoint is disabled unless TRON_METRICS_TOKEN is set and requires it as a bearer token.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Dict, Tuple

_lock = threading.Lock()
_requests: Dict[Tuple[str, str], int] = defaultdict(int)
_duration_sum: Dict[str, float] = defaultdict(float)
_duration_count: Dict[str, int] = defaultdict(int)
_counters: Dict[str, int] = defaultdict(int)

_GROUPS = (
    ("/api/auth", "auth"), ("/api/events", "events"), ("/api/scan", "scan"), ("/api/browser", "browser"),
    ("/api/fleet", "fleet"), ("/api/incidents", "incidents"), ("/api/policies", "policies"),
    ("/api/detectors", "detectors"), ("/api/stream", "stream"), ("/api/health", "health"),
)


def route_group(path: str) -> str:
    """Low-cardinality label for a request path."""
    for prefix, name in _GROUPS:
        if path.startswith(prefix):
            return name
    return "other"


def observe_request(path: str, status: int, seconds: float) -> None:
    group = route_group(path)
    with _lock:
        _requests[(group, f"{status // 100}xx")] += 1
        _duration_sum[group] += seconds
        _duration_count[group] += 1


def inc(name: str, amount: int = 1) -> None:
    with _lock:
        _counters[name] += amount


def _escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render(database=None, forwarder=None, version: str = "") -> str:
    lines = [
        "# HELP tron_build_info Build information.",
        "# TYPE tron_build_info gauge",
        f'tron_build_info{{version="{_escape(version)}"}} 1',
        "# HELP tron_http_requests_total API requests by route group and status class.",
        "# TYPE tron_http_requests_total counter",
    ]
    with _lock:
        requests_snapshot = dict(_requests)
        sums = dict(_duration_sum)
        counts = dict(_duration_count)
        counters = dict(_counters)
    for (group, status), n in sorted(requests_snapshot.items()):
        lines.append(f'tron_http_requests_total{{route="{group}",status="{status}"}} {n}')
    lines += ["# HELP tron_http_request_duration_seconds Time spent handling API requests.",
              "# TYPE tron_http_request_duration_seconds summary"]
    for group in sorted(sums):
        lines.append(f'tron_http_request_duration_seconds_sum{{route="{group}"}} {sums[group]:.6f}')
        lines.append(f'tron_http_request_duration_seconds_count{{route="{group}"}} {counts[group]}')
    for name in sorted(counters):
        lines += [f"# TYPE tron_{name}_total counter", f"tron_{name}_total {counters[name]}"]

    if database is not None:
        stats = database.stats() or {}
        lines += ["# HELP tron_incidents Incidents by status.", "# TYPE tron_incidents gauge"]
        for status in ("open", "escalated", "closed"):
            lines.append(f'tron_incidents{{status="{status}"}} {int(stats.get(status, 0))}')
        lines += ["# TYPE tron_events gauge", f"tron_events {int(stats.get('total_events', 0))}",
                  "# TYPE tron_scans gauge", f"tron_scans {int(stats.get('total_scans', 0))}"]
        from src.api import _fleet_agent_status  # late import: api imports this module
        by_status: Dict[str, int] = defaultdict(int)
        for agent in database.list_fleet_agents():
            by_status[_fleet_agent_status(agent.get("last_seen"))[0]] += 1
        lines += ["# HELP tron_fleet_agents Enrolled agents by connectivity.", "# TYPE tron_fleet_agents gauge"]
        for status in ("online", "idle", "offline", "pending"):
            lines.append(f'tron_fleet_agents{{status="{status}"}} {by_status.get(status, 0)}')
        outbox = database.siem_outbox_stats()
        lines += ["# HELP tron_siem_outbox_pending Records waiting for delivery to SIEM destinations.",
                  "# TYPE tron_siem_outbox_pending gauge", f"tron_siem_outbox_pending {outbox['pending']}"]
    if forwarder is not None:
        lines += ["# TYPE tron_siem_delivered_total counter", f"tron_siem_delivered_total {forwarder.delivered}",
                  "# TYPE tron_siem_failed_total counter", f"tron_siem_failed_total {forwarder.failed}"]
    return "\n".join(lines) + "\n"
