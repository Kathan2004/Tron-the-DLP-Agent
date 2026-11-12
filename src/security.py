"""
HTTP hardening shared by the API: rate limiting, response headers, request IDs.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from collections import deque
from typing import Deque, Dict, Tuple

from flask import Flask, g, jsonify, request


class RateLimiter:
    """Sliding-window limiter held in process memory.

    The API runs as a single worker process (see gunicorn.conf.py), so in-memory state is
    authoritative. Keys are (bucket, identity); identity is an agent ID or a client IP.
    """

    def __init__(self, max_keys: int = 50_000):
        self._hits: Dict[Tuple[str, str], Deque[float]] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def allow(self, bucket: str, identity: str, limit: int, window_seconds: float) -> Tuple[bool, int]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        if limit <= 0:
            return True, 0
        now = time.monotonic()
        key = (bucket, identity)
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self._max_keys:
                    self._evict(now, window_seconds)
                hits = self._hits[key] = deque()
            cutoff = now - window_seconds
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= limit:
                return False, max(1, int(hits[0] + window_seconds - now) + 1)
            hits.append(now)
            return True, 0

    def _evict(self, now: float, window_seconds: float) -> None:
        cutoff = now - window_seconds
        stale = [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]
        for k in stale:
            del self._hits[k]
        if len(self._hits) >= self._max_keys:
            # Under a key-flooding attack, drop the oldest half rather than grow without bound.
            for k in list(self._hits)[: self._max_keys // 2]:
                del self._hits[k]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def rate_limits() -> Dict[str, Tuple[int, int]]:
    """(limit, window seconds) per bucket. A limit of 0 disables that bucket."""
    return {
        "login": (_env_int("TRON_RATE_LOGIN_PER_MIN", 10), 60),
        "enroll": (_env_int("TRON_RATE_ENROLL_PER_MIN", 20), 60),
        "ingest": (_env_int("TRON_RATE_INGEST_PER_MIN", 600), 60),
        "console": (_env_int("TRON_RATE_CONSOLE_PER_MIN", 1200), 60),
    }


def too_many_requests(retry_after: int):
    response = jsonify({"error": "rate_limited", "retry_after": retry_after})
    response.status_code = 429
    response.headers["Retry-After"] = str(retry_after)
    return response


def check_rate(bucket: str, identity: str):
    """Return a 429 response when the caller is over the bucket's limit, else None."""
    limit, window = rate_limits().get(bucket, (0, 60))
    allowed, retry_after = limiter.allow(bucket, identity or "unknown", limit, window)
    return None if allowed else too_many_requests(retry_after)


def client_ip() -> str:
    """Peer address. Behind a reverse proxy, set TRON_TRUSTED_PROXIES so ProxyFix rewrites
    remote_addr from X-Forwarded-For; the header is never trusted otherwise."""
    return request.remote_addr or "unknown"


# Types a browser may render inline from the artifact store. Anything else is served as a
# download so an uploaded HTML/SVG file can never execute in the API's origin.
INLINE_SAFE_TYPES = {
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp",
    "application/pdf", "text/plain",
}


def install(app: Flask) -> None:
    """Attach request IDs, proxy handling and response headers to the app."""
    hops = _env_int("TRON_TRUSTED_PROXIES", 0)
    if hops > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)

    @app.before_request
    def _request_context():
        supplied = request.headers.get("X-Request-ID", "")
        g.request_id = supplied if 8 <= len(supplied) <= 64 and supplied.isascii() and supplied.replace("-", "").isalnum() \
            else uuid.uuid4().hex
        g.request_started = time.monotonic()

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("X-Request-ID", getattr(g, "request_id", ""))
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.path.startswith("/api/"):
            # API responses are data, never documents.
            response.headers.setdefault("Content-Security-Policy",
                                        "default-src 'none'; frame-ancestors 'none'; sandbox")
            if response.mimetype != "text/event-stream":
                response.headers.setdefault("Cache-Control", "no-store")
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.pop("Server", None)
        return response
