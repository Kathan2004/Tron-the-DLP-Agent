"""
Gunicorn configuration for the Tron API.

One worker process, many threads. This is deliberate, not a default to tune up:
the live event stream (SSE), the rate limiter and the background workers (SIEM
forwarder, retention, Telegram bot) keep state in process memory, and SQLite allows a
single writer. Scale by raising TRON_THREADS; put TLS in a reverse proxy in front
(see docs/deployment.md).
"""

import os

bind = f"{os.getenv('FLASK_HOST', '0.0.0.0')}:{os.getenv('FLASK_PORT', '5001')}"
workers = 1
worker_class = "gthread"
threads = int(os.getenv("TRON_THREADS", "64"))
# SSE connections are long-lived; the timeout applies to worker heartbeats, not requests.
timeout = 120
graceful_timeout = 30
keepalive = 15
max_requests = 0
limit_request_line = 8190
limit_request_fields = 100
accesslog = "-" if os.getenv("TRON_ACCESS_LOG", "1") not in {"0", "false"} else None
errorlog = "-"
# No query string in the access log: stream tickets and agent IDs travel there.
access_log_format = '%(h)s "%(m)s %(U)s" %(s)s %(b)s %(D)sus "%(a)s"'
# Honour X-Forwarded-* only from proxies listed here (default: loopback).
forwarded_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
