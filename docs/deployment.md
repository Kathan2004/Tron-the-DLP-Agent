# Deployment

## Topology

```
agents / extension ──┐
                     ├─ HTTPS ─► reverse proxy (TLS) ─► console (nginx, static + /api proxy) ─► API (gunicorn) ─► SQLite + artifact store
analysts (browser) ──┘                                                                           └─► SIEM, Telegram, Slack, Jira, Gemini (optional, outbound)
```

Console and API share one origin, so no CORS configuration is needed in production.
The API container is not published; it is reachable only through the console's proxy.

## Docker Compose

```bash
./setup.sh                      # or: cp .env.example .env and fill in the secrets
docker compose up -d --build    # console + API on http://127.0.0.1:8080
```

With TLS (Caddy obtains and renews the certificate for a public DNS name):

```bash
TRON_DOMAIN=dlp.example.com TRON_TRUSTED_PROXIES=2 docker compose --profile tls up -d --build
```

For an internal name or your own certificate, edit `deploy/Caddyfile` (`tls cert key`), or
put your existing load balancer in front of port 8080 and set `TRON_TRUSTED_PROXIES` to the
number of proxies between the client and the API (nginx counts as one).

The API container runs as UID 10001 with a read-only root filesystem, no capabilities and
`no-new-privileges`. State lives in the `tron-data` volume (`/app/data`).

## Without containers

```bash
pip install -r requirements.txt
gunicorn -c gunicorn.conf.py wsgi:app      # production
python main.py                             # development server, loopback only
cd siem-console && npm ci && npm run build # serve dist/ from any web server, proxy /api
```

`siem-console/nginx.conf` is a working reference for the web server (security headers,
CSP, SSE proxying without buffering).

## Process model

One gunicorn worker, many threads (`TRON_THREADS`, default 64). This is a constraint, not
a tuning default: the live event stream, the rate limiter and the background workers
(SIEM forwarder, retention, Telegram bot) hold state in the process, and SQLite has a
single writer. Do not raise `workers`. A deployment that outgrows one process needs the
storage layer moved to a client/server database first.

## Required configuration

| Variable | Purpose |
|---|---|
| `APP_AUTH_SECRET` | Signs console sessions and stream tickets. Unset = sessions die on restart. |
| `TRON_AGENT_TOKEN` | Enrollment token. Unset = ingest endpoints are unauthenticated. |
| `TRON_AGENT_AUTH` | `strict` once agents are enrolled: only per-agent keys are accepted. |
| `TRON_DATA_KEY` | Base64 32-byte data key. Unset = key file next to the database. |
| `TRON_TRUSTED_PROXIES` | Proxy hops whose `X-Forwarded-*` headers are trusted (0 = none). |

Optional: `TRON_METRICS_TOKEN`, `TRON_LOG_FORMAT=json`, `TRON_LOG_LEVEL`,
`TRON_RATE_LOGIN_PER_MIN` (10), `TRON_RATE_INGEST_PER_MIN` (600 per agent),
`TRON_RATE_CONSOLE_PER_MIN` (1200 per client), `TRON_RATE_ENROLL_PER_MIN` (20),
`TRON_MAX_STREAM_CLIENTS` (32), `APP_MAX_REQUEST_MB` (75), integrations (see `.env.example`).

The **Platform & Security** page in the console shows which of these still need attention.

## Rolling out agent keys

1. Set `TRON_AGENT_TOKEN` on the API. Give the same value to agents (`TRON_AGENT_TOKEN`)
   and to the extension (`agentToken` in Chrome enterprise policy).
2. Each agent enrolls on first contact and stores its key (`~/.tron/` or
   `%LOCALAPPDATA%\Tron\`, mode 0600; the extension keeps it in the service worker's
   storage). Watch **Platform & Security > Agent credentials** fill up.
3. Set `TRON_AGENT_AUTH=strict`. The shared token now only works for enrollment.
4. Rotate a key from the console (delivered at the next check-in) or revoke it; a revoked
   agent must enroll again. Enrolling an ID that already holds an active key is refused.

Agents refuse to talk to a non-loopback `http://` API unless `TRON_ALLOW_INSECURE_API=1`.

## Backup and restore

Back up the data volume (`tron_dlp.db` with its `-wal`/`-shm` files, `artifacts/`,
`edm/`) and, separately, the data key (`TRON_DATA_KEY` or `data/.data.key`). A backup
without the key cannot be read; that is the point of keeping them apart. For a consistent
copy of a running database:

```bash
sqlite3 data/tron_dlp.db ".backup '/backups/tron_dlp.db'"
```

## Monitoring

- `GET /api/health`: 200 when the database is reachable, 503 otherwise. No authentication.
- `GET /api/metrics`: Prometheus text format, requires `Authorization: Bearer $TRON_METRICS_TOKEN`.
  Request counts and latency by route group, incidents by status, agents by connectivity,
  SIEM outbox depth and delivery counters.
- Logs go to stdout; `TRON_LOG_FORMAT=json` for one JSON object per line with request IDs.

## Upgrading

Schema changes are applied on start. Rows written before encryption at rest was enabled
stay readable and are not rewritten. Audit entries written before hash chaining are
reported as "unchained" by the integrity check, not as failures.
