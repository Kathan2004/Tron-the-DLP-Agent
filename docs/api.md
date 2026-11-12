# API reference (platform endpoints)

All paths are under `/api`. Console endpoints need `Authorization: Bearer <token>` from
`POST /api/auth/login`; the permission in brackets is required. Agent endpoints need the
agent headers described in docs/security.md.

## Agents

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/fleet/enroll` | `X-Tron-Agent-Token` | `{agent_id, agent_type, hostname}` -> `201 {agent_key}` (shown once). `409` if the ID holds an active key. |
| POST | `/fleet/agents/<id>/key/rotate` | agent key | New key; previous one valid for 10 minutes. |
| POST | `/fleet/checkin` | agent | Heartbeat. Response carries at most one queued `command` (`upgrade`, `rotate_key`). |
| POST | `/events` | agent | `{agent_type, source_host, user, channel, payload, geo}` -> `{event_id}` (`null` if nothing matched). |
| GET | `/policies/sync` | agent | Active policies, exceptions, managed settings, detector configuration. |
| GET | `/fleet/credentials` | console [fleet.view] | Credential inventory (no key material). |
| POST | `/fleet/agents/<id>/key` | console [fleet.manage] | Pre-provision or re-issue a key. |
| DELETE | `/fleet/agents/<id>/key` | console [fleet.manage] | Revoke. |
| POST | `/fleet/agents/<id>/key/rotation` | console [fleet.manage] | Queue a rotation for the next check-in. |
| DELETE | `/fleet/agents/<id>` | console [fleet.manage] | Remove a decommissioned agent and revoke its key. |

## Protected documents (IDM)

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/idm/documents` | policies.view | List registered documents. |
| POST | `/idm/documents` | policies.manage | Multipart `file` (+ `name`, `description`, `sensitivity`) or JSON `{name, text}`. |
| PATCH | `/idm/documents/<id>` | policies.manage | `{is_active}`. |
| DELETE | `/idm/documents/<id>` | policies.manage | Remove the document and its fingerprints. |
| POST | `/idm/match` | policies.manage | Check a file or `{text}`; returns matched documents with containment. |

## Platform

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET / PUT | `/settings/retention` | settings.manage | `{retention_days: {events, scan_results, artifacts, screenshots, operational_logs, closed_incidents, auth_sessions}}`; 0 keeps forever. |
| POST | `/settings/retention/run` | settings.manage | Apply now; returns deleted counts. |
| GET | `/settings/data-protection` | settings.manage | Encryption, key source, agent auth mode, audit chain status. |
| GET / PUT | `/siem/config` | settings.manage | Destinations (`syslog`: host, port, protocol udp/tcp/tls, format cef/json; `webhook`: url, format json/splunk_hec, auth_header, secret). Secrets are write-only. |
| POST | `/siem/test` | settings.manage | `{destination_id}`: send one synthetic record. |
| GET | `/audit/verify` | audit.view | Recompute the audit hash chain. |
| POST | `/stream/ticket` | dashboard.view | 60 s ticket for `GET /stream?ticket=...` (server-sent events). |
| GET | `/metrics` | `TRON_METRICS_TOKEN` | Prometheus exposition. |
| GET | `/health` | none | 200 / 503. |

## Webhook signature

When a destination has a secret, each POST carries `X-Tron-Timestamp` and
`X-Tron-Signature: sha256=<hex>`, the HMAC-SHA256 of `<timestamp>.<raw body>`. Reject
requests whose timestamp is more than a few minutes old.

## Errors

JSON `{"error": "<code>"}`. `401` unauthenticated, `403` missing permission
(`required_permission` names it), `429` rate limited (`Retry-After`), `500` includes a
`request_id` that matches the server log.
