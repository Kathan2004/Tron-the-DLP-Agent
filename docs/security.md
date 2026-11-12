# Security model

## Trust boundaries

| Caller | Authenticates with | Can do |
|---|---|---|
| Analyst (console) | Password, then signed bearer token bound to a server-side session | What the role's permissions allow |
| Agent / extension | Per-agent key (`X-Tron-Agent-Id` + `X-Tron-Agent-Key`) | Submit events, scans, artifacts; check in; sync policy |
| New agent | Enrollment token, once | Obtain a key for an ID that has none |
| Prometheus | `TRON_METRICS_TOKEN` | Read metrics |
| Anyone | Nothing | `GET /api/health`, `POST /api/auth/login` (rate limited) |

## Console authentication

PBKDF2-SHA256 (200k iterations) password hashes; password policy, lockout after failed
attempts, concurrent session cap and idle timeout are configurable under IAM. Every
request re-checks the session row, so revocation is immediate. Role-based permissions
cover every route; viewers are read-only. Accounts flagged for a password change can only
reach the self-service endpoints.

The live event stream uses a 60-second single-purpose ticket (`POST /api/stream/ticket`)
because `EventSource` cannot send headers. The ticket is bound to the session and dies
with it. It travels in the query string, so the reference nginx config does not log that
location.

The session token is held in the browser's `localStorage`. The reference deployment
serves the console with a CSP that forbids inline and third-party script, which is what
keeps an injection from reaching it; keep that CSP if you serve the console yourself.

## Agent authentication

Keys are 256 bits from the OS CSPRNG; the server stores only SHA-256 of each. A request
that presents a wrong key is rejected and never falls back to the shared token. When a
request is authenticated with a key, the agent ID comes from the key: the body cannot
claim another identity, and an agent cannot write another agent's logs. Rotation keeps the
previous key valid for 10 minutes so a lost response does not lock the agent out.

Modes (`TRON_AGENT_AUTH`): `open` (no token configured), `token` (shared token or key,
for migration), `strict` (keys only).

## Data at rest

AES-256-GCM seals payload samples, findings (matched values), captured files,
screenshots, the SIEM outbox and stored integration secrets. Artifact ciphertext is bound
to its artifact ID. The key comes from `TRON_DATA_KEY`; without it a key file is created
beside the database, which protects against a leaked database file but not against a copy
of the whole data directory. Reading encrypted data with the wrong key fails; it is never
served as ciphertext or silently dropped.

Not encrypted: usernames, hostnames, detector names, timestamps and incident metadata,
which the console queries and aggregates. Use volume encryption for those.

Indexed Document Matching stores keyed fingerprints only; registered documents are
discarded after fingerprinting.

## Audit log

Every audit entry carries the SHA-256 of the previous entry plus its own content.
`GET /api/audit/verify` (and the console) recomputes the chain and reports the first
altered or missing entry. An attacker with write access to the database can rebuild the
whole chain; forward audit records to a SIEM destination to anchor it externally.

## Outbound data

- **LLM triage (optional):** every detected value is replaced with `[REDACTED:<TYPE>]`
  before a prompt is built. Exception: the extension's optional AI mode sends image
  uploads to Gemini for OCR unredacted.
- **SIEM forwarding (optional):** detector names, severities, identities and counts.
  Never matched values or payload samples. Collector certificates are always verified; a
  private CA can be supplied per destination. Link-local and metadata addresses are
  rejected as destinations.
- **Signed agent upgrades:** an upgrade is an HTTPS URL, a SHA-256 and an Ed25519
  signature. Agents verify against a locally pinned public key before executing anything,
  so a compromised API cannot run code on endpoints. POSIX agents only.

## HTTP surface

Request body cap, per-bucket rate limits (login, enrollment, ingest per agent, console),
`nosniff`, `X-Frame-Options: DENY`, a `default-src 'none'; sandbox` CSP on API responses,
`no-store`, HSTS over TLS, opaque 500s with a request ID (tracebacks only in server logs).
Captured files are served as downloads unless their type is on a short render-safe list,
so an uploaded HTML or SVG file cannot execute in the API's origin. `X-Forwarded-For` is
honoured only for the configured number of proxy hops.

## Known limitations

- Single-process API on SQLite (see docs/deployment.md).
- The enrollment token is a shared secret until `strict` mode is on; distribute it
  through enterprise policy / configuration management and rotate it after rollout.
- Agents run in user space. A local administrator can stop them; a missing heartbeat is
  visible in the fleet view but is not prevented.
- The Windows agent paths (clipboard, processes, connections, USB, volumes) are covered by
  parser tests against captured command output and have not been exercised on a Windows
  host in CI.
- Console sessions use a bearer token in `localStorage` rather than an HttpOnly cookie.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository. Do not file a public issue.
