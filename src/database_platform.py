"""
Platform tables: agent credentials, durable fleet command queue, platform settings,
Indexed Document Matching, screenshots, the SIEM delivery outbox, retention and the
tamper-evident audit chain.

Mixed into src.database.Database; relies on its `_cursor()` and `cipher`.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(dt: Optional[datetime] = None) -> str:
    return (dt or utcnow()).astimezone(timezone.utc).isoformat(timespec="seconds")


AUDIT_GENESIS = "0" * 64


def audit_entry_hash(prev_hash: str, timestamp: str, action: str, target_type: Optional[str],
                     target_id: Optional[str], actor: Optional[str], details: Optional[str]) -> str:
    """Hash of one audit row, chained to the previous row's hash."""
    material = json.dumps(
        [prev_hash, timestamp, action, target_type or "", target_id or "", actor or "", details or ""],
        separators=(",", ":"), ensure_ascii=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class PlatformStoreMixin:
    """Storage for the platform features. See module docstring."""

    # ==================== SCHEMA ====================

    def _init_platform_schema(self, cur: sqlite3.Cursor) -> None:
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS agent_credentials (
                agent_id TEXT PRIMARY KEY,
                key_hash TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                prev_key_hash TEXT,
                prev_valid_until TEXT,
                agent_type TEXT,
                hostname TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT,
                rotated_at TEXT,
                revoked_at TEXT,
                revoked_by TEXT,
                last_used_at TEXT,
                last_ip TEXT
            );

            CREATE TABLE IF NOT EXISTS fleet_commands (
                command_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                created_at TEXT NOT NULL,
                delivered_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_fleet_commands_agent ON fleet_commands(agent_id, status, created_at);

            CREATE TABLE IF NOT EXISTS platform_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT
            );

            CREATE TABLE IF NOT EXISTS idm_documents (
                doc_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                sensitivity TEXT NOT NULL DEFAULT 'HIGH',
                content_sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                word_count INTEGER NOT NULL DEFAULT 0,
                fingerprint_count INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT
            );
            CREATE TABLE IF NOT EXISTS idm_fingerprints (
                fingerprint INTEGER NOT NULL,
                doc_id TEXT NOT NULL,
                PRIMARY KEY (fingerprint, doc_id)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_idm_fingerprints_doc ON idm_fingerprints(doc_id);

            CREATE TABLE IF NOT EXISTS screenshots (
                screenshot_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                agent_id TEXT,
                domain TEXT,
                user TEXT,
                incident_type TEXT,
                severity TEXT,
                url TEXT,
                findings_summary TEXT,
                image_data TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_screenshots_created ON screenshots(created_at);

            CREATE TABLE IF NOT EXISTS siem_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                destination TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_siem_outbox_due ON siem_outbox(next_attempt_at);

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_scan_results_agent ON scan_results(agent_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_oplogs_agent ON operational_logs(agent_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
        """)
        cur.execute("PRAGMA table_info(fleet)")
        fleet_cols = {c[1] for c in cur.fetchall()}
        if "managed_settings" not in fleet_cols:
            cur.execute("ALTER TABLE fleet ADD COLUMN managed_settings TEXT")
        cur.execute("PRAGMA table_info(audit_log)")
        audit_cols = {c[1] for c in cur.fetchall()}
        if "prev_hash" not in audit_cols:
            cur.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
        if "entry_hash" not in audit_cols:
            cur.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")

    # ==================== PLATFORM SETTINGS ====================

    def get_platform_setting(self, key: str, default=None):
        with self._cursor() as cur:
            cur.execute("SELECT setting_value FROM platform_settings WHERE setting_key = ?", (key,))
            row = cur.fetchone()
        if not row:
            return default
        try:
            return json.loads(self.cipher.open_text(row[0]))
        except (ValueError, TypeError):
            return default

    def set_platform_setting(self, key: str, value, actor: Optional[str] = None, secret: bool = False) -> None:
        """Store a JSON-serialisable setting. `secret=True` seals it with the data key."""
        raw = json.dumps(value)
        if secret:
            raw = self.cipher.seal_text(raw)
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO platform_settings (setting_key, setting_value, updated_at, updated_by)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
            """, (key, raw, utc_iso(), actor))

    # ==================== AGENT CREDENTIALS ====================

    def get_agent_credential(self, agent_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM agent_credentials WHERE agent_id = ?", (agent_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_agent_credentials(self) -> List[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM agent_credentials ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def create_agent_credential(self, agent_id: str, key_hash: str, key_prefix: str,
                                agent_type: str = "", hostname: str = "",
                                created_by: Optional[str] = None) -> bool:
        """Insert a credential for an agent that has none (or only a revoked one).

        Returns False when the agent already holds an active credential, so a caller that
        only knows the enrollment token cannot take over an enrolled agent's identity.
        """
        now = utc_iso()
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO agent_credentials
                    (agent_id, key_hash, key_prefix, agent_type, hostname, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    key_hash = excluded.key_hash,
                    key_prefix = excluded.key_prefix,
                    prev_key_hash = NULL,
                    prev_valid_until = NULL,
                    agent_type = excluded.agent_type,
                    hostname = excluded.hostname,
                    created_at = excluded.created_at,
                    created_by = excluded.created_by,
                    rotated_at = NULL,
                    revoked_at = NULL,
                    revoked_by = NULL
                WHERE agent_credentials.revoked_at IS NOT NULL
            """, (agent_id, key_hash, key_prefix, agent_type, hostname, now, created_by))
            return cur.rowcount == 1

    def rotate_agent_credential(self, agent_id: str, key_hash: str, key_prefix: str,
                                grace_seconds: int = 600) -> bool:
        """Swap in a new key; the old one stays valid for `grace_seconds` so an agent that
        never received the response can still authenticate and retry."""
        now = utcnow()
        with self._cursor() as cur:
            cur.execute("""
                UPDATE agent_credentials
                SET prev_key_hash = key_hash,
                    prev_valid_until = ?,
                    key_hash = ?,
                    key_prefix = ?,
                    rotated_at = ?
                WHERE agent_id = ? AND revoked_at IS NULL
            """, (utc_iso(now + timedelta(seconds=max(0, grace_seconds))), key_hash, key_prefix,
                  utc_iso(now), agent_id))
            return cur.rowcount == 1

    def revoke_agent_credential(self, agent_id: str, actor: Optional[str] = None) -> bool:
        with self._cursor() as cur:
            cur.execute("""
                UPDATE agent_credentials
                SET revoked_at = ?, revoked_by = ?, prev_key_hash = NULL, prev_valid_until = NULL
                WHERE agent_id = ? AND revoked_at IS NULL
            """, (utc_iso(), actor, agent_id))
            return cur.rowcount == 1

    def touch_agent_credential(self, agent_id: str, ip: Optional[str] = None) -> None:
        with self._cursor() as cur:
            cur.execute("UPDATE agent_credentials SET last_used_at = ?, last_ip = ? WHERE agent_id = ?",
                        (utc_iso(), ip, agent_id))

    # ==================== FLEET ====================

    def get_fleet_agent(self, agent_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM fleet WHERE agent_id = ?", (agent_id,))
            row = cur.fetchone()
        return self._fleet_row(row) if row else None

    def list_fleet_agents(self) -> List[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM fleet ORDER BY last_seen DESC")
            return [self._fleet_row(r) for r in cur.fetchall()]

    @staticmethod
    def _fleet_row(row) -> Dict:
        d = dict(row)
        for field in ("meta", "managed_settings"):
            try:
                d[field] = json.loads(d.get(field) or "{}")
            except ValueError:
                d[field] = {}
            if not isinstance(d[field], dict):
                d[field] = {}
        return d

    def record_fleet_checkin(self, agent_id: str, agent_type: str, hostname: str, os_info: str,
                             version: str, ip: Optional[str], user: str, scans: int,
                             incidents: int, meta: dict) -> None:
        """Upsert the agent's self-reported state. Server-owned `managed_settings` is untouched."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO fleet
                    (agent_id, agent_type, hostname, os, version, ip, user, last_seen,
                     scans_reported, incidents_reported, status, meta)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    agent_type = excluded.agent_type,
                    hostname = excluded.hostname,
                    os = excluded.os,
                    version = excluded.version,
                    ip = excluded.ip,
                    user = excluded.user,
                    last_seen = excluded.last_seen,
                    scans_reported = excluded.scans_reported,
                    incidents_reported = excluded.incidents_reported,
                    meta = excluded.meta
            """, (agent_id, agent_type, hostname, os_info, version, ip, user, utc_iso(),
                  int(scans or 0), int(incidents or 0), json.dumps(meta or {})))

    def set_fleet_managed_settings(self, agent_id: str, managed: dict, ip: Optional[str] = None) -> None:
        """Store console-managed settings, creating a placeholder row for a not-yet-seen agent."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO fleet
                    (agent_id, agent_type, hostname, os, version, ip, user, last_seen, status, meta,
                     managed_settings)
                VALUES (?, 'browser_extension', ?, 'unknown', '', ?, 'unknown', NULL, 'pending', '{}', ?)
                ON CONFLICT(agent_id) DO UPDATE SET managed_settings = excluded.managed_settings
            """, (agent_id, agent_id, ip, json.dumps(managed or {})))

    def delete_fleet_agent(self, agent_id: str) -> bool:
        with self._cursor() as cur:
            cur.execute("DELETE FROM fleet_commands WHERE agent_id = ?", (agent_id,))
            cur.execute("DELETE FROM fleet WHERE agent_id = ?", (agent_id,))
            return cur.rowcount == 1

    # ---- command queue ----

    def enqueue_fleet_command(self, agent_id: str, command: dict, max_queued: int = 20) -> int:
        """Queue a command for delivery at the agent's next check-in. Returns queue depth."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO fleet_commands (command_id, agent_id, payload, status, created_at)
                VALUES (?, ?, ?, 'queued', ?)
            """, (command["command_id"], agent_id, json.dumps(command), utc_iso()))
            # Keep only the newest `max_queued` undelivered commands per agent.
            cur.execute("""
                UPDATE fleet_commands SET status = 'superseded'
                WHERE agent_id = ? AND status = 'queued' AND command_id NOT IN (
                    SELECT command_id FROM fleet_commands
                    WHERE agent_id = ? AND status = 'queued'
                    ORDER BY created_at DESC, rowid DESC LIMIT ?
                )
            """, (agent_id, agent_id, max_queued))
            cur.execute("SELECT COUNT(*) FROM fleet_commands WHERE agent_id = ? AND status = 'queued'",
                        (agent_id,))
            return int(cur.fetchone()[0])

    def pop_fleet_command(self, agent_id: str) -> Optional[Dict]:
        """Atomically claim the oldest queued command for an agent."""
        conn = self._get_conn()
        cur = conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE")
            cur.execute("""
                SELECT command_id, payload FROM fleet_commands
                WHERE agent_id = ? AND status = 'queued'
                ORDER BY created_at ASC, rowid ASC LIMIT 1
            """, (agent_id,))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE fleet_commands SET status = 'delivered', delivered_at = ? WHERE command_id = ?",
                            (utc_iso(), row[0]))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        if not row:
            return None
        try:
            return json.loads(row[1])
        except ValueError:
            return None

    def list_fleet_commands(self, agent_id: str, limit: int = 50) -> List[Dict]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT command_id, status, created_at, delivered_at, payload FROM fleet_commands
                WHERE agent_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?
            """, (agent_id, limit))
            out = []
            for r in cur.fetchall():
                d = dict(r)
                try:
                    payload = json.loads(d.pop("payload") or "{}")
                except ValueError:
                    payload = {}
                d["type"] = payload.get("type")
                d["requested_by"] = payload.get("requested_by")
                d["target_version"] = payload.get("target_version")
                out.append(d)
            return out

    # ==================== INDEXED DOCUMENT MATCHING ====================

    def add_idm_document(self, name: str, description: str, sensitivity: str, content_sha256: str,
                         size_bytes: int, word_count: int, fingerprints: Iterable[int],
                         created_by: Optional[str] = None) -> str:
        doc_id = f"IDM-{uuid.uuid4().hex[:10].upper()}"
        fps = sorted(set(int(f) for f in fingerprints))
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO idm_documents
                    (doc_id, name, description, sensitivity, content_sha256, size_bytes, word_count,
                     fingerprint_count, is_active, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """, (doc_id, name, description, sensitivity, content_sha256, int(size_bytes),
                  int(word_count), len(fps), utc_iso(), created_by))
            cur.executemany("INSERT OR IGNORE INTO idm_fingerprints (fingerprint, doc_id) VALUES (?, ?)",
                            ((fp, doc_id) for fp in fps))
        return doc_id

    def list_idm_documents(self, active_only: bool = False) -> List[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM idm_documents" + (" WHERE is_active = 1" if active_only else "")
                        + " ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def get_idm_document(self, doc_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM idm_documents WHERE doc_id = ?", (doc_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def find_idm_document_by_hash(self, content_sha256: str) -> Optional[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM idm_documents WHERE content_sha256 = ? LIMIT 1", (content_sha256,))
            row = cur.fetchone()
            return dict(row) if row else None

    def set_idm_document_active(self, doc_id: str, active: bool) -> bool:
        with self._cursor() as cur:
            cur.execute("UPDATE idm_documents SET is_active = ? WHERE doc_id = ?", (1 if active else 0, doc_id))
            return cur.rowcount == 1

    def delete_idm_document(self, doc_id: str) -> bool:
        with self._cursor() as cur:
            cur.execute("DELETE FROM idm_fingerprints WHERE doc_id = ?", (doc_id,))
            cur.execute("DELETE FROM idm_documents WHERE doc_id = ?", (doc_id,))
            return cur.rowcount == 1

    def idm_generation(self) -> str:
        """Cheap change marker for in-memory index caches."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*), COALESCE(SUM(is_active), 0), COALESCE(MAX(created_at), '') FROM idm_documents")
            row = cur.fetchone()
        return f"{row[0]}:{row[1]}:{row[2]}"

    def idm_match_counts(self, fingerprints: Iterable[int]) -> Dict[str, int]:
        """Number of the given fingerprints present in each active document."""
        fps = list(set(int(f) for f in fingerprints))
        counts: Dict[str, int] = {}
        if not fps:
            return counts
        with self._cursor() as cur:
            for i in range(0, len(fps), 500):
                chunk = fps[i:i + 500]
                marks = ",".join("?" * len(chunk))
                cur.execute(f"""
                    SELECT f.doc_id, COUNT(*) FROM idm_fingerprints f
                    JOIN idm_documents d ON d.doc_id = f.doc_id AND d.is_active = 1
                    WHERE f.fingerprint IN ({marks})
                    GROUP BY f.doc_id
                """, chunk)
                for doc_id, n in cur.fetchall():
                    counts[doc_id] = counts.get(doc_id, 0) + int(n)
        return counts

    # ==================== SCREENSHOTS ====================

    def add_screenshot(self, entry: Dict) -> str:
        screenshot_id = f"SS-{uuid.uuid4().hex[:10].upper()}"
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO screenshots
                    (screenshot_id, created_at, agent_id, domain, user, incident_type, severity, url,
                     findings_summary, image_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (screenshot_id, utc_iso(), entry.get("agent_id"), entry.get("domain"), entry.get("user"),
                  entry.get("incident_type"), entry.get("severity"), entry.get("url"),
                  self.cipher.seal_text(entry.get("findings_summary") or ""),
                  self.cipher.seal_text(entry.get("image_data") or "")))
        return screenshot_id

    def list_screenshots(self, limit: int = 20) -> List[Dict]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT screenshot_id, created_at, agent_id, domain, user, incident_type, severity, url,
                       findings_summary
                FROM screenshots ORDER BY created_at DESC, rowid DESC LIMIT ?
            """, (max(1, min(int(limit or 20), 200)),))
            rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["findings_summary"] = self.cipher.open_text(r.get("findings_summary"))
            r["id"] = r["screenshot_id"]
            r["timestamp"] = r["created_at"]
        return rows

    def get_screenshot(self, screenshot_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM screenshots WHERE screenshot_id = ?", (screenshot_id,))
            row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["findings_summary"] = self.cipher.open_text(d.get("findings_summary"))
        d["image_data"] = self.cipher.open_text(d.get("image_data"))
        d["id"] = d["screenshot_id"]
        d["timestamp"] = d["created_at"]
        return d

    # ==================== SIEM OUTBOX ====================

    def siem_enqueue(self, destination: str, payload: dict, max_rows: int = 50_000) -> None:
        now = utc_iso()
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM siem_outbox")
            if int(cur.fetchone()[0]) >= max_rows:
                # Destination has been down for a long time: drop the oldest rather than grow forever.
                cur.execute("DELETE FROM siem_outbox WHERE id IN (SELECT id FROM siem_outbox ORDER BY id ASC LIMIT 1000)")
            cur.execute("""
                INSERT INTO siem_outbox (destination, payload, created_at, next_attempt_at)
                VALUES (?, ?, ?, ?)
            """, (destination, self.cipher.seal_text(json.dumps(payload)), now, now))

    def siem_due(self, limit: int = 100) -> List[Dict]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM siem_outbox WHERE next_attempt_at <= ? ORDER BY id ASC LIMIT ?
            """, (utc_iso(), limit))
            rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            try:
                r["payload"] = json.loads(self.cipher.open_text(r["payload"]))
            except (ValueError, TypeError):
                r["payload"] = {}
        return rows

    def siem_ack(self, row_id: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM siem_outbox WHERE id = ?", (row_id,))

    def siem_retry_later(self, row_id: int, attempts: int, error: str, max_attempts: int = 12) -> None:
        with self._cursor() as cur:
            if attempts >= max_attempts:
                cur.execute("DELETE FROM siem_outbox WHERE id = ?", (row_id,))
                return
            delay = min(3600, 15 * (2 ** min(attempts, 8)))
            cur.execute("""
                UPDATE siem_outbox SET attempts = ?, last_error = ?, next_attempt_at = ? WHERE id = ?
            """, (attempts, (error or "")[:500], utc_iso(utcnow() + timedelta(seconds=delay)), row_id))

    def siem_outbox_stats(self) -> Dict:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*), MIN(created_at), MAX(attempts) FROM siem_outbox")
            pending, oldest, max_attempts = cur.fetchone()
            cur.execute("SELECT last_error FROM siem_outbox WHERE last_error IS NOT NULL ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        return {"pending": int(pending or 0), "oldest": oldest, "max_attempts": int(max_attempts or 0),
                "last_error": row[0] if row else None}

    # ==================== RETENTION ====================

    def purge_older_than(self, days: Dict[str, int]) -> Dict[str, object]:
        """Delete rows past their retention period.

        `days` maps a data class to its retention in days; 0 or a missing key keeps the data
        forever. Returns per-class deleted counts plus `artifact_paths`, the files whose
        metadata rows were removed (the caller deletes them from disk).
        """
        now = utcnow()
        deleted: Dict[str, object] = {}
        artifact_paths: List[str] = []

        def cutoffs(n: int):
            cut = now - timedelta(days=n)
            # Tables mix UTC "YYYY-MM-DD HH:MM:SS" (SQLite default) and local ISO strings written
            # by the application; compare each against a cutoff in its own format.
            return (cut.strftime("%Y-%m-%d %H:%M:%S"),
                    cut.astimezone().replace(tzinfo=None).isoformat(timespec="seconds"),
                    utc_iso(cut))

        with self._cursor() as cur:
            n = int(days.get("events") or 0)
            if n > 0:
                sql_cut, local_cut, _ = cutoffs(n)
                cur.execute("DELETE FROM events WHERE timestamp < ? AND created_at < ?", (local_cut, sql_cut))
                deleted["events"] = cur.rowcount

            n = int(days.get("scan_results") or 0)
            if n > 0:
                sql_cut, _, _ = cutoffs(n)
                cur.execute("DELETE FROM scan_results WHERE timestamp < ?", (sql_cut,))
                deleted["scan_results"] = cur.rowcount

            n = int(days.get("artifacts") or 0)
            if n > 0:
                sql_cut, _, _ = cutoffs(n)
                cur.execute("SELECT content_path FROM upload_artifacts WHERE created_at < ?", (sql_cut,))
                artifact_paths = [r[0] for r in cur.fetchall() if r[0]]
                cur.execute("DELETE FROM upload_artifacts WHERE created_at < ?", (sql_cut,))
                deleted["artifacts"] = cur.rowcount

            n = int(days.get("screenshots") or 0)
            if n > 0:
                _, _, utc_cut = cutoffs(n)
                cur.execute("DELETE FROM screenshots WHERE created_at < ?", (utc_cut,))
                deleted["screenshots"] = cur.rowcount

            n = int(days.get("operational_logs") or 0)
            if n > 0:
                sql_cut, _, _ = cutoffs(n)
                cur.execute("DELETE FROM operational_logs WHERE timestamp < ?", (sql_cut,))
                deleted["operational_logs"] = cur.rowcount

            n = int(days.get("closed_incidents") or 0)
            if n > 0:
                sql_cut, local_cut, _ = cutoffs(n)
                cur.execute("""
                    DELETE FROM incidents
                    WHERE status IN ('CLOSED', 'AUTO-CLOSED')
                      AND COALESCE(closed_at, updated_at) < ?
                      AND COALESCE(closed_at, updated_at) < ?
                """, (sql_cut, local_cut))
                deleted["closed_incidents"] = cur.rowcount

            n = int(days.get("auth_sessions") or 0)
            if n > 0:
                _, local_cut, _ = cutoffs(n)
                cur.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (local_cut,))
                deleted["auth_sessions"] = cur.rowcount

            cur.execute("DELETE FROM fleet_commands WHERE status != 'queued' AND created_at < ?",
                        (utc_iso(now - timedelta(days=30)),))

        deleted["artifact_paths"] = artifact_paths
        return deleted

    # ==================== AUDIT CHAIN ====================

    def _append_audit_chained(self, action: str, target_type: Optional[str], target_id: Optional[str],
                              actor: Optional[str], details: Optional[str]) -> None:
        """Insert an audit row whose hash covers the previous row's hash."""
        conn = self._get_conn()
        if conn.in_transaction:
            conn.commit()
        cur = conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE")
            cur.execute("SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            prev_hash = row[0] if row else AUDIT_GENESIS
            timestamp = utcnow().strftime("%Y-%m-%d %H:%M:%S")
            entry_hash = audit_entry_hash(prev_hash, timestamp, action, target_type, target_id, actor, details)
            cur.execute("""
                INSERT INTO audit_log (timestamp, action, target_type, target_id, actor, details, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, action, target_type, target_id, actor, details, prev_hash, entry_hash))
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def verify_audit_chain(self) -> Dict:
        """Recompute the audit hash chain. Rows written before chaining was introduced
        (no entry_hash) are counted as `unchained` and skipped."""
        checked = 0
        unchained = 0
        prev = None
        with self._cursor() as cur:
            cur.execute("""
                SELECT id, timestamp, action, target_type, target_id, actor, details, prev_hash, entry_hash
                FROM audit_log ORDER BY id ASC
            """)
            for row in cur:
                if not row["entry_hash"]:
                    unchained += 1
                    continue
                expected_prev = prev if prev is not None else row["prev_hash"]
                computed = audit_entry_hash(row["prev_hash"] or "", row["timestamp"], row["action"],
                                            row["target_type"], row["target_id"], row["actor"], row["details"])
                if row["prev_hash"] != expected_prev or computed != row["entry_hash"]:
                    return {"ok": False, "checked": checked, "unchained": unchained,
                            "first_bad_id": row["id"]}
                prev = row["entry_hash"]
                checked += 1
        return {"ok": True, "checked": checked, "unchained": unchained, "head": prev}
