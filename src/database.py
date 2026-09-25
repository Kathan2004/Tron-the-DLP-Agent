"""
Persistent SQLite Database for TRON THE DLP AGENT System
Replaces in-memory storage with durable, queryable persistence.
"""

import sqlite3
import json
import os
import uuid
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from contextlib import contextmanager
from pathlib import Path

DB_DIR = Path(__file__).parent.parent / "data"
DB_PATH = DB_DIR / "tron_dlp.db"
# Pre-rename database file name. Migrated to DB_PATH on first start.
LEGACY_DB_PATH = DB_DIR / "sentinel_dlp.db"


def _migrate_legacy_db_name() -> None:
    """Rename data/sentinel_dlp.db (and its WAL/SHM files) to data/tron_dlp.db."""
    if DB_PATH.exists() or not LEGACY_DB_PATH.exists():
        return
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(LEGACY_DB_PATH) + suffix)
        if src.exists():
            src.rename(Path(str(DB_PATH) + suffix))
    print(f"Migrated database {LEGACY_DB_PATH.name} -> {DB_PATH.name}")


class Database:
    """Thread-safe SQLite database for DLP data persistence."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            _migrate_legacy_db_name()
        self.db_path = str(db_path or DB_PATH)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, timeout=30)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    @contextmanager
    def _cursor(self):
        """Context manager for database operations."""
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_schema(self):
        """Create database tables and handle migrations."""
        with self._cursor() as cur:
            # Check for old schema
            cur.execute("PRAGMA table_info(policies)")
            cols = [col[1] for col in cur.fetchall()]
            
            if cols and "regex_pattern" in cols:
                # Migrate old policies table to new structured rule_data format
                print("Migrating policies table schema...")
                cur.executescript("""
                    CREATE TABLE IF NOT EXISTS policies_migrated (
                        policy_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        rule_type TEXT DEFAULT 'regex',
                        rule_data TEXT NOT NULL,
                        severity TEXT DEFAULT 'MEDIUM',
                        action TEXT DEFAULT 'monitor',
                        threshold_count INTEGER DEFAULT 1,
                        threshold_window_mins INTEGER DEFAULT 60,
                        is_active INTEGER DEFAULT 1,
                        created_at TEXT DEFAULT (datetime('now')),
                        updated_at TEXT DEFAULT (datetime('now'))
                    );
                """)
                
                # Check if rule_data already exists in old table (partially migrated)
                if "rule_data" in cols:
                    cur.execute("""
                        INSERT OR IGNORE INTO policies_migrated 
                        SELECT policy_id, name, description, rule_type, 
                               COALESCE(rule_data, '{"pattern": "' || regex_pattern || '"}'), 
                               severity, action, threshold_count, threshold_window_mins, 
                               is_active, created_at, updated_at 
                        FROM policies
                    """)
                else:
                    cur.execute("""
                        INSERT OR IGNORE INTO policies_migrated 
                        SELECT policy_id, name, description, rule_type, 
                               '{"pattern": "' || regex_pattern || '"}', 
                               severity, 'monitor', threshold_count, threshold_window_mins, 
                               is_active, created_at, updated_at 
                        FROM policies
                    """)
                
                cur.execute("DROP TABLE policies")
                cur.execute("ALTER TABLE policies_migrated RENAME TO policies")

            cur.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    source_host TEXT NOT NULL,
                    user TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload_sample TEXT,
                    matched_rules TEXT,  -- JSON array
                    severity TEXT NOT NULL,
                    geo TEXT,  -- JSON object
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    user TEXT NOT NULL,
                    host TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    dedup_key TEXT,
                    risk INTEGER DEFAULT 50,
                    verdict TEXT DEFAULT 'NEEDS_REVIEW',
                    fp INTEGER DEFAULT 50,
                    status TEXT DEFAULT 'OPEN',
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now')),
                    alert_count INTEGER DEFAULT 0,
                    events TEXT,  -- JSON array of event_ids
                    ai_analysis TEXT,  -- JSON object
                    repeat_count INTEGER DEFAULT 0,
                    auto_escalated INTEGER DEFAULT 0,
                    assigned_to TEXT,
                    assigned_at TEXT,
                    classification TEXT DEFAULT 'NOT_SET',
                    initial_statement TEXT,
                    closure_statement TEXT,
                    closed_by TEXT,
                    closed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS security_team (
                    member_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT DEFAULT 'SOC_ANALYST',
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS app_users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'SOC_ANALYST',
                    manager_email TEXT,
                    timezone TEXT DEFAULT 'Asia/Kolkata',
                    locale TEXT DEFAULT 'en-IN',
                    theme_preference TEXT DEFAULT 'light',
                    notify_email INTEGER DEFAULT 1,
                    notify_telegram INTEGER DEFAULT 1,
                    is_active INTEGER DEFAULT 1,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TEXT,
                    must_change_password INTEGER DEFAULT 1,
                    password_changed_at TEXT,
                    last_login_at TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS iam_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL,
                    updated_at TEXT DEFAULT (datetime('now')),
                    updated_by TEXT
                );

                CREATE TABLE IF NOT EXISTS iam_role_permissions (
                    role TEXT NOT NULL,
                    permission_key TEXT NOT NULL,
                    is_allowed INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT DEFAULT (datetime('now')),
                    updated_by TEXT,
                    PRIMARY KEY (role, permission_key)
                );

                CREATE TABLE IF NOT EXISTS custom_roles (
                    role_key TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    description TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now')),
                    created_by TEXT,
                    updated_by TEXT
                );

                CREATE TABLE IF NOT EXISTS auth_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_seen_at TEXT,
                    revoked_at TEXT,
                    revoked_reason TEXT,
                    user_agent TEXT,
                    ip_address TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (user_id) REFERENCES app_users(user_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS incident_activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    actor TEXT,
                    note TEXT NOT NULL,
                    tags TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT (datetime('now')),
                    action TEXT NOT NULL,
                    target_type TEXT,  -- 'event', 'incident'
                    target_id TEXT,
                    actor TEXT,
                    details TEXT  -- JSON
                );

                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT (datetime('now')),
                    agent_id TEXT,
                    scan_type TEXT NOT NULL,  -- 'file', 'clipboard', 'network', 'process', 'log'
                    source TEXT NOT NULL,
                    findings TEXT,  -- JSON array
                    severity TEXT,
                    file_path TEXT,
                    file_hash TEXT,
                    file_size INTEGER,
                    user TEXT,
                    host TEXT,
                    sent_to_api INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    rule_type TEXT DEFAULT 'regex',
                    rule_data TEXT NOT NULL,
                    severity TEXT DEFAULT 'MEDIUM',
                    action TEXT DEFAULT 'monitor',
                    threshold_count INTEGER DEFAULT 1,
                    threshold_window_mins INTEGER DEFAULT 60,
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS policy_exceptions (
                    exception_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    scope_type TEXT DEFAULT 'global',
                    policy_id TEXT,
                    policy_ids TEXT,
                    mode TEXT DEFAULT 'allow_and_log',
                    users TEXT,
                    senders TEXT,
                    recipients TEXT,
                    domains TEXT,
                    expires_at TEXT,
                    ticket_id TEXT,
                    reason TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS fleet (
                    agent_id TEXT PRIMARY KEY,
                    agent_type TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    os TEXT,
                    version TEXT,
                    ip TEXT,
                    user TEXT,
                    last_seen TEXT,
                    scans_reported INTEGER DEFAULT 0,
                    incidents_reported INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'online',
                    meta TEXT  -- JSON for additional details
                );

                CREATE TABLE IF NOT EXISTS operational_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    timestamp TEXT DEFAULT (datetime('now')),
                    event_type TEXT,
                    message TEXT,
                    details TEXT
                );

                CREATE TABLE IF NOT EXISTS upload_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    agent_id TEXT,
                    scan_id TEXT,
                    hostname TEXT,
                    user TEXT,
                    source_host TEXT,
                    file_name TEXT,
                    file_type TEXT,
                    file_size INTEGER,
                    action TEXT,
                    severity TEXT,
                    findings TEXT,
                    content_path TEXT,
                    content_sha256 TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(user);
                CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
                CREATE INDEX IF NOT EXISTS idx_scan_results_type ON scan_results(scan_type);
                CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp);
                CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(is_active);
                CREATE INDEX IF NOT EXISTS idx_exceptions_active_scope ON policy_exceptions(is_active, scope_type, policy_id);
                CREATE INDEX IF NOT EXISTS idx_fleet_last_seen ON fleet(last_seen);
                CREATE INDEX IF NOT EXISTS idx_artifacts_agent_created ON upload_artifacts(agent_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_activity_incident ON incident_activity_logs(incident_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_app_users_email ON app_users(email);
                CREATE INDEX IF NOT EXISTS idx_app_users_role_active ON app_users(role, is_active);
                CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id, issued_at);
                CREATE INDEX IF NOT EXISTS idx_auth_sessions_active ON auth_sessions(revoked_at, expires_at);
                CREATE INDEX IF NOT EXISTS idx_custom_roles_active ON custom_roles(is_active);
            """)
            
            # Seed default policies if empty
            # --- MIGRATION: Add missing columns if they don't exist ---
            cur.execute("PRAGMA table_info(policies)")
            columns = [c[1] for c in cur.fetchall()]
            if 'rule_type' not in columns:
                cur.execute("ALTER TABLE policies ADD COLUMN rule_type TEXT DEFAULT 'regex'")
            if 'rule_data' not in columns:
                # If rule_data didn't exist, migrate regex_pattern into rule_data
                cur.execute("ALTER TABLE policies ADD COLUMN rule_data TEXT")
                if 'regex_pattern' in columns:
                    cur.execute("UPDATE policies SET rule_data = '{\"pattern\": \"' || regex_pattern || '\"}'")
            if 'action' not in columns:
                cur.execute("ALTER TABLE policies ADD COLUMN action TEXT DEFAULT 'monitor'")
            if 'updated_by' not in columns:
                cur.execute("ALTER TABLE policies ADD COLUMN updated_by TEXT")
            # scan_results migration for per-agent isolation
            cur.execute("PRAGMA table_info(scan_results)")
            scan_cols = [c[1] for c in cur.fetchall()]
            if 'agent_id' not in scan_cols:
                cur.execute("ALTER TABLE scan_results ADD COLUMN agent_id TEXT")
            # upload_artifacts migration for precise incident evidence linkage
            cur.execute("PRAGMA table_info(upload_artifacts)")
            art_cols = [c[1] for c in cur.fetchall()]
            if 'scan_id' not in art_cols:
                cur.execute("ALTER TABLE upload_artifacts ADD COLUMN scan_id TEXT")

            # policy_exceptions migration for multi-policy scope support
            cur.execute("PRAGMA table_info(policy_exceptions)")
            ex_cols = [c[1] for c in cur.fetchall()]
            if 'policy_ids' not in ex_cols:
                cur.execute("ALTER TABLE policy_exceptions ADD COLUMN policy_ids TEXT")
            if 'updated_by' not in ex_cols:
                cur.execute("ALTER TABLE policy_exceptions ADD COLUMN updated_by TEXT")

            # incidents workflow migration
            cur.execute("PRAGMA table_info(incidents)")
            incident_cols = [c[1] for c in cur.fetchall()]
            if 'dedup_key' not in incident_cols:
                cur.execute("ALTER TABLE incidents ADD COLUMN dedup_key TEXT")
            if 'assigned_to' not in incident_cols:
                cur.execute("ALTER TABLE incidents ADD COLUMN assigned_to TEXT")
            if 'assigned_at' not in incident_cols:
                cur.execute("ALTER TABLE incidents ADD COLUMN assigned_at TEXT")
            if 'classification' not in incident_cols:
                cur.execute("ALTER TABLE incidents ADD COLUMN classification TEXT DEFAULT 'NOT_SET'")
            if 'initial_statement' not in incident_cols:
                cur.execute("ALTER TABLE incidents ADD COLUMN initial_statement TEXT")
            if 'closure_statement' not in incident_cols:
                cur.execute("ALTER TABLE incidents ADD COLUMN closure_statement TEXT")
            if 'closed_by' not in incident_cols:
                cur.execute("ALTER TABLE incidents ADD COLUMN closed_by TEXT")
            if 'closed_at' not in incident_cols:
                cur.execute("ALTER TABLE incidents ADD COLUMN closed_at TEXT")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_dedup_key ON incidents(dedup_key)")
            try:
                cur.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_active_dedup
                    ON incidents(dedup_key)
                    WHERE dedup_key IS NOT NULL
                      AND status IN ('OPEN', 'ESCALATED')
                """)
            except sqlite3.IntegrityError:
                # If legacy duplicates exist, keep service healthy; app-level merge still applies.
                pass
            cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to ON incidents(assigned_to)")
            # Create scan_id index only after ensuring the column exists.
            cur.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_scan_id ON upload_artifacts(scan_id)")

            # app_users migration
            cur.execute("PRAGMA table_info(app_users)")
            user_cols = [c[1] for c in cur.fetchall()]
            if user_cols:
                if 'manager_email' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN manager_email TEXT")
                if 'last_login_at' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN last_login_at TEXT")
                if 'timezone' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN timezone TEXT DEFAULT 'Asia/Kolkata'")
                if 'locale' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN locale TEXT DEFAULT 'en-IN'")
                if 'theme_preference' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN theme_preference TEXT DEFAULT 'light'")
                if 'notify_email' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN notify_email INTEGER DEFAULT 1")
                if 'notify_telegram' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN notify_telegram INTEGER DEFAULT 1")
                if 'failed_login_attempts' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
                if 'locked_until' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN locked_until TEXT")
                if 'must_change_password' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN must_change_password INTEGER DEFAULT 1")
                if 'password_changed_at' not in user_cols:
                    cur.execute("ALTER TABLE app_users ADD COLUMN password_changed_at TEXT")

            # auth_sessions migration for older deployments
            cur.execute("PRAGMA table_info(auth_sessions)")
            auth_session_cols = [c[1] for c in cur.fetchall()]
            if auth_session_cols:
                if 'last_seen_at' not in auth_session_cols:
                    cur.execute("ALTER TABLE auth_sessions ADD COLUMN last_seen_at TEXT")
                if 'revoked_at' not in auth_session_cols:
                    cur.execute("ALTER TABLE auth_sessions ADD COLUMN revoked_at TEXT")
                if 'revoked_reason' not in auth_session_cols:
                    cur.execute("ALTER TABLE auth_sessions ADD COLUMN revoked_reason TEXT")
                if 'user_agent' not in auth_session_cols:
                    cur.execute("ALTER TABLE auth_sessions ADD COLUMN user_agent TEXT")
                if 'ip_address' not in auth_session_cols:
                    cur.execute("ALTER TABLE auth_sessions ADD COLUMN ip_address TEXT")

            cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id, issued_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_active ON auth_sessions(revoked_at, expires_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_custom_roles_active ON custom_roles(is_active)")
            # ---------------------------------------------------------

            # Seed security team if empty
            cur.execute("SELECT COUNT(*) FROM security_team")
            if cur.fetchone()[0] == 0:
                default_team = [
                    ("SEC-01", "SOC Analyst 1", "soc.analyst1@tron.local", "SOC_ANALYST", 1),
                    ("SEC-02", "SOC Analyst 2", "soc.analyst2@tron.local", "SOC_ANALYST", 1),
                    ("SEC-03", "Incident Responder", "ir.lead@tron.local", "IR_LEAD", 1),
                ]
                cur.executemany("""
                    INSERT INTO security_team (member_id, display_name, email, role, is_active)
                    VALUES (?, ?, ?, ?, ?)
                """, default_team)

            cur.execute("SELECT COUNT(*) FROM policies")
            if cur.fetchone()[0] == 0:
                defaults = [
                    ("POL-DEFAULT-1", "SSN_PATTERN", "US Social Security Number", "regex", json.dumps({"pattern": r"\b\d{3}-\d{2}-\d{4}\b"}), "HIGH", "monitor", 3, 30),
                    ("POL-DEFAULT-2", "CREDIT_CARD", "Credit Card (formatted)", "regex", json.dumps({"pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b"}), "CRITICAL", "monitor", 1, 60),
                    ("POL-DEFAULT-3", "IBAN", "IBAN Account Number", "regex", json.dumps({"pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b"}), "HIGH", "monitor", 3, 30),
                    ("POL-DEFAULT-4", "PAN_INDIA", "India PAN Card", "regex", json.dumps({"pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"}), "HIGH", "monitor", 3, 30),
                    ("POL-DEFAULT-5", "AADHAAR", "India Aadhaar Card", "regex", json.dumps({"pattern": r"\b\d{4}\s?\d{4}\s?\d{4}\b"}), "HIGH", "monitor", 3, 30),
                    ("POL-DEFAULT-11", "LARGE_UPLOAD", "Block Large File Uploads (>10MB)", "file_size", json.dumps({"max_size_mb": 10}), "HIGH", "block", 1, 60)
                ]
                cur.executemany("""
                    INSERT INTO policies 
                    (policy_id, name, description, rule_type, rule_data, severity, action, threshold_count, threshold_window_mins)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, defaults)

    # ==================== EVENT OPERATIONS ====================

    def add_event(self, event_id: str, timestamp: str, agent_type: str,
                  source_host: str, user: str, channel: str,
                  payload_hash: str, payload_sample: str,
                  matched_rules: List[str], severity: str,
                  geo: Optional[dict] = None) -> str:
        """Store a detection event."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT OR REPLACE INTO events
                (event_id, timestamp, agent_type, source_host, user, channel,
                 payload_hash, payload_sample, matched_rules, severity, geo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id, timestamp, agent_type, source_host, user, channel,
                payload_hash, payload_sample,
                json.dumps(matched_rules),
                severity,
                json.dumps(geo or {})
            ))
        self._log_audit("event_created", "event", event_id, user)
        return event_id

    def get_event(self, event_id: str) -> Optional[Dict]:
        """Get event by ID."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
            row = cur.fetchone()
            if row:
                return self._row_to_event_dict(row)
        return None

    def get_recent_events(self, user: str, minutes: int = 30) -> List[Dict]:
        """Get user's events in last N minutes."""
        cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM events
                WHERE user = ? AND timestamp > ?
                ORDER BY timestamp DESC
            """, (user, cutoff))
            return [self._row_to_event_dict(row) for row in cur.fetchall()]

    def get_all_events(self, limit: int = 100) -> List[Dict]:
        """Get all events, newest first."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [self._row_to_event_dict(row) for row in cur.fetchall()]

    # ==================== INCIDENT OPERATIONS ====================

    def create_incident(self, user: str, host: str, channel: str,
                        pattern: str, risk: int, events: List[str], dedup_key: Optional[str] = None) -> Optional[Dict]:
        """Create a new incident."""
        incident_id = f"INC-{str(uuid.uuid4())[:8].upper()}"
        now = datetime.now().isoformat()
        dedup_value = str(dedup_key or '').strip() or None
        # Do NOT auto-assign at creation. Analysts must explicitly assign via dashboard.
        try:
            with self._cursor() as cur:
                cur.execute("""
                    INSERT INTO incidents
                    (incident_id, user, host, channel, pattern, dedup_key, risk, verdict, fp,
                     status, created_at, updated_at, alert_count, events, repeat_count, auto_escalated,
                     assigned_to, assigned_at, classification)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'NEEDS_REVIEW', 50, 'OPEN', ?, ?, ?, ?, 0, 0, NULL, NULL, 'NOT_SET')
                """, (
                    incident_id, user, host, channel, pattern, dedup_value, risk,
                    now, now, len(events), json.dumps(events)
                ))
        except sqlite3.IntegrityError:
            if dedup_value:
                with self._cursor() as cur:
                    cur.execute("""
                        SELECT * FROM incidents
                        WHERE dedup_key = ? AND status IN ('OPEN', 'ESCALATED')
                        ORDER BY created_at DESC
                        LIMIT 1
                    """, (dedup_value,))
                    row = cur.fetchone()
                    if row:
                        return self._row_to_incident_dict(row)
            raise
        self._log_audit("incident_created", "incident", incident_id, user)
        return self.get_incident(incident_id)

    def get_incident(self, incident_id: str) -> Optional[Dict]:
        """Get incident by ID."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cur.fetchone()
            if row:
                return self._row_to_incident_dict(row)
        return None

    def get_all_incidents(self, status: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get all incidents, optionally filtered."""
        with self._cursor() as cur:
            if status:
                cur.execute("""
                    SELECT * FROM incidents WHERE status = ?
                    ORDER BY created_at DESC LIMIT ?
                """, (status, limit))
            else:
                cur.execute("""
                    SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?
                """, (limit,))
            return [self._row_to_incident_dict(row) for row in cur.fetchall()]

    def get_active_incident_for_user(self, user: str) -> Optional[Dict]:
        """Get active incident for user (within 24h)."""
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM incidents
                WHERE user = ? AND created_at > ? AND status IN ('OPEN', 'ESCALATED')
                ORDER BY created_at DESC LIMIT 1
            """, (user, cutoff))
            row = cur.fetchone()
            if row:
                return self._row_to_incident_dict(row)
        return None

    def update_incident(self, incident_id: str, **kwargs) -> Optional[Dict]:
        """Update incident fields."""
        allowed_fields = {
            'verdict', 'fp', 'risk', 'status', 'ai_analysis',
            'alert_count', 'repeat_count', 'auto_escalated', 'events',
            'assigned_to', 'assigned_at', 'classification',
            'initial_statement', 'closure_statement', 'closed_by', 'closed_at'
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        if not updates:
            return self.get_incident(incident_id)

        # Serialize JSON fields
        if 'ai_analysis' in updates and isinstance(updates['ai_analysis'], dict):
            updates['ai_analysis'] = json.dumps(updates['ai_analysis'])
        if 'events' in updates and isinstance(updates['events'], list):
            updates['events'] = json.dumps(updates['events'])

        updates['updated_at'] = datetime.now().isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [incident_id]

        with self._cursor() as cur:
            cur.execute(
                f"UPDATE incidents SET {set_clause} WHERE incident_id = ?",
                values
            )
        self._log_audit("incident_updated", "incident", incident_id, details=json.dumps(list(kwargs.keys())))
        return self.get_incident(incident_id)

    def close_incident(self, incident_id: str, reason: str = "user_closed") -> Optional[Dict]:
        """Close an incident."""
        result = self.update_incident(incident_id, status="CLOSED")
        if result:
            self._log_audit("incident_closed", "incident", incident_id, details=reason)
        return result

    def escalate_incident(self, incident_id: str) -> Optional[Dict]:
        """Escalate an incident."""
        result = self.update_incident(incident_id, status="ESCALATED")
        if result:
            self._log_audit("incident_escalated", "incident", incident_id)
        return result

    def raise_ticket(self, incident_id: str, actor: str = "secops_analyst") -> Optional[Dict]:
        """Mark an incident as ticket raised."""
        result = self.update_incident(incident_id, status="TICKET_RAISED")
        if result:
            self._log_audit("incident_ticket_raised", "incident", incident_id, actor=actor)
        return result

    def reopen_incident(self, incident_id: str, actor: str = "secops_analyst") -> Optional[Dict]:
        """Reopen a previously closed/ticketed incident."""
        result = self.update_incident(
            incident_id,
            status="OPEN",
            closed_by=None,
            closed_at=None,
        )
        if result:
            self._log_audit("incident_reopened", "incident", incident_id, actor=actor)
        return result

    def get_security_team(self, active_only: bool = True) -> List[Dict]:
        """Return security team members."""
        # Prefer admin-managed app users for assignment/workflow.
        with self._cursor() as cur:
            cur.execute("""
                SELECT user_id, display_name, email, role, is_active, manager_email, created_at, updated_at
                FROM app_users
                WHERE role IN ('SUPER_ADMIN', 'SECURITY_ADMIN', 'SOC_ANALYST')
                ORDER BY role ASC, display_name ASC
            """)
            app_rows = [dict(r) for r in cur.fetchall()]

        if active_only:
            app_rows = [r for r in app_rows if int(r.get('is_active', 0)) == 1]
        if app_rows:
            # Backward compatible shape with existing security_team responses.
            return [
                {
                    'member_id': r.get('user_id'),
                    'display_name': r.get('display_name'),
                    'email': r.get('email'),
                    'role': r.get('role'),
                    'is_active': int(r.get('is_active', 0)),
                    'manager_email': r.get('manager_email'),
                    'created_at': r.get('created_at'),
                    'updated_at': r.get('updated_at'),
                }
                for r in app_rows
            ]

        # Fallback to legacy table for older deployments.
        with self._cursor() as cur:
            if active_only:
                cur.execute("""
                    SELECT * FROM security_team
                    WHERE is_active = 1
                    ORDER BY role ASC, display_name ASC
                """)
            else:
                cur.execute("SELECT * FROM security_team ORDER BY role ASC, display_name ASC")
            return [dict(r) for r in cur.fetchall()]

    def get_next_assignee(self) -> Optional[Dict]:
        """Pick next assignee by least number of open incidents."""
        # Prefer admin-managed app users.
        with self._cursor() as cur:
            cur.execute("""
                SELECT au.user_id as member_id, au.display_name, au.email, au.role,
                       COALESCE(SUM(CASE WHEN i.status IN ('OPEN', 'ESCALATED') THEN 1 ELSE 0 END), 0) AS open_count
                FROM app_users au
                LEFT JOIN incidents i ON i.assigned_to = au.email
                WHERE au.is_active = 1
                  AND au.role IN ('SUPER_ADMIN', 'SECURITY_ADMIN', 'SOC_ANALYST')
                GROUP BY au.user_id, au.display_name, au.email, au.role
                ORDER BY open_count ASC, au.display_name ASC
                LIMIT 1
            """)
            row = cur.fetchone()
            if row:
                return dict(row)

        # Fallback to legacy security_team.
        with self._cursor() as cur:
            cur.execute("""
                SELECT st.member_id, st.display_name, st.email, st.role,
                       COALESCE(SUM(CASE WHEN i.status IN ('OPEN', 'ESCALATED') THEN 1 ELSE 0 END), 0) AS open_count
                FROM security_team st
                LEFT JOIN incidents i ON i.assigned_to = st.email
                WHERE st.is_active = 1
                GROUP BY st.member_id, st.display_name, st.email, st.role
                ORDER BY open_count ASC, st.display_name ASC
                LIMIT 1
            """)
            row = cur.fetchone()
            return dict(row) if row else None

    # ==================== APP USER AUTH OPERATIONS ====================

    def count_app_users(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) as c FROM app_users")
            row = cur.fetchone()
            return int(row['c'] if row else 0)

    def get_app_user_by_email(self, email: str) -> Optional[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM app_users WHERE lower(email) = lower(?) LIMIT 1", (email,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_app_user_by_id(self, user_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM app_users WHERE user_id = ? LIMIT 1", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_app_users(self, active_only: bool = False) -> List[Dict]:
        with self._cursor() as cur:
            if active_only:
                cur.execute("SELECT * FROM app_users WHERE is_active = 1 ORDER BY role ASC, display_name ASC")
            else:
                cur.execute("SELECT * FROM app_users ORDER BY role ASC, display_name ASC")
            return [dict(r) for r in cur.fetchall()]

    def create_app_user(self,
                        email: str,
                        display_name: str,
                        password_hash: str,
                        role: str = 'SOC_ANALYST',
                        manager_email: Optional[str] = None,
                        is_active: bool = True,
                        must_change_password: bool = True) -> Optional[Dict]:
        user_id = f"USR-{str(uuid.uuid4())[:8].upper()}"
        now = datetime.now().isoformat()
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO app_users
                (user_id, email, display_name, password_hash, role, manager_email, is_active,
                 failed_login_attempts, locked_until, must_change_password, password_changed_at,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, NULL, ?, ?)
            """, (
                user_id,
                (email or '').strip().lower(),
                (display_name or '').strip(),
                password_hash,
                (role or 'SOC_ANALYST').strip().upper(),
                (manager_email or '').strip().lower() or None,
                1 if bool(is_active) else 0,
                1 if bool(must_change_password) else 0,
                now,
                now,
            ))
        self._log_audit("app_user_created", "user", user_id, actor=email)
        return self.get_app_user_by_id(user_id)

    def update_app_user(self, user_id: str, **kwargs) -> Optional[Dict]:
        allowed = {
            'display_name', 'password_hash', 'role', 'manager_email', 'is_active', 'last_login_at',
            'failed_login_attempts', 'locked_until', 'must_change_password', 'password_changed_at',
            'timezone', 'locale', 'theme_preference', 'notify_email', 'notify_telegram'
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_app_user_by_id(user_id)

        if 'role' in updates and updates['role']:
            updates['role'] = str(updates['role']).strip().upper()
        if 'manager_email' in updates:
            updates['manager_email'] = str(updates['manager_email'] or '').strip().lower() or None
        if 'display_name' in updates and updates['display_name'] is not None:
            updates['display_name'] = str(updates['display_name']).strip()
        if 'is_active' in updates:
            updates['is_active'] = 1 if bool(updates['is_active']) else 0
        if 'must_change_password' in updates:
            updates['must_change_password'] = 1 if bool(updates['must_change_password']) else 0
        if 'failed_login_attempts' in updates:
            updates['failed_login_attempts'] = int(updates['failed_login_attempts'] or 0)
        if 'notify_email' in updates:
            updates['notify_email'] = 1 if bool(updates['notify_email']) else 0
        if 'notify_telegram' in updates:
            updates['notify_telegram'] = 1 if bool(updates['notify_telegram']) else 0
        if 'timezone' in updates and updates['timezone'] is not None:
            updates['timezone'] = str(updates['timezone']).strip() or 'Asia/Kolkata'
        if 'locale' in updates and updates['locale'] is not None:
            updates['locale'] = str(updates['locale']).strip() or 'en-IN'
        if 'theme_preference' in updates and updates['theme_preference'] is not None:
            updates['theme_preference'] = str(updates['theme_preference']).strip() or 'light'

        updates['updated_at'] = datetime.now().isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [user_id]

        with self._cursor() as cur:
            cur.execute(f"UPDATE app_users SET {set_clause} WHERE user_id = ?", values)

        self._log_audit("app_user_updated", "user", user_id)
        return self.get_app_user_by_id(user_id)

    def count_active_users_by_role(self, role: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) as c
                FROM app_users
                WHERE is_active = 1 AND upper(role) = upper(?)
                """,
                (role,)
            )
            row = cur.fetchone()
            return int(row['c'] if row else 0)

    def count_users_by_role(self, role: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) as c
                FROM app_users
                WHERE upper(role) = upper(?)
                """,
                (role,)
            )
            row = cur.fetchone()
            return int(row['c'] if row else 0)

    # ==================== CUSTOM ROLE OPERATIONS ====================

    def list_custom_roles(self, active_only: bool = False) -> List[Dict]:
        with self._cursor() as cur:
            if active_only:
                cur.execute("SELECT * FROM custom_roles WHERE is_active = 1 ORDER BY role_key ASC")
            else:
                cur.execute("SELECT * FROM custom_roles ORDER BY role_key ASC")
            return [dict(r) for r in cur.fetchall()]

    def get_custom_role(self, role_key: str) -> Optional[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM custom_roles WHERE upper(role_key)=upper(?) LIMIT 1", (role_key,))
            row = cur.fetchone()
            return dict(row) if row else None

    def create_custom_role(self,
                           role_key: str,
                           display_name: str,
                           description: str = '',
                           is_active: bool = True,
                           actor: Optional[str] = None) -> Optional[Dict]:
        key = str(role_key or '').strip().upper()
        now = datetime.now().isoformat()
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO custom_roles (role_key, display_name, description, is_active, created_at, updated_at, created_by, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    str(display_name or '').strip() or key,
                    str(description or '').strip(),
                    1 if bool(is_active) else 0,
                    now,
                    now,
                    actor,
                    actor,
                ),
            )
        self._log_audit("custom_role_created", "role", key, actor=actor)
        return self.get_custom_role(key)

    def update_custom_role(self, role_key: str, **kwargs) -> Optional[Dict]:
        allowed = {'display_name', 'description', 'is_active', 'updated_by'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_custom_role(role_key)

        if 'display_name' in updates:
            updates['display_name'] = str(updates['display_name'] or '').strip() or str(role_key or '').strip().upper()
        if 'description' in updates:
            updates['description'] = str(updates['description'] or '').strip()
        if 'is_active' in updates:
            updates['is_active'] = 1 if bool(updates['is_active']) else 0

        updates['updated_at'] = datetime.now().isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [str(role_key or '').strip().upper()]

        with self._cursor() as cur:
            cur.execute(f"UPDATE custom_roles SET {set_clause} WHERE upper(role_key)=upper(?)", values)

        key = str(role_key or '').strip().upper()
        self._log_audit("custom_role_updated", "role", key, actor=str(kwargs.get('updated_by') or ''))
        return self.get_custom_role(key)

    def delete_custom_role(self, role_key: str, actor: Optional[str] = None) -> bool:
        key = str(role_key or '').strip().upper()
        with self._cursor() as cur:
            cur.execute("DELETE FROM custom_roles WHERE upper(role_key)=upper(?)", (key,))
            changed = cur.rowcount > 0
        if changed:
            self._log_audit("custom_role_deleted", "role", key, actor=actor)
        return changed

    # ==================== IAM SETTINGS / PERMISSIONS ====================

    def get_iam_settings(self) -> Dict:
        with self._cursor() as cur:
            cur.execute("SELECT setting_key, setting_value FROM iam_settings")
            rows = cur.fetchall()
        out: Dict[str, object] = {}
        for row in rows:
            key = str(row['setting_key'])
            raw = row['setting_value']
            try:
                out[key] = json.loads(raw)
            except Exception:
                out[key] = raw
        return out

    def upsert_iam_settings(self, settings: Dict, actor: Optional[str] = None) -> Dict:
        now = datetime.now().isoformat()
        with self._cursor() as cur:
            for k, v in (settings or {}).items():
                cur.execute(
                    """
                    INSERT INTO iam_settings (setting_key, setting_value, updated_at, updated_by)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(setting_key) DO UPDATE SET
                        setting_value=excluded.setting_value,
                        updated_at=excluded.updated_at,
                        updated_by=excluded.updated_by
                    """,
                    (str(k), json.dumps(v), now, actor)
                )
        self._log_audit("iam_settings_updated", "iam", "global", actor=actor)
        return self.get_iam_settings()

    def get_role_permission_overrides(self) -> Dict[str, Dict[str, bool]]:
        with self._cursor() as cur:
            cur.execute("SELECT role, permission_key, is_allowed FROM iam_role_permissions")
            rows = cur.fetchall()
        out: Dict[str, Dict[str, bool]] = {}
        for row in rows:
            role = str(row['role'] or '').upper()
            if not role:
                continue
            out.setdefault(role, {})[str(row['permission_key'])] = bool(row['is_allowed'])
        return out

    def replace_role_permission_overrides(self, role: str, permissions: Dict[str, bool], actor: Optional[str] = None) -> None:
        role_u = str(role or '').strip().upper()
        if not role_u:
            return
        now = datetime.now().isoformat()
        with self._cursor() as cur:
            cur.execute("DELETE FROM iam_role_permissions WHERE upper(role)=upper(?)", (role_u,))
            rows = [
                (role_u, str(pk), 1 if bool(v) else 0, now, actor)
                for pk, v in (permissions or {}).items()
            ]
            if rows:
                cur.executemany(
                    """
                    INSERT INTO iam_role_permissions (role, permission_key, is_allowed, updated_at, updated_by)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    rows,
                )
        self._log_audit("iam_role_permissions_updated", "iam_role", role_u, actor=actor)

    def delete_role_permission_overrides(self, role: str, actor: Optional[str] = None) -> bool:
        role_u = str(role or '').strip().upper()
        if not role_u:
            return False
        with self._cursor() as cur:
            cur.execute("DELETE FROM iam_role_permissions WHERE upper(role)=upper(?)", (role_u,))
            changed = cur.rowcount > 0
        if changed:
            self._log_audit("iam_role_permissions_cleared", "iam_role", role_u, actor=actor)
        return changed

    # ==================== AUTH SESSION OPERATIONS ====================

    def create_auth_session(self,
                            user_id: str,
                            issued_at: str,
                            expires_at: str,
                            user_agent: Optional[str] = None,
                            ip_address: Optional[str] = None) -> str:
        session_id = f"SES-{uuid.uuid4().hex[:24].upper()}"
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO auth_sessions
                (session_id, user_id, issued_at, expires_at, last_seen_at, revoked_at, revoked_reason, user_agent, ip_address)
                VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (session_id, user_id, issued_at, expires_at, issued_at, user_agent, ip_address)
            )
        return session_id

    def get_auth_session(self, session_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM auth_sessions WHERE session_id = ? LIMIT 1", (session_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def touch_auth_session(self, session_id: str, seen_at: Optional[str] = None) -> None:
        ts = seen_at or datetime.now().isoformat()
        with self._cursor() as cur:
            cur.execute(
                """
                UPDATE auth_sessions
                SET last_seen_at = ?
                WHERE session_id = ? AND revoked_at IS NULL
                """,
                (ts, session_id)
            )

    def list_user_auth_sessions(self, user_id: str, include_revoked: bool = False) -> List[Dict]:
        with self._cursor() as cur:
            if include_revoked:
                cur.execute(
                    """
                    SELECT * FROM auth_sessions
                    WHERE user_id = ?
                    ORDER BY issued_at DESC
                    """,
                    (user_id,)
                )
            else:
                cur.execute(
                    """
                    SELECT * FROM auth_sessions
                    WHERE user_id = ? AND revoked_at IS NULL
                    ORDER BY issued_at DESC
                    """,
                    (user_id,)
                )
            return [dict(r) for r in cur.fetchall()]

    def revoke_auth_session(self, session_id: str, reason: str = 'manual_revoke') -> bool:
        now = datetime.now().isoformat()
        with self._cursor() as cur:
            cur.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = COALESCE(revoked_at, ?),
                    revoked_reason = COALESCE(revoked_reason, ?)
                WHERE session_id = ?
                """,
                (now, reason, session_id)
            )
            changed = cur.rowcount > 0
        if changed:
            self._log_audit("auth_session_revoked", "session", session_id, details=reason)
        return changed

    def revoke_user_sessions(self, user_id: str, except_session_id: Optional[str] = None, reason: str = 'admin_revoke_all') -> int:
        now = datetime.now().isoformat()
        with self._cursor() as cur:
            if except_session_id:
                cur.execute(
                    """
                    UPDATE auth_sessions
                    SET revoked_at = COALESCE(revoked_at, ?),
                        revoked_reason = COALESCE(revoked_reason, ?)
                    WHERE user_id = ? AND session_id != ? AND revoked_at IS NULL
                    """,
                    (now, reason, user_id, except_session_id)
                )
            else:
                cur.execute(
                    """
                    UPDATE auth_sessions
                    SET revoked_at = COALESCE(revoked_at, ?),
                        revoked_reason = COALESCE(revoked_reason, ?)
                    WHERE user_id = ? AND revoked_at IS NULL
                    """,
                    (now, reason, user_id)
                )
            count = cur.rowcount
        if count > 0:
            self._log_audit("auth_sessions_revoked_for_user", "user", user_id, details=reason)
        return count

    def assign_incident(self, incident_id: str, assignee: str, actor: str = "system") -> Optional[Dict]:
        """Assign incident to analyst email."""
        now = datetime.now().isoformat()
        updated = self.update_incident(incident_id, assigned_to=assignee, assigned_at=now)
        if updated:
            self.add_incident_activity_log(
                incident_id=incident_id,
                stage="assignment",
                actor=actor,
                note=f"Assigned to {assignee}",
                tags=["ASSIGNMENT"]
            )
        return updated

    def add_incident_activity_log(self,
                                  incident_id: str,
                                  stage: str,
                                  actor: str,
                                  note: str,
                                  tags: Optional[List[str]] = None) -> Optional[int]:
        """Add a timeline entry for incident workflow."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO incident_activity_logs (incident_id, stage, actor, note, tags)
                VALUES (?, ?, ?, ?, ?)
            """, (incident_id, stage, actor, note, json.dumps(tags or [])))
            return cur.lastrowid

    def get_incident_activity_logs(self, incident_id: str) -> List[Dict]:
        """Get all activity logs for an incident."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM incident_activity_logs
                WHERE incident_id = ?
                ORDER BY created_at ASC, id ASC
            """, (incident_id,))
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                try:
                    r['tags'] = json.loads(r.get('tags') or '[]')
                except Exception:
                    r['tags'] = []
            return rows

    # ==================== SCAN RESULTS ====================

    def add_scan_result(self, scan_type: str, source: str, findings: list,
                        severity: str, file_path: Optional[str] = None,
                        file_hash: Optional[str] = None, file_size: Optional[int] = None,
                        user: Optional[str] = None, host: Optional[str] = None, agent_id: Optional[str] = None) -> Optional[int]:
        """Store a scan result."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO scan_results
                (agent_id, scan_type, source, findings, severity, file_path, file_hash, file_size, user, host)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent_id, scan_type, source, json.dumps(findings), severity,
                file_path, file_hash, file_size, user, host
            ))
            return cur.lastrowid

    def get_scan_results(self, scan_type: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """Get scan results."""
        with self._cursor() as cur:
            if scan_type:
                cur.execute("""
                    SELECT * FROM scan_results WHERE scan_type = ?
                    ORDER BY timestamp DESC LIMIT ?
                """, (scan_type, limit))
            else:
                cur.execute("""
                    SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
            return [dict(row) for row in cur.fetchall()]

    # ==================== STATISTICS ====================

    def stats(self) -> Optional[Dict]:
        """Get dashboard statistics."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM incidents WHERE status = 'OPEN'")
            open_count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM incidents WHERE status = 'ESCALATED'")
            escalated = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('CLOSED', 'AUTO-CLOSED')")
            closed_count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM incidents")
            total_incidents = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM events")
            total_events = cur.fetchone()[0]

            cur.execute("SELECT AVG(risk) FROM incidents")
            avg_risk_row = cur.fetchone()[0]
            avg_risk = int(avg_risk_row) if avg_risk_row else 0

            cur.execute("SELECT COUNT(*) FROM scan_results")
            total_scans = cur.fetchone()[0]

            # Recent activity (last 24h)
            cutoff_24h = (datetime.now() - timedelta(hours=24)).isoformat()
            cur.execute("SELECT COUNT(*) FROM events WHERE timestamp > ?", (cutoff_24h,))
            events_24h = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM scan_results WHERE timestamp > ?", (cutoff_24h,))
            scans_24h = cur.fetchone()[0]

        return {
            "total_incidents": total_incidents,
            "open": open_count,
            "escalated": escalated,
            "closed": closed_count,
            "auto_closed": closed_count,
            "total_events": total_events,
            "avg_risk": avg_risk,
            "total_scans": total_scans,
            "events_24h": events_24h,
            "scans_24h": scans_24h,
        }

    # ==================== AUDIT LOG ====================

    def _log_audit(self, action: str, target_type: Optional[str] = None,
                   target_id: Optional[str] = None, actor: Optional[str] = None,
                   details: Optional[str] = None):
        """Log an audit event."""
        try:
            with self._cursor() as cur:
                cur.execute("""
                    INSERT INTO audit_log (action, target_type, target_id, actor, details)
                    VALUES (?, ?, ?, ?, ?)
                """, (action, target_type, target_id, actor, details))
        except Exception:
            pass  # Don't let audit logging break main operations

    def add_audit_entry(self,
                        action: str,
                        target_type: Optional[str] = None,
                        target_id: Optional[str] = None,
                        actor: Optional[str] = None,
                        details: Optional[str] = None):
        """Public wrapper to write audit logs from API layer."""
        self._log_audit(action, target_type=target_type, target_id=target_id, actor=actor, details=details)

    def get_audit_log(self,
                      limit: int = 50,
                      actor: Optional[str] = None,
                      action: Optional[str] = None,
                      query: Optional[str] = None,
                      since: Optional[str] = None,
                      action_only: bool = False) -> List[Dict]:
        """Get recent audit log entries with optional filters."""
        clauses = []
        params: List[object] = []

        if action_only:
            clauses.append("action NOT IN ('api', 'portal_api_call', 'event_created', 'incident_created')")

        if actor:
            clauses.append("lower(actor) LIKE lower(?)")
            params.append(f"%{actor.strip()}%")
        if action:
            clauses.append("lower(action) LIKE lower(?)")
            params.append(f"%{action.strip()}%")
        if query:
            clauses.append("(lower(target_id) LIKE lower(?) OR lower(details) LIKE lower(?) OR lower(target_type) LIKE lower(?))")
            q = f"%{query.strip()}%"
            params.extend([q, q, q])
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM audit_log {where_sql} ORDER BY timestamp DESC LIMIT ?"
        params.append(max(1, int(limit or 50)))

        with self._cursor() as cur:
            cur.execute(sql, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    # ==================== POLICIES ====================

    def add_policy(self, name: str, rule_type: str, rule_data: dict, 
                   description: str = "", severity: str = "MEDIUM", 
                   action: str = "monitor", threshold_count: int = 1,
                   threshold_window_mins: int = 60, actor: str = None) -> str:
        """Add a new detection policy."""
        policy_id = f"POL-{str(uuid.uuid4())[:8].upper()}"
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO policies
                (policy_id, name, description, rule_type, rule_data, severity,
                 action, threshold_count, threshold_window_mins, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                policy_id, name, description, rule_type, json.dumps(rule_data), severity,
                action, threshold_count, threshold_window_mins, actor or 'system'
            ))
        self._log_audit("policy_created", "policy", policy_id)
        return policy_id

    def get_policies(self, active_only: bool = False) -> List[Dict]:
        """Get policies."""
        with self._cursor() as cur:
            if active_only:
                cur.execute("SELECT * FROM policies WHERE is_active = 1 ORDER BY created_at DESC")
            else:
                cur.execute("SELECT * FROM policies ORDER BY created_at DESC")
            
            policies = []
            for row in cur.fetchall():
                d = dict(row)
                d['rule_data'] = json.loads(d.get('rule_data') or '{}')
                policies.append(d)
            return policies

    def update_policy(self, policy_id: str, actor: str = None, **kwargs) -> bool:
        """Update a policy."""
        allowed = {'name', 'description', 'rule_type', 'rule_data', 'severity',
                   'action', 'threshold_count', 'threshold_window_mins', 'is_active'}
        
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False

        if 'rule_data' in updates and isinstance(updates['rule_data'], dict):
            updates['rule_data'] = json.dumps(updates['rule_data'])

        updates['updated_at'] = datetime.now().isoformat()
        if actor:
            updates['updated_by'] = actor
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [policy_id]

        with self._cursor() as cur:
            cur.execute(f"UPDATE policies SET {set_clause} WHERE policy_id = ?", values)
        self._log_audit("policy_updated", "policy", policy_id)
        return True

    def delete_policy(self, policy_id: str):
        """Delete a policy."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM policies WHERE policy_id = ?", (policy_id,))
        self._log_audit("policy_deleted", "policy", policy_id)

    # ==================== EXCEPTIONS ====================

    def add_exception(self, name: str, scope_type: str = 'global', policy_id: Optional[str] = None,
                      policy_ids: Optional[List[str]] = None,
                      users: Optional[List[str]] = None, senders: Optional[List[str]] = None,
                      recipients: Optional[List[str]] = None, domains: Optional[List[str]] = None,
                      description: str = '', mode: str = 'allow_and_log', expires_at: Optional[str] = None,
                      ticket_id: str = '', reason: str = '', is_active: int = 1, actor: str = None) -> str:
        """Add a new policy exception."""
        exception_id = f"EXC-{str(uuid.uuid4())[:8].upper()}"
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO policy_exceptions
                (exception_id, name, description, scope_type, policy_id, policy_ids, mode,
                 users, senders, recipients, domains, expires_at, ticket_id, reason,
                 is_active, updated_at, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                exception_id,
                name,
                description,
                scope_type,
                policy_id,
                json.dumps(policy_ids or ([] if not policy_id else [policy_id])),
                mode,
                json.dumps(users or []),
                json.dumps(senders or []),
                json.dumps(recipients or []),
                json.dumps(domains or []),
                expires_at,
                ticket_id,
                reason,
                int(bool(is_active)),
                datetime.now().isoformat(),
                actor or 'system',
            ))
        self._log_audit("exception_created", "exception", exception_id)
        return exception_id

    def get_exceptions(self, active_only: bool = False) -> List[Dict]:
        """Get exception rules."""
        with self._cursor() as cur:
            if active_only:
                cur.execute("SELECT * FROM policy_exceptions WHERE is_active = 1 ORDER BY created_at DESC")
            else:
                cur.execute("SELECT * FROM policy_exceptions ORDER BY created_at DESC")

            rows = []
            for row in cur.fetchall():
                d = dict(row)
                for k in ('users', 'senders', 'recipients', 'domains', 'policy_ids'):
                    raw = d.get(k)
                    try:
                        parsed = json.loads(raw or '[]')
                        d[k] = parsed if isinstance(parsed, list) else []
                    except Exception:
                        d[k] = []
                if not d.get('policy_ids') and d.get('policy_id'):
                    d['policy_ids'] = [d.get('policy_id')]
                rows.append(d)
            return rows

    def update_exception(self, exception_id: str, actor: str = None, **kwargs) -> bool:
        """Update a policy exception."""
        allowed = {
            'name', 'description', 'scope_type', 'policy_id', 'policy_ids', 'mode',
            'users', 'senders', 'recipients', 'domains',
            'expires_at', 'ticket_id', 'reason', 'is_active'
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False

        for list_field in ('users', 'senders', 'recipients', 'domains', 'policy_ids'):
            if list_field in updates and isinstance(updates[list_field], list):
                updates[list_field] = json.dumps(updates[list_field])

        updates['updated_at'] = datetime.now().isoformat()
        if actor:
            updates['updated_by'] = actor
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [exception_id]

        with self._cursor() as cur:
            cur.execute(f"UPDATE policy_exceptions SET {set_clause} WHERE exception_id = ?", values)
        self._log_audit("exception_updated", "exception", exception_id)
        return True

    def delete_exception(self, exception_id: str):
        """Delete a policy exception."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM policy_exceptions WHERE exception_id = ?", (exception_id,))
        self._log_audit("exception_deleted", "exception", exception_id)

    # ==================== FLEET MANAGEMENT ====================

    def update_fleet_checkin(self, agent_id: str, agent_type: str, hostname: str, 
                             os_info: Optional[str] = None, version: Optional[str] = None, ip: Optional[str] = None, 
                             user: Optional[str] = None, scans: int = 0, incidents: int = 0, 
                             meta: Optional[dict] = None):
        """Update or create an agent entry in the fleet registry."""
        now = datetime.now().isoformat()
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
                status = 'online',
                meta = excluded.meta
            """, (agent_id, agent_type, hostname, os_info, version, ip, user, now, 
                 scans, incidents, json.dumps(meta or {})))

    def get_fleet_agents(self) -> List[Dict]:
        """Get all agents from fleet registry."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM fleet")
            agents = []
            for row in cur.fetchall():
                d = dict(row)
                d['meta'] = json.loads(d.get('meta') or '{}')
                agents.append(d)
            return agents

    def get_agent_scan_history(self, hostname: str, limit: int = 50, agent_id: Optional[str] = None, user: Optional[str] = None) -> List[Dict]:
        """Get recent scan results for a specific agent/host."""
        with self._cursor() as cur:
            if agent_id:
                cur.execute("""
                    SELECT * FROM scan_results
                    WHERE agent_id = ?
                    ORDER BY timestamp DESC LIMIT ?
                """, (agent_id, limit))
            elif user:
                cur.execute("""
                    SELECT * FROM scan_results
                    WHERE user = ?
                    ORDER BY timestamp DESC LIMIT ?
                """, (user, limit))
            else:
                cur.execute("""
                    SELECT * FROM scan_results 
                    WHERE host = ? 
                    ORDER BY timestamp DESC LIMIT ?
                """, (hostname, limit))
            return [dict(row) for row in cur.fetchall()]

    def get_agent_events(self, hostname: str, limit: int = 50) -> List[Dict]:
        """Get recent events where source_host or host matches the given hostname."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM events
                WHERE source_host = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (hostname, limit))
            rows = [self._row_to_event_dict(row) for row in cur.fetchall()]
            return rows

    def get_events_for_agent(self, agent_id: Optional[str] = None, hostname: Optional[str] = None, user: Optional[str] = None, agent_type: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """Get recent events related to an agent by host, user, or agent_type."""
        with self._cursor() as cur:
            # Build flexible query
            clauses = []
            params = []
            if hostname:
                clauses.append("source_host = ?")
                params.append(hostname)
            if user:
                clauses.append("user = ?")
                params.append(user)
            if agent_type:
                clauses.append("agent_type = ?")
                params.append(agent_type)

            if not clauses:
                cur.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
            else:
                where = " OR ".join(clauses)
                cur.execute(f"SELECT * FROM events WHERE ({where}) ORDER BY timestamp DESC LIMIT ?", (*params, limit))

            rows = [self._row_to_event_dict(row) for row in cur.fetchall()]
            return rows

    def get_incidents_for_host(self, hostname: str, limit: int = 50) -> List[Dict]:
        """Get recent incidents related to a host."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM incidents
                WHERE host = ?
                ORDER BY created_at DESC LIMIT ?
            """, (hostname, limit))
            rows = [dict(row) for row in cur.fetchall()]
            # Normalize JSON fields
            for r in rows:
                try:
                    r['events'] = json.loads(r.get('events') or '[]')
                    r['ai_analysis'] = json.loads(r.get('ai_analysis') or 'null')
                except Exception:
                    pass
            return rows

    def get_agent_downloads(self, hostname: str, limit: int = 50, agent_id: Optional[str] = None, user: Optional[str] = None) -> List[Dict]:
        """Get recent web/download scan results for a specific agent/host."""
        with self._cursor() as cur:
            if agent_id:
                cur.execute("""
                    SELECT * FROM scan_results
                    WHERE agent_id = ? AND scan_type IN ('web_download','file','download')
                    ORDER BY timestamp DESC LIMIT ?
                """, (agent_id, limit))
            elif user:
                cur.execute("""
                    SELECT * FROM scan_results
                    WHERE user = ? AND scan_type IN ('web_download','file','download')
                    ORDER BY timestamp DESC LIMIT ?
                """, (user, limit))
            else:
                cur.execute("""
                    SELECT * FROM scan_results 
                    WHERE host = ? AND scan_type IN ('web_download','file','download')
                    ORDER BY timestamp DESC LIMIT ?
                """, (hostname, limit))
            rows = [dict(row) for row in cur.fetchall()]
            # Parse findings JSON for readability
            for r in rows:
                try:
                    r['findings'] = json.loads(r.get('findings') or '[]')
                except Exception:
                    pass
            return rows

    def add_operational_log(self, agent_id: str, event_type: str, message: str, details: dict = None) -> Optional[int]:
        """Store an operational log entry for an agent."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO operational_logs (agent_id, event_type, message, details)
                VALUES (?, ?, ?, ?)
            """, (agent_id, event_type, message, json.dumps(details or {})))
            return cur.lastrowid

    def get_operational_logs(self, agent_id: str, limit: int = 100) -> List[Dict]:
        """Get recent operational logs for an agent."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM operational_logs
                WHERE agent_id = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (agent_id, limit))
            rows = [dict(row) for row in cur.fetchall()]
            for r in rows:
                try:
                    r['details'] = json.loads(r.get('details') or '{}')
                except Exception:
                    r['details'] = {}
            return rows

    def add_upload_artifact(self,
                            artifact_id: str,
                            agent_id: str,
                            scan_id: str,
                            hostname: str,
                            user: str,
                            source_host: str,
                            file_name: str,
                            file_type: str,
                            file_size: int,
                            action: str,
                            severity: str,
                            findings: list,
                            content_path: str,
                            content_sha256: str) -> str:
        """Store uploaded/flagged file artifact metadata."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT OR REPLACE INTO upload_artifacts
                (artifact_id, agent_id, scan_id, hostname, user, source_host, file_name, file_type, file_size,
                 action, severity, findings, content_path, content_sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact_id, agent_id, scan_id, hostname, user, source_host, file_name, file_type, file_size,
                action, severity, json.dumps(findings or []), content_path, content_sha256
            ))
        return artifact_id

    def get_agent_upload_artifacts(self, agent_id: Optional[str] = None, hostname: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get recent upload artifacts for an agent (by agent_id and/or hostname)."""
        with self._cursor() as cur:
            clauses = []
            params = []
            if agent_id:
                clauses.append("agent_id = ?")
                params.append(agent_id)
            if hostname:
                clauses.append("hostname = ?")
                params.append(hostname)

            if clauses:
                where = " OR ".join(clauses)
                cur.execute(f"""
                    SELECT * FROM upload_artifacts
                    WHERE ({where})
                    ORDER BY created_at DESC LIMIT ?
                """, (*params, limit))
            else:
                cur.execute("SELECT * FROM upload_artifacts ORDER BY created_at DESC LIMIT ?", (limit,))

            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                try:
                    r['findings'] = json.loads(r.get('findings') or '[]')
                except Exception:
                    r['findings'] = []
            return rows

    def get_upload_artifact(self, artifact_id: str) -> Optional[Dict]:
        """Get a single artifact metadata entry by ID."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM upload_artifacts WHERE artifact_id = ?", (artifact_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            try:
                d['findings'] = json.loads(d.get('findings') or '[]')
            except Exception:
                d['findings'] = []
            return d

    # ==================== HELPERS ====================

    def _row_to_event_dict(self, row) -> Optional[Dict]:
        """Convert a DB row to event dict."""
        d = dict(row)
        d['matched_rules'] = json.loads(d.get('matched_rules') or '[]')
        d['geo'] = json.loads(d.get('geo') or '{}')
        return d

    def _row_to_incident_dict(self, row) -> Optional[Dict]:
        """Convert a DB row to incident dict."""
        d = dict(row)
        d['events'] = json.loads(d.get('events') or '[]')
        d['ai_analysis'] = json.loads(d.get('ai_analysis') or 'null')
        d['auto_escalated'] = bool(d.get('auto_escalated'))
        return d
