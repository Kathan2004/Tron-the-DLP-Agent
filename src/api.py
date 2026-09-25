"""
TRON THE DLP AGENT API — Flask REST Server
Real API endpoints for the DLP system with persistent storage.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import tempfile
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from config.settings import Config
from flask import Flask, jsonify, request, send_file, g
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from src.ai_analyzer import FalsePositiveClassifier, VertexAIAnalyzer
from src.database import Database
from src.event_processor import EventProcessor, EscalationEngine
from src.file_scanner import FileContentScanner, quick_scan
from src.incident_store import IncidentStore
from src.rules_engine import RulesEngine
from src.telegram_bot import DLPTelegramBot, scrub_token

app = Flask(__name__)

# Console API: only the configured console origins may call it cross-origin.
# Unauthenticated ingest endpoints used by the browser extension's content script
# (which runs under the visited page's origin) stay open to any origin.
CORS_ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv(
        'APP_CORS_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173'
    ).split(',') if o.strip()
]
CORS(app, resources={
    r"/api/browser/.*": {"origins": "*"},
    r"/api/scan/.*": {"origins": "*"},
    r"/api/.*": {"origins": CORS_ALLOWED_ORIGINS},
})

# These will be initialized in main.py
incident_store: IncidentStore | None = None
rules_engine: RulesEngine | None = None
event_processor: EventProcessor | None = None
escalation_engine: EscalationEngine | None = None
ai_analyzer: VertexAIAnalyzer | None = None
fp_classifier: FalsePositiveClassifier | None = None
telegram_bot: DLPTelegramBot | None = None
database: Database | None = None
file_scanner: FileContentScanner | None = None
browser_incident_lock = threading.Lock()

AUTH_SECRET = os.getenv('APP_AUTH_SECRET', '').strip()
if not AUTH_SECRET:
    AUTH_SECRET = secrets.token_urlsafe(48)
    print("WARNING: APP_AUTH_SECRET is not set. Using a random per-run signing secret; "
          "all console sessions will be invalidated on restart. Set APP_AUTH_SECRET in .env.")
AUTH_TOKEN_MAX_AGE_SECONDS = int(os.getenv('APP_AUTH_TOKEN_TTL_SECONDS', str(8 * 60 * 60)))
AUTH_MAX_FAILED_ATTEMPTS = int(os.getenv('APP_AUTH_MAX_FAILED_ATTEMPTS', '5'))
AUTH_LOCKOUT_MINUTES = int(os.getenv('APP_AUTH_LOCKOUT_MINUTES', '15'))
DEFAULT_ADMIN_EMAIL = os.getenv('APP_ADMIN_EMAIL', 'admin@tron.local').strip().lower()
DEFAULT_ADMIN_NAME = os.getenv('APP_ADMIN_NAME', 'Platform Admin').strip()
DEFAULT_ADMIN_PASSWORD = os.getenv('APP_ADMIN_PASSWORD', '').strip()
SYSTEM_ROLES = {'SUPER_ADMIN', 'SECURITY_ADMIN', 'SOC_ANALYST', 'VIEWER'}
VALID_ROLES = set(SYSTEM_ROLES)
VALID_THEME_PREFS = {'system', 'light', 'dark'}

IAM_PERMISSION_CATALOG = {
    'dashboard.view': 'View dashboard and live stream',
    'events.view': 'View events and event details',
    'incidents.view': 'View incidents and workflows',
    'incidents.manage': 'Update incident workflow actions',
    'policies.view': 'View policies',
    'policies.manage': 'Create/update/delete policies',
    'exceptions.view': 'View exception rules',
    'exceptions.manage': 'Create/update/delete exception rules',
    'fleet.view': 'View endpoint fleet and status',
    'fleet.manage': 'Send endpoint fleet commands',
    'audit.view': 'Read audit log and governance trails',
    'users.manage': 'Manage user lifecycle and role assignments',
    'iam.manage': 'Manage IAM settings and role permissions',
    'ai_lab.manage': 'Manage AI lab and policy simulation controls',
}

IAM_ROLE_DEFAULTS = {
    'SUPER_ADMIN': set(IAM_PERMISSION_CATALOG.keys()),
    'SECURITY_ADMIN': {
        'dashboard.view', 'events.view', 'incidents.view', 'incidents.manage',
        'policies.view', 'policies.manage', 'exceptions.view', 'exceptions.manage',
        'fleet.view', 'fleet.manage', 'audit.view', 'ai_lab.manage',
    },
    'SOC_ANALYST': {
        'dashboard.view', 'events.view', 'incidents.view', 'incidents.manage',
        'policies.view', 'exceptions.view', 'fleet.view', 'audit.view',
    },
    'VIEWER': {
        'dashboard.view', 'events.view', 'incidents.view', 'policies.view',
        'exceptions.view', 'fleet.view',
    },
}

ROLE_KEY_PATTERN = re.compile(r'^[A-Z][A-Z0-9_]{1,48}$')

IAM_SETTINGS_DEFAULTS = {
    'password_min_length': 12,
    'password_require_upper': True,
    'password_require_lower': True,
    'password_require_digit': True,
    'password_require_special': True,
    'password_prevent_email_localpart': True,
    'max_concurrent_sessions': 3,
    'session_idle_timeout_minutes': 120,
    'enforce_last_super_admin_protection': True,
    'enforce_policy_delete_confirmation_ticket': False,
}


def _get_iam_settings() -> dict:
    settings = dict(IAM_SETTINGS_DEFAULTS)
    if not database:
        return settings
    try:
        from_db = database.get_iam_settings() or {}
        settings.update(from_db)
    except Exception:
        pass
    return settings


def _normalize_role_key(value: object | None) -> str:
    return str(value or '').strip().upper()


def _get_role_catalog(include_inactive: bool = False) -> dict[str, dict]:
    catalog: dict[str, dict] = {
        role: {
            'role': role,
            'display_name': role,
            'description': 'System role',
            'is_system': True,
            'is_active': True,
        }
        for role in sorted(SYSTEM_ROLES)
    }
    if not database:
        return catalog

    try:
        custom_roles = database.list_custom_roles(active_only=not include_inactive)
    except Exception:
        custom_roles = []

    for row in custom_roles:
        role = _normalize_role_key(row.get('role_key'))
        if not role or role in SYSTEM_ROLES:
            continue
        catalog[role] = {
            'role': role,
            'display_name': str(row.get('display_name') or role),
            'description': str(row.get('description') or '').strip(),
            'is_system': False,
            'is_active': bool(row.get('is_active')),
            'created_at': row.get('created_at'),
            'updated_at': row.get('updated_at'),
        }
    return catalog


def _is_role_allowed_for_assignment(role: str) -> bool:
    role_u = _normalize_role_key(role)
    if not role_u:
        return False
    catalog = _get_role_catalog(include_inactive=False)
    entry = catalog.get(role_u)
    return bool(entry and entry.get('is_active'))


def _bool_setting(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s in {'1', 'true', 'yes', 'on'}:
            return True
        if s in {'0', 'false', 'no', 'off'}:
            return False
    if value is None:
        return default
    return bool(value)


def _int_setting(value: object, default: int) -> int:
    try:
        return int(str(value))
    except Exception:
        return default


def _effective_permissions_for_role(role: str) -> set[str]:
    role_u = str(role or 'VIEWER').strip().upper() or 'VIEWER'
    if role_u in IAM_ROLE_DEFAULTS:
        base = set(IAM_ROLE_DEFAULTS.get(role_u, set()))
    else:
        base = set()
    if not database:
        return base
    try:
        overrides = database.get_role_permission_overrides().get(role_u, {})
        for key, allowed in overrides.items():
            if _bool_setting(allowed, False):
                base.add(key)
            elif key in base:
                base.remove(key)
    except Exception:
        pass
    return base


def _has_permission(role: str, permission_key: str) -> bool:
    return permission_key in _effective_permissions_for_role(role)


def _required_permission_for_request(path: str, method: str) -> str | None:
    p = str(path or '')
    m = str(method or 'GET').upper()

    if p.startswith('/api/admin/iam'):
        return 'iam.manage'
    if p.startswith('/api/admin/users'):
        return 'users.manage'
    if p.startswith('/api/audit'):
        return 'audit.view'
    if p.startswith('/api/policies'):
        return 'policies.manage' if m in {'POST', 'PUT', 'PATCH', 'DELETE'} else 'policies.view'
    if p.startswith('/api/exceptions'):
        return 'exceptions.manage' if m in {'POST', 'PUT', 'PATCH', 'DELETE'} else 'exceptions.view'
    if p.startswith('/api/lab'):
        return 'ai_lab.manage' if m in {'POST', 'PUT', 'PATCH', 'DELETE'} else None
    if p.startswith('/api/fleet'):
        if m in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            if p in {'/api/fleet/checkin'} or p.startswith('/api/fleet/agents/') and p.endswith('/operational'):
                return None
            return 'fleet.manage'
        return 'fleet.view'
    if p.startswith('/api/incidents'):
        return 'incidents.manage' if m in {'POST', 'PUT', 'PATCH', 'DELETE'} else 'incidents.view'
    if p.startswith('/api/events'):
        return 'events.view' if m == 'GET' else None
    if p in {'/api/stats', '/api/stream'}:
        return 'dashboard.view'
    return None


def _validate_password_against_policy(password: str, email: str = '') -> str | None:
    settings = _get_iam_settings()
    min_len = max(8, _int_setting(settings.get('password_min_length'), 12))
    pwd = str(password or '')
    em = str(email or '').strip().lower()

    if len(pwd) < min_len:
        return f'new_password must be at least {min_len} chars'
    if _bool_setting(settings.get('password_require_upper'), True) and not re.search(r'[A-Z]', pwd):
        return 'new_password must include an uppercase letter'
    if _bool_setting(settings.get('password_require_lower'), True) and not re.search(r'[a-z]', pwd):
        return 'new_password must include a lowercase letter'
    if _bool_setting(settings.get('password_require_digit'), True) and not re.search(r'\d', pwd):
        return 'new_password must include a digit'
    if _bool_setting(settings.get('password_require_special'), True) and not re.search(r'[^A-Za-z0-9]', pwd):
        return 'new_password must include a special character'
    if _bool_setting(settings.get('password_prevent_email_localpart'), True) and em and '@' in em:
        local = em.split('@')[0].strip()
        if local and local in pwd.lower():
            return 'new_password must not include your email username'
    return None


def _auth_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(AUTH_SECRET, salt='tron-auth-v1')


def _hash_password(password: str, salt: str | None = None) -> str:
    s = (salt or base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')).strip()
    iters = 200_000
    dk = hashlib.pbkdf2_hmac('sha256', (password or '').encode('utf-8'), s.encode('utf-8'), iters)
    return f"pbkdf2_sha256${iters}${s}${base64.urlsafe_b64encode(dk).decode('utf-8')}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt, digest = str(stored or '').split('$', 3)
        if algo != 'pbkdf2_sha256':
            return False
        iters = int(iter_s)
        chk = hashlib.pbkdf2_hmac('sha256', (password or '').encode('utf-8'), salt.encode('utf-8'), iters)
        chk_b64 = base64.urlsafe_b64encode(chk).decode('utf-8')
        return hmac.compare_digest(chk_b64, digest)
    except Exception:
        return False


def _user_public_view(user_row: dict | None) -> dict:
    u = user_row or {}
    return {
        'user_id': u.get('user_id'),
        'email': u.get('email'),
        'display_name': u.get('display_name'),
        'role': u.get('role'),
        'manager_email': u.get('manager_email'),
        'timezone': u.get('timezone') or 'Asia/Kolkata',
        'locale': u.get('locale') or 'en-IN',
        'theme_preference': u.get('theme_preference') or 'light',
        'notify_email': bool(u.get('notify_email', 1)),
        'notify_telegram': bool(u.get('notify_telegram', 1)),
        'is_active': bool(u.get('is_active')),
        'must_change_password': bool(u.get('must_change_password')),
        'locked_until': u.get('locked_until'),
        'failed_login_attempts': int(u.get('failed_login_attempts') or 0),
        'last_login_at': u.get('last_login_at'),
        'created_at': u.get('created_at'),
        'updated_at': u.get('updated_at'),
    }


def _create_auth_token(user_row: dict, session_id: str) -> str:
    payload = {
        'uid': user_row.get('user_id'),
        'sid': session_id,
        'email': str(user_row.get('email') or '').strip().lower(),
        'role': str(user_row.get('role') or 'VIEWER').strip().upper(),
    }
    return _auth_serializer().dumps(payload)


def _decode_auth_token(token: str) -> dict | None:
    try:
        return _auth_serializer().loads(token, max_age=AUTH_TOKEN_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None


def _bootstrap_local_admin() -> None:
    if not database:
        return
    try:
        if database.count_app_users() > 0:
            return
        password = DEFAULT_ADMIN_PASSWORD
        generated = not password
        if generated:
            password = secrets.token_urlsafe(16)
        database.create_app_user(
            email=DEFAULT_ADMIN_EMAIL,
            display_name=DEFAULT_ADMIN_NAME,
            password_hash=_hash_password(password),
            role='SUPER_ADMIN',
            manager_email=None,
            is_active=True,
            must_change_password=generated,
        )
        print(f"🔐 Local admin bootstrapped: {DEFAULT_ADMIN_EMAIL}")
        if generated:
            # Shown exactly once, only on the console of the process that created the account.
            print("=" * 64)
            print("  APP_ADMIN_PASSWORD not set. Generated one-time admin password:")
            print(f"    {password}")
            print("  You must change it on first login. It will not be shown again.")
            print("=" * 64)
    except Exception as e:
        print(f"⚠️ Local admin bootstrap failed: {e}")


def _is_public_api_request(path: str, method: str) -> bool:
    p = str(path or '')
    m = str(method or 'GET').upper()
    if p in {'/api/health', '/api/auth/login'}:
        return True
    if p == '/api/events' and m == 'POST':
        return True
    if p == '/api/browser/incident' and m == 'POST':
        return True
    if p.startswith('/api/scan/') and m == 'POST':
        return True
    if p.startswith('/api/browser/artifact') and m == 'POST':
        return True
    if p == '/api/screenshots' and m == 'POST':
        return True
    if p == '/api/fleet/checkin' and m == 'POST':
        return True
    if p.startswith('/api/fleet/agents/') and p.endswith('/operational') and m == 'POST':
        return True
    if p == '/api/policies/sync' and m == 'GET':
        return True
    if p == '/api/stream' and m == 'GET':
        return True
    return False


def _role_allowed(role: str, allowed_roles: set[str]) -> bool:
    return str(role or '').upper() in {r.upper() for r in allowed_roles}


@app.before_request
def _auth_guard():
    path = request.path or ''
    method = (request.method or 'GET').upper()

    # Always allow CORS preflight requests.
    if method == 'OPTIONS':
        return None

    if not path.startswith('/api/'):
        return None
    if _is_public_api_request(path, method):
        return None

    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'authentication_required'}), 401

    token = auth.split(' ', 1)[1].strip()
    claims = _decode_auth_token(token)
    if not claims:
        return jsonify({'error': 'invalid_or_expired_token'}), 401

    if not database:
        return jsonify({'error': 'database_unavailable'}), 500

    user = database.get_app_user_by_id(str(claims.get('uid') or '').strip())
    if not user or not bool(user.get('is_active')):
        return jsonify({'error': 'user_inactive_or_missing'}), 401

    session_id = str(claims.get('sid') or '').strip()
    if not session_id:
        return jsonify({'error': 'invalid_token_session'}), 401
    session = database.get_auth_session(session_id)
    if not session:
        return jsonify({'error': 'session_not_found'}), 401
    if str(session.get('user_id') or '') != str(user.get('user_id') or ''):
        return jsonify({'error': 'session_user_mismatch'}), 401
    if session.get('revoked_at'):
        return jsonify({'error': 'session_revoked'}), 401
    try:
        expires_at = datetime.fromisoformat(str(session.get('expires_at') or '').replace('Z', '+00:00'))
        now_dt = datetime.now(expires_at.tzinfo) if expires_at.tzinfo else datetime.now()
        if now_dt >= expires_at:
            database.revoke_auth_session(session_id, reason='expired')
            return jsonify({'error': 'session_expired'}), 401
    except Exception:
        return jsonify({'error': 'invalid_session_expiry'}), 401

    try:
        iam_settings = _get_iam_settings()
        idle_limit = max(1, _int_setting(iam_settings.get('session_idle_timeout_minutes'), 120))
        last_seen_raw = str(session.get('last_seen_at') or session.get('issued_at') or '').strip()
        if last_seen_raw:
            last_seen_dt = datetime.fromisoformat(last_seen_raw.replace('Z', '+00:00'))
            idle_now = datetime.now(last_seen_dt.tzinfo) if last_seen_dt.tzinfo else datetime.now()
            if idle_now - last_seen_dt > timedelta(minutes=idle_limit):
                database.revoke_auth_session(session_id, reason='idle_timeout')
                return jsonify({'error': 'session_idle_timeout'}), 401
    except Exception:
        pass

    try:
        database.touch_auth_session(session_id)
    except Exception:
        pass

    # Accounts flagged for a password change may only use self-service auth endpoints.
    if bool(user.get('must_change_password')) and path not in {
        '/api/auth/change-password', '/api/auth/me', '/api/auth/permissions',
        '/api/auth/logout', '/api/auth/sessions', '/api/auth/sessions/revoke',
    }:
        return jsonify({'error': 'password_change_required'}), 403

    g.current_user = user
    g.current_role = str(user.get('role') or 'VIEWER').upper()
    g.current_session_id = session_id
    g.current_permissions = _effective_permissions_for_role(g.current_role)

    required_perm = _required_permission_for_request(path, method)
    if required_perm and required_perm not in g.current_permissions:
        return jsonify({'error': 'forbidden_missing_permission', 'required_permission': required_perm}), 403

    # Viewers remain read-only for authenticated console APIs (except self-service auth endpoints).
    if method in {'POST', 'PUT', 'PATCH', 'DELETE'} and g.current_role == 'VIEWER' and path not in {
        '/api/auth/change-password', '/api/auth/profile', '/api/auth/logout', '/api/auth/sessions/revoke'
    }:
        return jsonify({'error': 'forbidden_read_only_role'}), 403

    return None


def _actor_from_request(default_actor: str = 'secops_analyst') -> str:
    user = getattr(g, 'current_user', None)
    if isinstance(user, dict) and user.get('email'):
        return str(user.get('email')).strip()
    payload = request.get_json(silent=True) or {}
    return str(payload.get('actor') or default_actor).strip()


_AUDIT_SENSITIVE_FIELDS = {
    'password', 'new_password', 'old_password', 'password_hash',
    'token', 'authorization', 'secret', 'api_key', 'access_token',
}


def _sanitize_audit_payload(payload: object | None) -> dict:
    if not isinstance(payload, dict):
        return {}
    cleaned: dict[str, object] = {}
    for k, v in payload.items():
        key = str(k or '').strip()
        if not key:
            continue
        key_l = key.lower()
        if key_l in _AUDIT_SENSITIVE_FIELDS or 'password' in key_l or 'token' in key_l:
            cleaned[key] = '***'
            continue
        if isinstance(v, (dict, list)):
            try:
                cleaned[key] = json.loads(json.dumps(v))
            except Exception:
                cleaned[key] = str(v)
        else:
            cleaned[key] = v
    return cleaned


def _write_portal_audit(action: str,
                        target_type: str,
                        target_id: str,
                        actor: str,
                        details: dict | None = None) -> None:
    if not database:
        return
    try:
        database.add_audit_entry(
            action=action,
            target_type=target_type,
            target_id=target_id,
            actor=actor,
            details=json.dumps(details or {}),
        )
    except Exception:
        pass


def _short_value(value: object) -> str:
    try:
        if isinstance(value, (list, tuple)):
            vals = [str(v) for v in value][:3]
            suffix = '' if len(value) <= 3 else f" +{len(value) - 3}"
            return f"[{', '.join(vals)}]{suffix}"
        if isinstance(value, dict):
            keys = list(value.keys())[:3]
            suffix = '' if len(value.keys()) <= 3 else '…'
            return '{' + ', '.join(str(k) for k in keys) + suffix + '}'
        text = str(value)
        return text[:80] + ('…' if len(text) > 80 else '')
    except Exception:
        return ''


def _change_summary_from_payload(payload: dict | None) -> tuple[list[str], str]:
    if not isinstance(payload, dict):
        return [], ''
    changed_fields = [str(k) for k in payload.keys() if str(k)]
    if not changed_fields:
        return [], ''
    pairs = []
    for key in changed_fields[:8]:
        pairs.append(f"{key}={_short_value(payload.get(key))}")
    summary = '; '.join(pairs)
    return changed_fields, summary


@app.after_request
def _portal_activity_audit(response):
    try:
        path = str(request.path or '')
        method = str(request.method or 'GET').upper()
        payload = request.get_json(silent=True) or {}

        if not path.startswith('/api/'):
            return response
        if method == 'OPTIONS':
            return response

        # Capture user-driven mutating actions in the SIEM portal.
        if method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            return response
        if int(getattr(response, 'status_code', 0) or 0) >= 400:
            return response

        # Skip high-volume non-portal ingest traffic.
        if path in {'/api/events', '/api/browser/incident', '/api/fleet/checkin'}:
            return response
        if path.startswith('/api/browser/artifact') or path.startswith('/api/scan/'):
            return response

        actor = ''
        user = getattr(g, 'current_user', None)
        if isinstance(user, dict) and user.get('email'):
            actor = str(user.get('email')).strip().lower()
        elif path == '/api/auth/login':
            actor = str(payload.get('email') or '').strip().lower() or 'anonymous'
        else:
            actor = 'anonymous'

        action = ''
        target_type = 'api'
        target_id = path
        details_override = None

        if path == '/api/auth/change-password' and method == 'POST':
            action = 'password_changed'
            target_type = 'user'
            target_id = str((getattr(g, 'current_user', None) or {}).get('user_id') or actor)
        elif path == '/api/auth/profile' and method == 'PATCH':
            action = 'profile_updated'
            target_type = 'user'
            target_id = str((getattr(g, 'current_user', None) or {}).get('user_id') or actor)
        elif path.startswith('/api/policies'):
            if method == 'POST':
                action = 'policy_created'
            elif method == 'PUT':
                action = 'policy_updated'
            elif method == 'PATCH':
                if 'is_active' in payload:
                    action = 'policy_activated' if bool(payload.get('is_active')) else 'policy_deactivated'
                else:
                    action = 'policy_updated'
            elif method == 'DELETE':
                action = 'policy_deleted'
            else:
                action = ''
            target_type = 'policy'
            target_id = path.split('/')[-1] if path.count('/') >= 3 else 'new'
            policy_name = str(payload.get('name') or '').strip()
            if not policy_name and target_id not in {'new', '', path} and database:
                try:
                    existing_policy = next((p for p in database.get_policies(active_only=False) if str(p.get('policy_id') or '') == target_id), None)
                    policy_name = str((existing_policy or {}).get('name') or '').strip()
                except Exception:
                    policy_name = ''
            if action and policy_name:
                if not details_override:
                    details_override = {'policy_name': policy_name[:100]}
                else:
                    details_override['policy_name'] = policy_name[:100]
            if action == 'policy_updated':
                changed_fields, change_summary = _change_summary_from_payload(payload)
                if changed_fields:
                    if not details_override:
                        details_override = {}
                    details_override['changed_fields'] = ','.join(changed_fields)
                    details_override['change_summary'] = change_summary
        elif path.startswith('/api/exceptions'):
            if method == 'POST':
                action = 'exception_created'
            elif method == 'PUT':
                action = 'exception_updated'
            elif method == 'PATCH':
                if 'is_active' in payload:
                    action = 'exception_activated' if bool(payload.get('is_active')) else 'exception_deactivated'
                else:
                    action = 'exception_updated'
            elif method == 'DELETE':
                action = 'exception_deleted'
            else:
                action = ''
            target_type = 'exception'
            target_id = path.split('/')[-1] if path.count('/') >= 3 else 'new'
            exception_name = str(payload.get('name') or '').strip()
            if not exception_name and target_id not in {'new', '', path} and database:
                try:
                    existing_exception = next((e for e in database.get_exceptions(active_only=False) if str(e.get('exception_id') or '') == target_id), None)
                    exception_name = str((existing_exception or {}).get('name') or '').strip()
                except Exception:
                    exception_name = ''
            if action and exception_name:
                if not details_override:
                    details_override = {'exception_name': exception_name[:100]}
                else:
                    details_override['exception_name'] = exception_name[:100]
            if action == 'exception_updated':
                changed_fields, change_summary = _change_summary_from_payload(payload)
                if changed_fields:
                    if not details_override:
                        details_override = {}
                    details_override['changed_fields'] = ','.join(changed_fields)
                    details_override['change_summary'] = change_summary
        elif path == '/api/incidents/bulk-action' and method == 'POST':
            bulk_action = str(payload.get('action') or '').strip().lower().replace('-', '_')
            incident_ids_raw = payload.get('incident_ids')
            if not isinstance(incident_ids_raw, list):
                incident_ids_raw = []
            incident_ids = [str(v).strip() for v in incident_ids_raw if str(v).strip()]
            bulk_action_map = {
                'assign': ('incident_bulk_assigned', 'assigned'),
                'close': ('incident_bulk_closed', 'closed'),
                'escalate': ('incident_bulk_escalated', 'escalated'),
                'reopen': ('incident_bulk_reopened', 'reopened'),
                'raise_ticket': ('incident_bulk_ticket_raised', 'raised ticket for'),
            }
            mapped = bulk_action_map.get(bulk_action)
            action = mapped[0] if mapped else ''
            verb = mapped[1] if mapped else 'updated'
            target_type = 'incident'
            if len(incident_ids) == 1:
                target_id = incident_ids[0]
            else:
                target_id = f"bulk:{len(incident_ids)}"

            summary = f"{actor} {verb} {len(incident_ids)} incident(s)"
            details_override = {
                'summary': summary,
                'incident_count': len(incident_ids),
                'incident_ids': incident_ids,
            }
            if bulk_action == 'assign' and payload.get('assignee'):
                details_override['assignee'] = str(payload.get('assignee') or '').strip()
            if bulk_action == 'close':
                if payload.get('classification'):
                    details_override['classification'] = str(payload.get('classification') or '').strip().upper()
                if payload.get('initial_statement'):
                    details_override['initial_statement'] = str(payload.get('initial_statement') or '').strip()[:120]
                if payload.get('final_statement'):
                    details_override['final_statement'] = str(payload.get('final_statement') or '').strip()[:120]
        elif path.startswith('/api/incidents'):
            p = path.lower()
            if '/close' in p:
                action = 'incident_closed'
                if payload.get('final_statement'):
                    statement = str(payload.get('final_statement') or '').strip()[:120]
                    if not details_override:
                        details_override = {'final_statement': statement}
                    else:
                        details_override['final_statement'] = statement
            elif '/escalate' in p:
                action = 'incident_escalated'
            elif '/ticket' in p:
                action = 'incident_ticket_raised'
            elif '/reopen' in p:
                action = 'incident_reopened'
            elif method in {'PUT', 'PATCH'}:
                action = 'incident_updated'
            target_type = 'incident'
            target_id = path.split('/')[-1] if path.count('/') >= 3 else path
        elif path.startswith('/api/admin/users'):
            target_type = 'user'
            segments = [s for s in path.split('/') if s]
            # /api/admin/users
            if len(segments) == 3 and method == 'POST':
                action = 'app_user_created'
                target_id = str(payload.get('email') or 'new').strip() or 'new'
            # /api/admin/users/<user_id>
            elif len(segments) == 4 and method in {'PUT', 'PATCH'}:
                if 'is_active' in payload:
                    action = 'app_user_activated' if bool(payload.get('is_active')) else 'app_user_deactivated'
                elif 'role' in payload:
                    action = 'app_user_role_changed'
                else:
                    action = 'app_user_updated'
                target_id = segments[3]
            # /api/admin/users/<user_id>/reset-password
            elif len(segments) >= 5 and segments[4] == 'reset-password' and method == 'POST':
                action = 'app_user_password_reset'
                target_id = segments[3]
            # /api/admin/users/<user_id>/revoke-sessions
            elif len(segments) >= 5 and segments[4] == 'revoke-sessions' and method == 'POST':
                action = 'auth_session_revoked'
                target_id = segments[3]
                details_override = {
                    'reason': 'admin_revoke_all_sessions',
                    'scope': 'all_user_sessions',
                }
            else:
                action = ''
        elif path.startswith('/api/admin/iam/settings') and method == 'PATCH':
            action = 'iam_settings_updated'
            target_type = 'iam'
            target_id = 'global'
        elif '/permissions' in path and path.startswith('/api/admin/iam/roles') and method == 'PUT':
            action = 'iam_role_permissions_updated'
            target_type = 'iam_role'
            target_id = path.split('/')[-2] if path.count('/') >= 6 else 'unknown'
        elif path.startswith('/api/admin/iam/roles') and method == 'POST':
            action = 'custom_role_created'
            target_type = 'role'
            target_id = str((request.get_json(silent=True) or {}).get('role') or 'new')
        elif path.startswith('/api/admin/iam/roles') and method == 'PATCH':
            if 'is_active' in payload:
                action = 'custom_role_activated' if bool(payload.get('is_active')) else 'custom_role_deactivated'
            else:
                action = 'custom_role_updated'
            target_type = 'role'
            target_id = path.split('/')[-1]
        elif path.startswith('/api/admin/iam/roles') and method == 'DELETE':
            action = 'custom_role_deleted'
            target_type = 'role'
            target_id = path.split('/')[-1]

        if not action:
            return response

        default_details = {
            'method': method,
            'path': path,
            'status': int(getattr(response, 'status_code', 0) or 0),
            'query': request.query_string.decode('utf-8', errors='ignore') if request.query_string else '',
            'payload': _sanitize_audit_payload(payload),
        }
        details = ({**default_details, **details_override} if isinstance(details_override, dict) else default_details)
        _write_portal_audit(action, target_type, target_id, actor, details)
    except Exception:
        pass
    return response


def _safe_user_folder(user_value: object | None) -> str:
    """Convert user identifier into a safe folder name."""
    raw = str(user_value or "unknown_user").strip().lower()
    safe = re.sub(r"[^a-z0-9._-]+", "_", raw)
    return safe[:120] or "unknown_user"


def _normalize_host(host_value: object | None) -> str:
    """Normalize host strings for loose matching between incident and artifact records."""
    h = str(host_value or "").strip().lower()
    if h.startswith("www."):
        h = h[4:]
    return h


ALLOWED_CLASSIFICATIONS = {
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "FALSE_NEGATIVE",
    "BENIGN_POSITIVE",
}


def _normalize_classification(value: object | None) -> str:
    raw = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    return raw if raw in ALLOWED_CLASSIFICATIONS else ""


def _parse_tags(value: object | None) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.split(',') if v.strip()]
    return []


def _has_required_closure_logs(logs: list[dict]) -> tuple[bool, bool]:
    has_initial = any(str(l.get('stage', '')).lower() == 'initial' and str(l.get('note', '')).strip() for l in logs)
    has_final = any(str(l.get('stage', '')).lower() == 'final' and str(l.get('note', '')).strip() for l in logs)
    return has_initial, has_final


def _normalize_managed_extension_settings(managed: dict | None = None) -> dict:
    raw = managed if isinstance(managed, dict) else {}

    def _as_bool(v, default=False):
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in {'true', '1', 'yes', 'on'}:
                return True
            if s in {'false', '0', 'no', 'off'}:
                return False
        return bool(v) if v is not None else default

    def _as_int(v, default=0):
        try:
            return int(v)
        except Exception:
            return default

    def _as_str_list(v):
        if not isinstance(v, list):
            return []
        out = []
        for x in v:
            s = str(x or '').strip()
            if s:
                out.append(s)
        return out

    block_mode = str(raw.get('blockMode', 'block') or 'block').strip().lower()
    if block_mode not in {'block', 'warn', 'monitor'}:
        block_mode = 'block'

    scan_threshold = str(raw.get('scanThreshold', 'medium') or 'medium').strip().lower()
    if scan_threshold not in {'low', 'medium', 'high', 'critical'}:
        scan_threshold = 'medium'

    ai_scan_mode = str(raw.get('aiScanMode', 'smart') or 'smart').strip().lower()
    if ai_scan_mode not in {'always', 'smart', 'never'}:
        ai_scan_mode = 'smart'

    max_file_size = _as_int(raw.get('maxFileSize', 10 * 1024 * 1024), 10 * 1024 * 1024)
    if max_file_size <= 0:
        max_file_size = 10 * 1024 * 1024

    return {
        "enabled": _as_bool(raw.get('enabled', True), True),
        "hardBlockAllUploads": _as_bool(raw.get('hardBlockAllUploads', False), False),
        "blockMode": block_mode,
        "scanThreshold": scan_threshold,
        "notifyOnDetection": _as_bool(raw.get('notifyOnDetection', True), True),
        "reportToApi": _as_bool(raw.get('reportToApi', True), True),
        "strictInspection": _as_bool(raw.get('strictInspection', True), True),
        "silentMode": _as_bool(raw.get('silentMode', False), False),
        "aiEnabled": _as_bool(raw.get('aiEnabled', True), True),
        "aiScanMode": ai_scan_mode,
        "allowedDomains": _as_str_list(raw.get('allowedDomains')),
        "blockedDomains": _as_str_list(raw.get('blockedDomains')),
        "highRiskDomains": _as_str_list(raw.get('highRiskDomains')),
        "maxFileSize": max_file_size,
        "settingsLocked": True,
    }


def _to_clean_list(value: object | None) -> list[str]:
    if isinstance(value, list):
        source = value
    elif isinstance(value, str):
        source = value.split(',')
    else:
        source = []
    out: list[str] = []
    seen = set()
    for item in source:
        s = str(item or '').strip()
        if not s:
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _normalize_iso_datetime(value: object | None) -> str | None:
    s = str(value or '').strip()
    if not s:
        return None
    candidate = s
    if candidate.endswith('Z'):
        candidate = candidate[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(candidate)
    except Exception:
        return None
    return dt.isoformat().replace('+00:00', 'Z')


def _extract_domain_list(values: list[str] | None) -> list[str]:
    source = values if isinstance(values, list) else []
    out: list[str] = []
    seen = set()
    for item in source:
        s = str(item or '').strip().lower()
        if not s:
            continue
        if '@' in s:
            s = s.split('@')[-1].strip()
        s = s.removeprefix('https://').removeprefix('http://').removeprefix('www.')
        s = s.split('/')[0].split(':')[0].strip('.')
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _normalize_exception_payload(payload: dict | None = None) -> dict:
    data = payload if isinstance(payload, dict) else {}
    scope = str(data.get('scope_type') or 'global').strip().lower()
    if scope not in {'global', 'policy'}:
        scope = 'global'

    mode = str(data.get('mode') or 'allow_and_log').strip().lower()
    if mode not in {'allow_and_log', 'allow', 'monitor_only'}:
        mode = 'allow_and_log'

    policy_ids = _to_clean_list(data.get('policy_ids'))
    policy_id = str(data.get('policy_id') or '').strip() or None
    if policy_id and policy_id not in policy_ids:
        policy_ids.insert(0, policy_id)
    if policy_ids:
        policy_id = policy_ids[0]
    if scope == 'global':
        policy_id = None
        policy_ids = []

    users = _to_clean_list(data.get('users'))
    senders = _to_clean_list(data.get('senders'))
    recipients = _to_clean_list(data.get('recipients'))
    domains = _to_clean_list(data.get('domains'))

    # Browser flow has one primary identity, so keep users/senders aligned.
    if not users and senders:
        users = list(senders)
    if not senders and users:
        senders = list(users)

    # Treat recipient entries as domain-compatible criteria too.
    # Example: recipient "audit@corp.com" also matches domain "corp.com".
    domains = _to_clean_list(domains + _extract_domain_list(recipients))

    expires_at = _normalize_iso_datetime(data.get('expires_at'))

    return {
        'name': str(data.get('name') or '').strip(),
        'description': str(data.get('description') or '').strip(),
        'scope_type': scope,
        'policy_id': policy_id,
        'policy_ids': policy_ids,
        'mode': mode,
        'users': users,
        'senders': senders,
        'recipients': recipients,
        'domains': domains,
        'expires_at': expires_at,
        'ticket_id': str(data.get('ticket_id') or '').strip(),
        'reason': str(data.get('reason') or '').strip(),
        'is_active': 1 if bool(data.get('is_active', True)) else 0,
    }


def _exception_to_rule_set(exception_row: dict) -> dict:
    policy_ids = _to_clean_list(exception_row.get('policy_ids'))
    if not policy_ids:
        pid = str(exception_row.get('policy_id') or '').strip()
        policy_ids = [pid] if pid else []
    policy_id = str(exception_row.get('policy_id') or '').strip() or (policy_ids[0] if policy_ids else None)
    return {
        'id': exception_row.get('exception_id'),
        'name': exception_row.get('name') or '',
        'scope_type': exception_row.get('scope_type') or 'global',
        'policy_id': policy_id,
        'policy_ids': policy_ids,
        'mode': exception_row.get('mode') or 'allow_and_log',
        'users': _to_clean_list(exception_row.get('users')),
        'senders': _to_clean_list(exception_row.get('senders')),
        'recipients': _to_clean_list(exception_row.get('recipients')),
        'domains': _to_clean_list(exception_row.get('domains')),
        'expires_at': exception_row.get('expires_at'),
        'ticket_id': str(exception_row.get('ticket_id') or '').strip(),
        'reason': str(exception_row.get('reason') or '').strip(),
    }


def _aggregate_legacy_exceptions(exception_sets: list[dict], existing: dict | None = None) -> dict:
    base = existing if isinstance(existing, dict) else {}
    users = _to_clean_list(base.get('users'))
    senders = _to_clean_list(base.get('senders'))
    recipients = _to_clean_list(base.get('recipients'))
    domains = _to_clean_list(base.get('domains'))

    users.extend([x for s in exception_sets for x in _to_clean_list(s.get('users'))])
    senders.extend([x for s in exception_sets for x in _to_clean_list(s.get('senders'))])
    recipients.extend([x for s in exception_sets for x in _to_clean_list(s.get('recipients'))])
    domains.extend([x for s in exception_sets for x in _to_clean_list(s.get('domains'))])

    return {
        'users': _to_clean_list(users),
        'senders': _to_clean_list(senders),
        'recipients': _to_clean_list(recipients),
        'domains': _to_clean_list(domains),
        'expires_at': base.get('expires_at'),
        'mode': str(base.get('mode') or 'allow_and_log'),
        'reason': str(base.get('reason') or '').strip(),
        'ticket_id': str(base.get('ticket_id') or '').strip(),
    }

def init_components(store, rules, processor, escalation, analyzer, classifier, bot, db=None):
    """Initialize components from main.py"""
    global incident_store, rules_engine, event_processor, escalation_engine
    global ai_analyzer, fp_classifier, telegram_bot, database, file_scanner
    incident_store = store
    rules_engine = rules
    event_processor = processor
    escalation_engine = escalation
    ai_analyzer = analyzer
    fp_classifier = classifier
    telegram_bot = bot
    database = db or (store.db if hasattr(store, 'db') else None)
    file_scanner = FileContentScanner()
    _bootstrap_local_admin()


# ============== AUTH / RBAC ==============

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500

    _bootstrap_local_admin()
    payload = request.json or {}
    email = str(payload.get('email') or '').strip().lower()
    password = str(payload.get('password') or '')

    if not email or not password:
        return jsonify({'error': 'email and password are required'}), 400

    user = database.get_app_user_by_email(email)
    if not user or not bool(user.get('is_active')):
        return jsonify({'error': 'invalid_credentials'}), 401

    locked_until_raw = str(user.get('locked_until') or '').strip()
    if locked_until_raw:
        try:
            locked_until_dt = datetime.fromisoformat(locked_until_raw.replace('Z', '+00:00'))
            now_dt = datetime.now(locked_until_dt.tzinfo) if locked_until_dt.tzinfo else datetime.now()
            if locked_until_dt > now_dt:
                return jsonify({'error': 'account_locked', 'locked_until': locked_until_raw}), 423
        except Exception:
            pass

    if not _verify_password(password, str(user.get('password_hash') or '')):
        failed_attempts = int(user.get('failed_login_attempts') or 0) + 1
        updates: dict[str, object] = {'failed_login_attempts': failed_attempts}
        iam_settings = _get_iam_settings()
        max_attempts = max(3, _int_setting(iam_settings.get('auth_max_failed_attempts'), AUTH_MAX_FAILED_ATTEMPTS))
        lockout_minutes = max(1, _int_setting(iam_settings.get('auth_lockout_minutes'), AUTH_LOCKOUT_MINUTES))
        if failed_attempts >= max_attempts:
            lock_until = datetime.now() + timedelta(minutes=lockout_minutes)
            updates['locked_until'] = lock_until.isoformat()
            try:
                database.update_app_user(str(user.get('user_id')), **updates)
            except Exception:
                pass
            return jsonify({'error': 'account_locked', 'locked_until': lock_until.isoformat()}), 423
        try:
            database.update_app_user(str(user.get('user_id')), **updates)
        except Exception:
            pass
        return jsonify({'error': 'invalid_credentials'}), 401

    try:
        database.update_app_user(
            str(user.get('user_id')),
            last_login_at=datetime.now().isoformat(),
            failed_login_attempts=0,
            locked_until=None,
        )
        user = database.get_app_user_by_id(str(user.get('user_id'))) or user
    except Exception:
        pass

    now_dt = datetime.now()
    expires_dt = now_dt + timedelta(seconds=AUTH_TOKEN_MAX_AGE_SECONDS)
    session_id = database.create_auth_session(
        user_id=str(user.get('user_id')),
        issued_at=now_dt.isoformat(),
        expires_at=expires_dt.isoformat(),
        user_agent=request.headers.get('User-Agent', ''),
        ip_address=request.remote_addr,
    )

    # Optional concurrency control.
    try:
        iam_settings = _get_iam_settings()
        max_sessions = max(1, _int_setting(iam_settings.get('max_concurrent_sessions'), 3))
        sessions = database.list_user_auth_sessions(str(user.get('user_id')), include_revoked=False)
        if len(sessions) > max_sessions:
            to_revoke = sessions[max_sessions:]
            for sess in to_revoke:
                database.revoke_auth_session(str(sess.get('session_id')), reason='max_concurrent_sessions_enforced')
    except Exception:
        pass

    token = _create_auth_token(user, session_id=session_id)
    perms = sorted(_effective_permissions_for_role(str(user.get('role') or 'VIEWER')))
    return jsonify({
        'token': token,
        'token_type': 'Bearer',
        'expires_in': AUTH_TOKEN_MAX_AGE_SECONDS,
        'session_id': session_id,
        'permissions': perms,
        'user': _user_public_view(user),
    }), 200


@app.route('/api/auth/change-password', methods=['POST'])
def auth_change_password():
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({'error': 'unauthorized'}), 401

    payload = request.json or {}
    old_password = str(payload.get('old_password') or '')
    new_password = str(payload.get('new_password') or '')
    policy_error = _validate_password_against_policy(new_password, str(user.get('email') or ''))
    if policy_error:
        return jsonify({'error': policy_error}), 400
    if not _verify_password(old_password, str(user.get('password_hash') or '')):
        return jsonify({'error': 'invalid_current_password'}), 400

    updated = database.update_app_user(
        str(user.get('user_id')),
        password_hash=_hash_password(new_password),
        must_change_password=False,
        password_changed_at=datetime.now().isoformat(),
    )
    if not updated:
        return jsonify({'error': 'update_failed'}), 500
    return jsonify({'status': 'password_changed'}), 200


@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    return jsonify({'user': _user_public_view(user)}), 200


@app.route('/api/auth/permissions', methods=['GET'])
def auth_permissions():
    role = str(getattr(g, 'current_role', 'VIEWER') or 'VIEWER').upper()
    perms = sorted(_effective_permissions_for_role(role))
    return jsonify({
        'role': role,
        'permissions': perms,
        'catalog': IAM_PERMISSION_CATALOG,
    }), 200


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    sid = str(getattr(g, 'current_session_id', '') or '').strip()
    if not sid or not database:
        return jsonify({'status': 'ok'}), 200
    database.revoke_auth_session(sid, reason='logout')
    return jsonify({'status': 'logged_out'}), 200


@app.route('/api/auth/sessions', methods=['GET'])
def auth_sessions():
    if not database:
        return jsonify({'sessions': []}), 200
    user = getattr(g, 'current_user', None) or {}
    current_sid = str(getattr(g, 'current_session_id', '') or '')
    sessions = database.list_user_auth_sessions(str(user.get('user_id') or ''), include_revoked=True)
    out = []
    for s in sessions:
        out.append({
            'session_id': s.get('session_id'),
            'issued_at': s.get('issued_at'),
            'expires_at': s.get('expires_at'),
            'last_seen_at': s.get('last_seen_at'),
            'revoked_at': s.get('revoked_at'),
            'revoked_reason': s.get('revoked_reason'),
            'user_agent': s.get('user_agent'),
            'ip_address': s.get('ip_address'),
            'is_current': str(s.get('session_id') or '') == current_sid,
        })
    return jsonify({'sessions': out}), 200


@app.route('/api/auth/sessions/revoke', methods=['POST'])
def auth_revoke_session():
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500
    payload = request.json or {}
    target_sid = str(payload.get('session_id') or '').strip()
    revoke_all = bool(payload.get('revoke_all'))
    user = getattr(g, 'current_user', None) or {}
    role = str(getattr(g, 'current_role', 'VIEWER') or 'VIEWER').upper()
    current_sid = str(getattr(g, 'current_session_id', '') or '')

    if revoke_all:
        count = database.revoke_user_sessions(str(user.get('user_id') or ''), except_session_id=current_sid, reason='self_revoke_all')
        return jsonify({'status': 'revoked', 'count': count}), 200

    if not target_sid:
        return jsonify({'error': 'session_id is required'}), 400

    target = database.get_auth_session(target_sid)
    if not target:
        return jsonify({'error': 'session_not_found'}), 404

    is_owner = str(target.get('user_id') or '') == str(user.get('user_id') or '')
    is_admin = _has_permission(role, 'users.manage')
    if not is_owner and not is_admin:
        return jsonify({'error': 'forbidden'}), 403

    database.revoke_auth_session(target_sid, reason='manual_revoke')
    return jsonify({'status': 'revoked'}), 200


@app.route('/api/auth/profile', methods=['PATCH'])
def auth_update_profile():
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({'error': 'unauthorized'}), 401

    payload = request.json or {}
    updates: dict[str, object] = {}

    if 'display_name' in payload:
        dn = str(payload.get('display_name') or '').strip()
        if not dn:
            return jsonify({'error': 'display_name cannot be empty'}), 400
        updates['display_name'] = dn

    if 'timezone' in payload:
        updates['timezone'] = str(payload.get('timezone') or 'Asia/Kolkata').strip() or 'Asia/Kolkata'

    if 'locale' in payload:
        updates['locale'] = str(payload.get('locale') or 'en-IN').strip() or 'en-IN'

    if 'theme_preference' in payload:
        t = str(payload.get('theme_preference') or 'light').strip().lower()
        if t not in VALID_THEME_PREFS:
            return jsonify({'error': 'theme_preference must be system|light|dark'}), 400
        updates['theme_preference'] = t

    if 'notify_email' in payload:
        updates['notify_email'] = bool(payload.get('notify_email'))

    if 'notify_telegram' in payload:
        updates['notify_telegram'] = bool(payload.get('notify_telegram'))

    if not updates:
        return jsonify({'error': 'no_updates'}), 400

    updated = database.update_app_user(str(user.get('user_id')), **updates)
    if not updated:
        return jsonify({'error': 'update_failed'}), 500
    return jsonify({'status': 'updated', 'user': _user_public_view(updated)}), 200


@app.route('/api/admin/users', methods=['GET'])
def admin_list_users():
    if not database:
        return jsonify({'users': []}), 200
    users = [_user_public_view(u) for u in database.list_app_users(active_only=False)]
    return jsonify({'users': users}), 200


@app.route('/api/admin/users', methods=['POST'])
def admin_create_user():
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500

    payload = request.json or {}
    email = str(payload.get('email') or '').strip().lower()
    display_name = str(payload.get('display_name') or '').strip()
    password = str(payload.get('password') or '').strip()
    role = _normalize_role_key(payload.get('role') or 'SOC_ANALYST')
    manager_email = str(payload.get('manager_email') or '').strip().lower() or None
    is_active = bool(payload.get('is_active', True))

    if not email or not display_name or not password:
        return jsonify({'error': 'email, display_name, and password are required'}), 400
    if not _is_role_allowed_for_assignment(role):
        allowed = sorted([r for r, v in _get_role_catalog(include_inactive=False).items() if v.get('is_active')])
        return jsonify({'error': f'role must be an active role: {", ".join(allowed)}'}), 400
    policy_error = _validate_password_against_policy(password, email)
    if policy_error:
        return jsonify({'error': policy_error.replace('new_password', 'password')}), 400
    if database.get_app_user_by_email(email):
        return jsonify({'error': 'email already exists'}), 409

    created = database.create_app_user(
        email=email,
        display_name=display_name,
        password_hash=_hash_password(password),
        role=role,
        manager_email=manager_email,
        is_active=is_active,
        must_change_password=True,
    )
    if not created:
        return jsonify({'error': 'failed_to_create_user'}), 500
    return jsonify({'status': 'created', 'user': _user_public_view(created)}), 201


@app.route('/api/admin/users/<user_id>', methods=['PATCH'])
def admin_update_user(user_id):
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500

    existing = database.get_app_user_by_id(user_id)
    if not existing:
        return jsonify({'error': 'user_not_found'}), 404

    payload = request.json or {}
    updates = {}
    iam_settings = _get_iam_settings()
    protect_last_super = _bool_setting(iam_settings.get('enforce_last_super_admin_protection'), True)

    if 'display_name' in payload:
        updates['display_name'] = str(payload.get('display_name') or '').strip()
    if 'role' in payload:
        role = _normalize_role_key(payload.get('role') or '')
        if role and not _is_role_allowed_for_assignment(role):
            allowed = sorted([r for r, v in _get_role_catalog(include_inactive=False).items() if v.get('is_active')])
            return jsonify({'error': f'role must be an active role: {", ".join(allowed)}'}), 400
        if role:
            updates['role'] = role
    if 'manager_email' in payload:
        updates['manager_email'] = str(payload.get('manager_email') or '').strip().lower() or None
    if 'is_active' in payload:
        updates['is_active'] = bool(payload.get('is_active'))
    if 'password' in payload:
        pwd = str(payload.get('password') or '').strip()
        if not pwd:
            return jsonify({'error': 'password cannot be empty'}), 400
        updates['password_hash'] = _hash_password(pwd)

    target_new_role = str(updates.get('role') or existing.get('role') or '').upper()
    target_active = bool(updates.get('is_active', existing.get('is_active')))
    existing_role = str(existing.get('role') or '').upper()

    if protect_last_super and existing_role == 'SUPER_ADMIN' and (target_new_role != 'SUPER_ADMIN' or not target_active):
        active_super = database.count_active_users_by_role('SUPER_ADMIN')
        if active_super <= 1:
            return jsonify({'error': 'cannot_modify_last_active_super_admin'}), 400

    updated = database.update_app_user(user_id, **updates)
    if not updated:
        return jsonify({'error': 'update_failed'}), 500
    return jsonify({'status': 'updated', 'user': _user_public_view(updated)}), 200


@app.route('/api/admin/users/<user_id>/reset-password', methods=['POST'])
def admin_reset_user_password(user_id):
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500
    existing = database.get_app_user_by_id(user_id)
    if not existing:
        return jsonify({'error': 'user_not_found'}), 404

    payload = request.json or {}
    new_password = str(payload.get('new_password') or '').strip()
    policy_error = _validate_password_against_policy(new_password, str(existing.get('email') or ''))
    if policy_error:
        return jsonify({'error': policy_error}), 400

    updated = database.update_app_user(
        user_id,
        password_hash=_hash_password(new_password),
        must_change_password=True,
        failed_login_attempts=0,
        locked_until=None,
        password_changed_at=datetime.now().isoformat(),
    )
    if not updated:
        return jsonify({'error': 'update_failed'}), 500
    return jsonify({'status': 'password_reset', 'user': _user_public_view(updated)}), 200


@app.route('/api/admin/users/<user_id>/revoke-sessions', methods=['POST'])
def admin_revoke_user_sessions(user_id):
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500
    existing = database.get_app_user_by_id(user_id)
    if not existing:
        return jsonify({'error': 'user_not_found'}), 404
    revoked = database.revoke_user_sessions(user_id, except_session_id=None, reason='admin_revoke_all_sessions')
    return jsonify({'status': 'revoked', 'count': revoked}), 200


@app.route('/api/admin/iam/settings', methods=['GET'])
def admin_get_iam_settings():
    return jsonify({'settings': _get_iam_settings(), 'defaults': IAM_SETTINGS_DEFAULTS}), 200


@app.route('/api/admin/iam/settings', methods=['PATCH'])
def admin_update_iam_settings():
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500
    payload = request.json or {}
    allowed_keys = set(IAM_SETTINGS_DEFAULTS.keys()) | {'auth_max_failed_attempts', 'auth_lockout_minutes'}
    updates = {k: payload[k] for k in payload.keys() if k in allowed_keys}
    if not updates:
        return jsonify({'error': 'no_valid_settings'}), 400

    normalized: dict[str, object] = {}
    for k, v in updates.items():
        if k in {
            'password_require_upper', 'password_require_lower', 'password_require_digit',
            'password_require_special', 'password_prevent_email_localpart',
            'enforce_last_super_admin_protection', 'enforce_policy_delete_confirmation_ticket',
        }:
            normalized[k] = _bool_setting(v, bool(IAM_SETTINGS_DEFAULTS.get(k, False)))
        elif k in {'password_min_length', 'max_concurrent_sessions', 'session_idle_timeout_minutes', 'auth_max_failed_attempts', 'auth_lockout_minutes'}:
            normalized[k] = max(1, _int_setting(v, int(IAM_SETTINGS_DEFAULTS.get(k, 1))))
        else:
            normalized[k] = v

    actor = _actor_from_request(default_actor='system')
    merged = database.upsert_iam_settings(normalized, actor=actor)
    out = dict(IAM_SETTINGS_DEFAULTS)
    out.update(merged)
    return jsonify({'status': 'updated', 'settings': out}), 200


@app.route('/api/admin/iam/roles', methods=['GET'])
def admin_get_iam_roles():
    if not database:
        return jsonify({'roles': []}), 200
    overrides = database.get_role_permission_overrides()
    roles = []
    catalog = _get_role_catalog(include_inactive=True)
    for role in sorted(catalog.keys()):
        meta = catalog.get(role, {})
        roles.append({
            'role': role,
            'display_name': meta.get('display_name') or role,
            'description': meta.get('description') or '',
            'is_system': bool(meta.get('is_system')),
            'is_active': bool(meta.get('is_active', True)),
            'default_permissions': sorted(IAM_ROLE_DEFAULTS.get(role, set())),
            'overrides': overrides.get(role, {}),
            'effective_permissions': sorted(_effective_permissions_for_role(role)),
        })
    return jsonify({'roles': roles, 'catalog': IAM_PERMISSION_CATALOG}), 200


@app.route('/api/admin/iam/roles', methods=['POST'])
def admin_create_custom_role():
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500

    payload = request.json or {}
    role = _normalize_role_key(payload.get('role') or payload.get('role_key'))
    display_name = str(payload.get('display_name') or role).strip()
    description = str(payload.get('description') or '').strip()

    if not role:
        return jsonify({'error': 'role is required'}), 400
    if not ROLE_KEY_PATTERN.match(role):
        return jsonify({'error': 'role must match pattern [A-Z][A-Z0-9_]{1,48}'}), 400
    if role in SYSTEM_ROLES:
        return jsonify({'error': 'cannot_create_system_role'}), 400

    existing = database.get_custom_role(role)
    if existing:
        return jsonify({'error': 'role_already_exists'}), 409

    actor = _actor_from_request(default_actor='system')
    created = database.create_custom_role(
        role_key=role,
        display_name=display_name,
        description=description,
        is_active=True,
        actor=actor,
    )
    if not created:
        return jsonify({'error': 'failed_to_create_role'}), 500
    return jsonify({'status': 'created', 'role': created}), 201


@app.route('/api/admin/iam/roles/<role>', methods=['PATCH'])
def admin_update_custom_role(role):
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500

    role_u = _normalize_role_key(role)
    if role_u in SYSTEM_ROLES:
        return jsonify({'error': 'system_roles_cannot_be_modified'}), 400

    existing = database.get_custom_role(role_u)
    if not existing:
        return jsonify({'error': 'role_not_found'}), 404

    payload = request.json or {}
    updates: dict[str, object] = {}
    if 'display_name' in payload:
        updates['display_name'] = str(payload.get('display_name') or '').strip() or role_u
    if 'description' in payload:
        updates['description'] = str(payload.get('description') or '').strip()
    if 'is_active' in payload:
        next_active = bool(payload.get('is_active'))
        if not next_active and database.count_users_by_role(role_u) > 0:
            return jsonify({'error': 'cannot_deactivate_role_in_use'}), 400
        updates['is_active'] = next_active

    if not updates:
        return jsonify({'error': 'no_updates'}), 400

    updates['updated_by'] = _actor_from_request(default_actor='system')
    updated = database.update_custom_role(role_u, **updates)
    if not updated:
        return jsonify({'error': 'update_failed'}), 500
    return jsonify({'status': 'updated', 'role': updated}), 200


@app.route('/api/admin/iam/roles/<role>', methods=['DELETE'])
def admin_delete_custom_role(role):
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500

    role_u = _normalize_role_key(role)
    if role_u in SYSTEM_ROLES:
        return jsonify({'error': 'system_roles_cannot_be_deleted'}), 400

    existing = database.get_custom_role(role_u)
    if not existing:
        return jsonify({'error': 'role_not_found'}), 404

    if database.count_users_by_role(role_u) > 0:
        return jsonify({'error': 'cannot_delete_role_in_use'}), 400

    actor = _actor_from_request(default_actor='system')
    try:
        database.delete_role_permission_overrides(role_u, actor=actor)
    except Exception:
        pass

    deleted = database.delete_custom_role(role_u, actor=actor)
    if not deleted:
        return jsonify({'error': 'delete_failed'}), 500
    return jsonify({'status': 'deleted', 'role': role_u}), 200


@app.route('/api/admin/iam/roles/<role>/permissions', methods=['PUT'])
def admin_put_iam_role_permissions(role):
    if not database:
        return jsonify({'error': 'Database not initialized'}), 500
    role_u = str(role or '').strip().upper()
    role_catalog = _get_role_catalog(include_inactive=True)
    if role_u not in role_catalog:
        return jsonify({'error': 'role_not_found'}), 400

    payload = request.json or {}
    incoming = payload.get('permissions')
    if not isinstance(incoming, dict):
        return jsonify({'error': 'permissions object is required'}), 400

    sanitized = {}
    for perm_key, val in incoming.items():
        key = str(perm_key or '').strip()
        if key in IAM_PERMISSION_CATALOG:
            sanitized[key] = _bool_setting(val, False)

    actor = _actor_from_request(default_actor='system')
    database.replace_role_permission_overrides(role_u, sanitized, actor=actor)
    return jsonify({
        'status': 'updated',
        'role': role_u,
        'effective_permissions': sorted(_effective_permissions_for_role(role_u)),
    }), 200


# ============== EVENT INGESTION ==============

@app.route('/api/events', methods=['POST'])
def ingest_event():
    """Ingest event from agent"""

    data = request.json or {}

    try:
        if not event_processor:
            return jsonify({"status": "error", "message": "Event processor not initialized"}), 500

        event_id = event_processor.process_event(
            agent_type=data.get('agent_type', 'unknown'),
            source_host=data.get('source_host', 'unknown'),
            user=data.get('user', 'unknown'),
            channel=data.get('channel', 'unknown'),
            payload=data.get('payload', ''),
            geo=data.get('geo', {})
        )

        return jsonify({
            "status": "success",
            "event_id": event_id
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 400


@app.route('/api/browser/incident', methods=['POST'])
def create_browser_incident():
    """Create an incident directly from a browser extension detection and send Telegram alert."""
    data = request.json or {}

    try:
        from src.incident_store import Event
        import hashlib

        if not incident_store:
            return jsonify({"error": "Incident store not initialized"}), 500

        payload = data.get('payload', '')
        user = data.get('user', 'browser_user')
        host = data.get('source_host', 'unknown')
        channel = data.get('channel', 'browser_upload')
        geo = data.get('geo', {})
        
        severity = geo.get('severity', 'high')
        action = geo.get('action', 'block')
        upload_batch_id = str(geo.get('upload_batch_id') or '').strip()
        
        # Build event
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        event_id = f"EVT-B-{uuid.uuid4().hex[:8].upper()}"
        
        # Parse payload to get better pattern description for Telegram
        # Browser payload format: File: <name>\nDomain: <domain>\nAction: <action>\nPatterns: <patterns>\n<sample>
        pattern_desc = "Browser Upload"
        lines = payload.split("\n")
        file_name = "unknown file"
        patterns_matched = ""
        for line in lines:
            if line.startswith("File: "):
                file_name = line.replace("File: ", "").strip()
            elif line.startswith("Patterns: "):
                patterns_matched = line.replace("Patterns: ", "").strip()
        
        pattern_desc = f"{file_name} [{patterns_matched}]"
        
        # Extract matched samples (everything after Patterns)
        samples = []
        parsing_samples = False
        for line in lines:
            if parsing_samples and line.startswith("["):
                samples.append(line)
            if line.startswith("Patterns: "):
                parsing_samples = True

        if samples:
            pattern_desc += f" | {', '.join(samples[:2])}"

        event = Event(
            event_id=event_id,
            timestamp=datetime.now().isoformat(),
            agent_type='browser_extension',
            source_host=host,
            user=user,
            channel=channel,
            payload_hash=payload_hash,
            payload_sample=payload,
            matched_rules=[patterns_matched] if patterns_matched else ["Browser Upload"],
            severity=severity,
            geo=geo
        )
        
        # Store event
        incident_store.add_event(event)

        findings = geo.get('findings') if isinstance(geo.get('findings'), list) else []
        has_findings = len(findings) > 0
        exception_applied = bool(geo.get('exception_applied'))
        only_exception_findings = has_findings and all(
            str((f or {}).get('category') or '').strip().lower() == 'policy exception'
            or str((f or {}).get('source') or '').strip().lower() in {'policy_exception', 'global_exception'}
            for f in findings if isinstance(f, dict)
        )
        exception_mode = str(geo.get('exception_mode') or '').strip().lower()
        should_suppress_incident = exception_applied or (
            str(action).strip().lower() == 'allow'
            and only_exception_findings
            and exception_mode in {'allow', 'allow_and_log', ''}
        )

        if should_suppress_incident:
            return jsonify({
                "status": "event_logged",
                "event_id": event.event_id,
                "incident_id": None,
                "suppressed": "policy_exception",
            }), 200

        # Create incident
        avg_risk = 90 if severity == "critical" else 75 if severity == "high" else 40
        ai_analysis_dict = {}
        if geo.get("ai_used"):
            ai_score = geo.get("ai_risk_score", avg_risk)
            try:
                avg_risk = int(ai_score) if ai_score is not None and str(ai_score).strip() != "" else avg_risk
            except (TypeError, ValueError):
                avg_risk = avg_risk
            # Extract AI reasoning from payload if available
            ai_reason_line = next((l for l in lines if l.startswith("AI Reasoning: ")), None)
            verdict = "LIKELY_THREAT" if avg_risk > 60 else "NEEDS_REVIEW"
            ai_analysis_dict = {
                "verdict": verdict,
                "reasoning": ai_reason_line.replace("AI Reasoning: ", "") if ai_reason_line else "Analyzed by Gemini 2.0 Flash in Browser",
                "risk_score": avg_risk
            }

        if upload_batch_id:
            pattern_desc = f"Batch Upload {upload_batch_id[:32]}"

        # Reuse active recent incident for same user+host (and logically same batch/upload family)
        # so repeat_count increments instead of creating duplicate incidents.
        incident = None
        with browser_incident_lock:
            recent_match = None
            try:
                current_pattern = pattern_desc[:250]
                current_is_batch = bool(upload_batch_id)
                file_name_l = str(file_name or '').strip().lower()

                for cand in incident_store.get_all_incidents():
                    if cand.user != user or cand.host != host:
                        continue
                    if cand.status not in ("OPEN", "ESCALATED"):
                        continue

                    try:
                        created_at = datetime.fromisoformat(str(cand.created_at).replace('Z', '+00:00'))
                        if abs((datetime.now() - created_at).total_seconds()) > (30 * 60):
                            continue
                    except Exception:
                        pass

                    cand_pattern = str(cand.pattern or '')
                    same_pattern = cand_pattern == current_pattern

                    # Batch uploads should merge even if upload_batch_id differs.
                    if not same_pattern and current_is_batch and cand_pattern.startswith('Batch Upload '):
                        same_pattern = True

                    # Backward compatibility: match prior non-batch incidents by file name prefix.
                    if not same_pattern and file_name_l:
                        same_pattern = cand_pattern.lower().startswith(f"{file_name_l} [")

                    if not same_pattern:
                        continue

                    recent_match = cand
                    break
            except Exception:
                recent_match = None

            if recent_match:
                existing_events = list(recent_match.events or [])
                existing_events.append(event.event_id)
                incident_store.update_incident(
                    recent_match.incident_id,
                    alert_count=int(recent_match.alert_count or 0) + 1,
                    repeat_count=int(recent_match.repeat_count or 0) + 1,
                    risk=min(100, int(recent_match.risk or avg_risk) + 10),
                    events=existing_events,
                )
                incident = incident_store.get_incident(recent_match.incident_id)
            else:
                dedup_scope = 'batch_upload' if upload_batch_id else str(file_name or 'unknown').strip().lower()[:120]
                dedup_key = f"browser:{str(user).strip().lower()}|{str(host).strip().lower()}|{dedup_scope}"
                incident = incident_store.create_incident(
                    user=user,
                    host=host,
                    channel=channel,
                    pattern=pattern_desc[:250],
                    risk=avg_risk,
                    events=[event],
                    dedup_key=dedup_key,
                )

        if not incident:
            return jsonify({"error": "Failed to create or update incident"}), 500
        
        # Patch AI analysis if used
        if ai_analysis_dict:
            incident.ai_analysis = ai_analysis_dict
            incident.verdict = ai_analysis_dict["verdict"]
        
        print(f"🚨 BROWSER INCIDENT: {incident.incident_id} - User {user} upload to {host} ({action})")

        # Broadcast real-time notification to SIEM Console
        try:
            broadcast_notification({
                "type": "incident",
                "incident_id": incident.incident_id,
                "user": user,
                "host": host,
                "pattern": pattern_desc[:100],
                "severity": severity,
                "action": action,
                "risk": avg_risk,
                "timestamp": datetime.now().isoformat(),
                "message": f"🚨 {severity.upper()} — {user}@{host}: {pattern_desc[:80]}"
            })
        except Exception:
            pass

        # Send Telegram alert
        try:
            if telegram_bot:
                verdict_icon = "🔴" if action == "block" else "🟠" if action == "warn" else "🟡"
                summary = f"Browser Upload {action.upper()}: {host}"
                
                loop = getattr(telegram_bot, 'loop', None)
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        telegram_bot.send_alert(
                            incident_id=incident.incident_id,
                            summary=summary,
                            verdictcolor=verdict_icon
                        ),
                        loop
                    )
                    print(f"📱 BROWSER TELEGRAM ALERT QUEUED: {incident.incident_id}")
        except Exception as e:
            print(f"⚠️ Telegram alert failed for browser incident: {scrub_token(e)}")

        return jsonify({
            "status": "success",
            "incident_id": incident.incident_id,
            "event_id": event.event_id
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ============== INCIDENT ANALYSIS ==============

@app.route('/api/incidents/<incident_id>/analyze', methods=['POST'])
def analyze_incident(incident_id):
    """Trigger AI analysis for incident"""

    if not incident_store or not fp_classifier:
        return jsonify({"error": "Analysis components not initialized"}), 500

    incident = incident_store.get_incident(incident_id)

    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    try:
        # Get related events for context
        events_list = incident.events if isinstance(incident.events, list) else []
        event_objs = [incident_store.events.get(e_id) for e_id in events_list]
        detections = ", ".join([
            e.matched_rules[0] if hasattr(e, 'matched_rules') and e.matched_rules else "unknown"
            for e in event_objs if e
        ])

        # Run analysis
        analysis = fp_classifier.classify(
            incident_id=incident_id,
            user=incident.user,
            host=incident.host,
            channel=incident.channel,
            pattern=incident.pattern,
            alert_count=incident.alert_count,
            detections=detections,
            events_summary=f"{incident.alert_count} alerts in {incident.channel}"
        )

        # Update incident with analysis
        incident_store.update_incident(
            incident_id=incident_id,
            verdict=analysis['verdict'],
            fp_probability=analysis['false_positive_probability'],
            risk_score=analysis['risk_score'],
            ai_analysis=analysis
        )

        # Send to Telegram
        try:
            if telegram_bot:
                verdict_emoji = "🔴" if analysis['verdict'] == "LIKELY_THREAT" else "🟢" if analysis['verdict'] == "LIKELY_FP" else "🟡"
                loop = getattr(telegram_bot, 'loop', None)
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        telegram_bot.send_alert(incident_id, "", verdict_emoji), 
                        loop
                    )
        except Exception as e:
            print(f"⚠️ Telegram send failed: {scrub_token(e)}")

        return jsonify(analysis), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============== INCIDENT MANAGEMENT ==============

@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    """Get all incidents with optional filtering"""

    if not incident_store:
        return jsonify({"total": 0, "incidents": []}), 200

    status = request.args.get('status')
    incidents = incident_store.get_all_incidents(status=status)

    return jsonify({
        "total": len(incidents),
        "incidents": [inc.to_dict() for inc in incidents]
    }), 200


@app.route('/api/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    """Get specific incident"""

    if not incident_store:
        return jsonify({"error": "Incident store not initialized"}), 500

    incident = incident_store.get_incident(incident_id)

    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    data = incident.to_dict()

    # Enrich detail payload for UI: exact pattern names + matched text samples.
    try:
        raw_events = data.get('events')
        event_ids = raw_events if isinstance(raw_events, list) else []
        pattern_names = []
        exact_findings = []

        for event_id in event_ids:
            evt = incident_store.events.get(event_id) if incident_store else None
            if (not evt) and database:
                evt = database.get_event(str(event_id))

            if not evt:
                continue

            # Event may be dataclass object or dict.
            matched_rules = getattr(evt, 'matched_rules', None)
            if matched_rules is None and isinstance(evt, dict):
                matched_rules = evt.get('matched_rules')
            if isinstance(matched_rules, list):
                for x in matched_rules:
                    if not x:
                        continue
                    parts = [p.strip() for p in str(x).split(',') if p.strip()]
                    pattern_names.extend(parts or [str(x)])

            geo = getattr(evt, 'geo', None)
            if geo is None and isinstance(evt, dict):
                geo = evt.get('geo')
            geo = geo if isinstance(geo, dict) else {}

            geo_findings = geo.get('findings')
            has_geo_findings = False
            if isinstance(geo_findings, list):
                for f in geo_findings:
                    if not isinstance(f, dict):
                        continue
                    pname = f.get('pattern_name') or f.get('description') or f.get('category') or 'match'
                    mtxt = f.get('matched_text') or ''
                    if mtxt:
                        has_geo_findings = True
                        exact_findings.append({
                            'pattern_name': str(pname),
                            'matched_text': str(mtxt),
                            'severity': str(f.get('severity') or ''),
                        })

            # Fallback parse from payload sample lines: [PATTERN] value
            payload_sample = getattr(evt, 'payload_sample', None)
            if payload_sample is None and isinstance(evt, dict):
                payload_sample = evt.get('payload_sample')
            if not has_geo_findings:
                for line in str(payload_sample or '').split('\n'):
                    m = re.match(r'^\[([^\]]+)\]\s*(.+)$', line.strip())
                    if not m:
                        continue
                    pattern_names.append(m.group(1).strip())
                    exact_findings.append({
                        'pattern_name': m.group(1).strip(),
                        'matched_text': m.group(2).strip(),
                        'severity': '',
                    })

        # De-duplicate while preserving order
        seen_p = set()
        uniq_patterns = []
        for p in pattern_names:
            key = p.strip()
            if not key or key in seen_p:
                continue
            seen_p.add(key)
            uniq_patterns.append(key)

        seen_f = set()
        uniq_findings = []
        for f in exact_findings:
            key = (f.get('pattern_name', ''), f.get('matched_text', ''), f.get('severity', ''))
            if key in seen_f:
                continue
            seen_f.add(key)
            uniq_findings.append(f)

        data['pattern_matches'] = uniq_patterns[:50]
        data['exact_findings'] = uniq_findings[:100]
    except Exception:
        data.setdefault('pattern_matches', [])
        data.setdefault('exact_findings', [])

    try:
        if database:
            data['activity_logs'] = database.get_incident_activity_logs(incident_id)
        else:
            data['activity_logs'] = []
    except Exception:
        data['activity_logs'] = []

    return jsonify(data), 200


@app.route('/api/security-team', methods=['GET'])
def get_security_team():
    """Get available security analysts for assignment."""
    if not database:
        return jsonify({"members": []}), 200
    try:
        members = database.get_security_team(active_only=True)
        return jsonify({"members": members}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/incidents/<incident_id>/activity-log', methods=['GET'])
def get_incident_activity_log(incident_id):
    """Get workflow/activity timeline for an incident."""
    if not database:
        return jsonify({"logs": []}), 200
    try:
        logs = database.get_incident_activity_logs(incident_id)
        return jsonify({"incident_id": incident_id, "logs": logs}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/incidents/<incident_id>/activity-log', methods=['POST'])
def add_incident_activity_log(incident_id):
    """Add analyst workflow note to incident timeline."""
    if not database or not incident_store:
        return jsonify({"error": "Components not initialized"}), 500

    payload = request.json or {}
    stage = str(payload.get('stage') or 'update').strip().lower()
    actor = _actor_from_request('secops_analyst')
    note = str(payload.get('note') or '').strip()
    tags = _parse_tags(payload.get('tags'))

    if stage not in {'initial', 'final', 'update', 'assignment', 'comment'}:
        return jsonify({"error": "Invalid stage. Use initial/final/update/assignment/comment"}), 400
    if not note:
        return jsonify({"error": "note is required"}), 400
    if not incident_store.get_incident(incident_id):
        return jsonify({"error": "Incident not found"}), 404

    try:
        database.add_incident_activity_log(
            incident_id=incident_id,
            stage=stage,
            actor=actor,
            note=note,
            tags=tags,
        )
        if stage == 'initial':
            incident_store.update_incident(incident_id, initial_statement=note)
        if stage == 'final':
            incident_store.update_incident(incident_id, closure_statement=note)

        logs = database.get_incident_activity_logs(incident_id)
        return jsonify({"status": "ok", "incident_id": incident_id, "logs": logs}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
def assign_incident(incident_id):
    """Assign an incident to a security team member."""
    if not database or not incident_store:
        return jsonify({"error": "Components not initialized"}), 500

    payload = request.json or {}
    assignee = str(payload.get('assignee') or '').strip()
    actor = _actor_from_request('secops_analyst')
    note = str(payload.get('note') or '').strip()

    if not assignee:
        return jsonify({"error": "assignee is required"}), 400

    incident = incident_store.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    try:
        updated = database.assign_incident(incident_id, assignee, actor=actor)
        if not updated:
            return jsonify({"error": "Incident not found"}), 404

        incident_store.update_incident(incident_id, assigned_to=assignee, assigned_at=updated.get('assigned_at'))

        if note:
            database.add_incident_activity_log(
                incident_id=incident_id,
                stage='comment',
                actor=actor,
                note=note,
                tags=['ASSIGNMENT_NOTE']
            )

        return jsonify({"status": "assigned", "incident": updated}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/incidents/bulk-action', methods=['POST'])
def bulk_incident_action():
    """Bulk action endpoint for SOC queue operations (assign/close/escalate/reopen/raise_ticket)."""
    if not database or not incident_store:
        return jsonify({"error": "Components not initialized"}), 500

    payload = request.json or {}
    action = str(payload.get('action') or '').strip().lower()
    incident_ids = payload.get('incident_ids') if isinstance(payload.get('incident_ids'), list) else []
    actor = _actor_from_request('secops_analyst')

    if action not in {'assign', 'close', 'escalate', 'reopen', 'raise_ticket', 'raise-ticket'}:
        return jsonify({"error": "action must be assign|close|escalate|reopen|raise_ticket"}), 400
    if not incident_ids:
        return jsonify({"error": "incident_ids is required"}), 400

    assignee = str(payload.get('assignee') or '').strip()
    classification = _normalize_classification(payload.get('classification'))
    initial_note = str(payload.get('initial_statement') or '').strip()
    final_note = str(payload.get('final_statement') or '').strip()
    tags = _parse_tags(payload.get('tags'))

    if action == 'assign' and not assignee:
        return jsonify({"error": "assignee is required for assign action"}), 400
    if action == 'close':
        if not classification:
            return jsonify({"error": "classification is required: TRUE_POSITIVE|FALSE_POSITIVE|FALSE_NEGATIVE|BENIGN_POSITIVE"}), 400
        if not initial_note or not final_note:
            return jsonify({"error": "initial_statement and final_statement are required to close incidents"}), 400

    updated = []
    failed = []
    integration_summary = {
        "slack_sent": 0,
        "slack_failed": 0,
        "slack_unconfigured": 0,
        "jira_created": 0,
        "jira_failed": 0,
        "jira_unconfigured": 0,
    }

    for iid in incident_ids:
        incident_id = str(iid or '').strip()
        if not incident_id:
            continue

        inc = incident_store.get_incident(incident_id)
        if not inc:
            failed.append({"incident_id": incident_id, "error": "not_found"})
            continue

        try:
            if action == 'assign':
                database.assign_incident(incident_id, assignee, actor=actor)
                incident_store.update_incident(incident_id, assigned_to=assignee, assigned_at=datetime.now().isoformat())
                updated.append({"incident_id": incident_id, "status": "assigned", "assignee": assignee})
                continue

            if action == 'escalate':
                if str(getattr(inc, 'status', '')).upper() == 'ESCALATED':
                    failed.append({"incident_id": incident_id, "error": "already_escalated"})
                    continue
                incident = incident_store.escalate_incident(incident_id)
                if not incident:
                    failed.append({"incident_id": incident_id, "error": "escalate_failed"})
                    continue

                incident_dict = incident.to_dict() if hasattr(incident, 'to_dict') else {}
                slack_status = 'unconfigured'
                jira_ticket = None

                if escalation_engine and getattr(escalation_engine, 'slack_webhook', None):
                    slack_sent = escalation_engine.escalate_to_slack(incident_dict)
                    slack_status = 'sent' if slack_sent else 'failed'
                if escalation_engine and all([
                    getattr(escalation_engine, 'jira_server', None),
                    getattr(escalation_engine, 'jira_user', None),
                    getattr(escalation_engine, 'jira_token', None),
                ]):
                    jira_ticket = escalation_engine.escalate_to_jira(incident_dict)

                if slack_status == 'sent':
                    integration_summary['slack_sent'] += 1
                elif slack_status == 'failed':
                    integration_summary['slack_failed'] += 1
                else:
                    integration_summary['slack_unconfigured'] += 1

                if jira_ticket:
                    integration_summary['jira_created'] += 1
                else:
                    if escalation_engine and all([
                        getattr(escalation_engine, 'jira_server', None),
                        getattr(escalation_engine, 'jira_user', None),
                        getattr(escalation_engine, 'jira_token', None),
                    ]):
                        integration_summary['jira_failed'] += 1
                    else:
                        integration_summary['jira_unconfigured'] += 1

                database.add_incident_activity_log(
                    incident_id=incident_id,
                    stage='update',
                    actor=actor,
                    note=f"Incident escalated from bulk queue action. Slack={slack_status}; Jira={jira_ticket or 'none'}",
                    tags=['ESCALATED']
                )
                updated.append({
                    "incident_id": incident_id,
                    "status": "escalated",
                    "slack": slack_status,
                    "jira_ticket": jira_ticket,
                })
                continue

            if action in {'raise_ticket', 'raise-ticket'}:
                incident = incident_store.raise_ticket(incident_id, actor=actor)
                if not incident:
                    failed.append({"incident_id": incident_id, "error": "raise_ticket_failed"})
                    continue

                incident_dict = incident.to_dict() if hasattr(incident, 'to_dict') else {}
                jira_ticket = None
                if escalation_engine and all([
                    getattr(escalation_engine, 'jira_server', None),
                    getattr(escalation_engine, 'jira_user', None),
                    getattr(escalation_engine, 'jira_token', None),
                ]):
                    jira_ticket = escalation_engine.escalate_to_jira(incident_dict)

                if jira_ticket:
                    integration_summary['jira_created'] += 1
                else:
                    if escalation_engine and all([
                        getattr(escalation_engine, 'jira_server', None),
                        getattr(escalation_engine, 'jira_user', None),
                        getattr(escalation_engine, 'jira_token', None),
                    ]):
                        integration_summary['jira_failed'] += 1
                    else:
                        integration_summary['jira_unconfigured'] += 1

                database.add_incident_activity_log(
                    incident_id=incident_id,
                    stage='update',
                    actor=actor,
                    note=f"Ticket raised from bulk queue action. Jira={jira_ticket or 'none'}",
                    tags=['TICKET_RAISED']
                )
                updated.append({
                    "incident_id": incident_id,
                    "status": "ticket_raised",
                    "jira_ticket": jira_ticket,
                })
                continue

            if action == 'reopen':
                incident_store.reopen_incident(incident_id, actor=actor)
                database.add_incident_activity_log(
                    incident_id=incident_id,
                    stage='update',
                    actor=actor,
                    note='Incident reopened from bulk queue action.',
                    tags=['REOPENED']
                )
                updated.append({"incident_id": incident_id, "status": "reopened"})
                continue

            # action == close
            database.add_incident_activity_log(
                incident_id=incident_id,
                stage='initial',
                actor=actor,
                note=initial_note,
                tags=tags + ['INITIAL_STATEMENT']
            )
            database.add_incident_activity_log(
                incident_id=incident_id,
                stage='final',
                actor=actor,
                note=final_note,
                tags=tags + [classification, 'FINAL_CLOSURE']
            )
            incident_store.update_incident(
                incident_id,
                status='CLOSED',
                classification=classification,
                initial_statement=initial_note,
                closure_statement=final_note,
                closed_by=actor,
                closed_at=datetime.now().isoformat(),
            )
            updated.append({"incident_id": incident_id, "status": "closed", "classification": classification})
        except Exception as e:
            failed.append({"incident_id": incident_id, "error": str(e)})

    return jsonify({
        "action": action,
        "updated_count": len(updated),
        "failed_count": len(failed),
        "updated": updated,
        "failed": failed,
        "integrations": integration_summary,
    }), 200


@app.route('/api/incidents/<incident_id>/close', methods=['POST'])
def close_incident(incident_id):
    """Close incident only after required SOC workflow notes are provided."""

    if not incident_store or not database:
        return jsonify({"error": "Incident store not initialized"}), 500

    incident = incident_store.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    payload = request.json or {}
    actor = _actor_from_request('secops_analyst')
    classification = _normalize_classification(payload.get('classification') or getattr(incident, 'classification', None))
    initial_statement = str(payload.get('initial_statement') or '').strip()
    final_statement = str(payload.get('final_statement') or '').strip()
    tags = _parse_tags(payload.get('tags'))

    existing_logs = database.get_incident_activity_logs(incident_id)
    has_initial, has_final = _has_required_closure_logs(existing_logs)

    if not classification:
        return jsonify({"error": "classification is required: TRUE_POSITIVE|FALSE_POSITIVE|FALSE_NEGATIVE|BENIGN_POSITIVE"}), 400

    if not has_initial and not initial_statement:
        return jsonify({"error": "initial_statement is required before closure"}), 400
    if not has_final and not final_statement:
        return jsonify({"error": "final_statement is required before closure"}), 400

    try:
        if initial_statement:
            database.add_incident_activity_log(
                incident_id=incident_id,
                stage='initial',
                actor=actor,
                note=initial_statement,
                tags=tags + ['INITIAL_STATEMENT']
            )
        if final_statement:
            database.add_incident_activity_log(
                incident_id=incident_id,
                stage='final',
                actor=actor,
                note=final_statement,
                tags=tags + [classification, 'FINAL_CLOSURE']
            )

        updated = incident_store.update_incident(
            incident_id,
            status="CLOSED",
            classification=classification,
            initial_statement=initial_statement or getattr(incident, 'initial_statement', None),
            closure_statement=final_statement or getattr(incident, 'closure_statement', None),
            closed_by=actor,
            closed_at=datetime.now().isoformat(),
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if not updated:
        return jsonify({"error": "Incident not found"}), 404

    return jsonify({
        "status": "closed",
        "incident": updated.to_dict() if hasattr(updated, 'to_dict') else updated
    }), 200


@app.route('/api/incidents/<incident_id>/escalate', methods=['POST'])
def escalate_incident(incident_id):
    """Escalate incident to Slack/Jira"""

    try:
        if not incident_store:
            return jsonify({"error": "Incident store not initialized"}), 500

        existing = incident_store.get_incident(incident_id)
        if not existing:
            return jsonify({"error": "Incident not found"}), 404
        if str(getattr(existing, 'status', '')).upper() == 'ESCALATED':
            existing_dict = existing.to_dict() if hasattr(existing, 'to_dict') else existing
            return jsonify({
                "status": "already_escalated",
                "incident": existing_dict,
                "mode": "status_only",
            }), 200

        incident = incident_store.escalate_incident(incident_id)

        if not incident:
            return jsonify({"error": "Incident not found"}), 404

        # Escalate to external systems
        incident_dict = incident.to_dict()

        slack_result = False
        jira_ticket = None
        escalation_mode = "status_only"
        if escalation_engine:
            slack_result = escalation_engine.escalate_to_slack(incident_dict)
            jira_ticket = escalation_engine.escalate_to_jira(incident_dict)
            escalation_mode = "integrated"

        return jsonify({
            "status": "escalated",
            "incident": incident_dict,
            "slack": "sent" if slack_result else "failed",
            "jira_ticket": jira_ticket,
            "mode": escalation_mode,
        }), 200

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Escalate error: {e}")
        print(error_trace)
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@app.route('/api/incidents/<incident_id>/raise-ticket', methods=['POST'])
def raise_incident_ticket(incident_id):
    """Mark incident as ticket raised."""
    if not incident_store or not database:
        return jsonify({"error": "Components not initialized"}), 500

    payload = request.json or {}
    actor = _actor_from_request('secops_analyst')
    note = str(payload.get('note') or 'Ticket raised by analyst').strip()

    incident = incident_store.raise_ticket(incident_id, actor=actor)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    incident_dict = incident.to_dict() if hasattr(incident, 'to_dict') else {}
    jira_ticket = None
    jira_mode = 'unconfigured'
    if escalation_engine and all([
        getattr(escalation_engine, 'jira_server', None),
        getattr(escalation_engine, 'jira_user', None),
        getattr(escalation_engine, 'jira_token', None),
    ]):
        jira_ticket = escalation_engine.escalate_to_jira(incident_dict)
        jira_mode = 'integrated'

    try:
        database.add_incident_activity_log(
            incident_id=incident_id,
            stage='update',
            actor=actor,
            note=f"{note} Jira={jira_ticket or 'none'}",
            tags=['TICKET_RAISED']
        )
    except Exception:
        pass

    return jsonify({
        "status": "ticket_raised",
        "incident": incident_dict,
        "jira_ticket": jira_ticket,
        "jira": 'created' if jira_ticket else ('failed' if jira_mode == 'integrated' else 'unconfigured'),
        "mode": jira_mode,
    }), 200


@app.route('/api/incidents/<incident_id>/reopen', methods=['POST'])
def reopen_incident(incident_id):
    """Reopen a closed/ticketed incident."""
    if not incident_store or not database:
        return jsonify({"error": "Components not initialized"}), 500

    payload = request.json or {}
    actor = _actor_from_request('secops_analyst')
    note = str(payload.get('note') or 'Incident reopened for further investigation').strip()

    incident = incident_store.reopen_incident(incident_id, actor=actor)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    try:
        database.add_incident_activity_log(
            incident_id=incident_id,
            stage='update',
            actor=actor,
            note=note,
            tags=['REOPENED']
        )
    except Exception:
        pass

    return jsonify({"status": "reopened", "incident": incident.to_dict()}), 200


# ============== EVENTS ==============

@app.route('/api/events', methods=['GET'])
def get_events():
    """Get recent events"""
    limit = request.args.get('limit', 50, type=int)
    if database:
        events = database.get_all_events(limit=limit)
        return jsonify({
            "total": len(events),
            "events": events
        }), 200
    return jsonify({"total": 0, "events": []}), 200


@app.route('/api/events/<event_id>', methods=['GET'])
def get_event_by_id(event_id):
    """Get single event by event_id"""
    if not database:
        return jsonify({"error": "Database not configured"}), 500

    eid = (event_id or '').strip()
    if not eid:
        return jsonify({"error": "event_id is required"}), 400

    event = database.get_event(eid)
    if event:
        return jsonify(event), 200

    # Fallback for accidental casing mismatches in links
    event = database.get_event(eid.upper())
    if event:
        return jsonify(event), 200

    return jsonify({"error": "Event not found"}), 404


# ============== FILE SCANNING ==============

@app.route('/api/scan/file', methods=['POST'])
def scan_file_endpoint():
    """Scan a file or directory for sensitive data"""
    data = request.json or {}
    path = data.get('path')

    if not path:
        return jsonify({"error": "Path is required"}), 400

    if not os.path.exists(path):
        return jsonify({"error": f"Path not found: {path}"}), 404

    try:
        results = quick_scan(path)

        # Store results in DB
        if database:
            for r in results:
                database.add_scan_result(
                    scan_type="manual_scan",
                    source=r.get('file_path', path),
                    findings=r.get('findings', []),
                    severity=r.get('severity', 'none'),
                    file_path=r.get('file_path'),
                    file_hash=r.get('file_hash'),
                    file_size=r.get('file_size'),
                )

        return jsonify({
            "status": "success",
            "files_scanned": len(results),
            "results": results
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/text', methods=['POST'])
def scan_text_endpoint():
    """Scan text content for sensitive data patterns"""
    data = request.json or {}
    text = data.get('text', '')

    if not text:
        return jsonify({"error": "Text is required"}), 400

    try:
        if not file_scanner:
            return jsonify({"error": "Scanner not initialized"}), 500

        findings = file_scanner.scan_text(text, "api_scan")

        return jsonify({
            "status": "success",
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings]
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/clipboard', methods=['POST'])
def scan_clipboard_endpoint():
    """Scan current clipboard content"""
    try:
        if not file_scanner:
            return jsonify({"error": "Scanner not initialized"}), 500

        findings = file_scanner.scan_clipboard()

        return jsonify({
            "status": "success",
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings]
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============== BROWSER EXTENSION ==============

@app.route('/api/scan/browser', methods=['POST'])
def scan_browser_upload():
    """Scan file content from browser extension before upload.
    This allows the extension to double-check with the server-side scanner."""
    data = request.json or {}
    text = data.get('content', '')
    file_name = data.get('file_name', 'unknown')
    file_size = data.get('file_size', 0)
    domain = data.get('domain', 'unknown')

    if not text:
        return jsonify({"error": "Content is required"}), 400

    try:
        if not file_scanner:
            return jsonify({"error": "Scanner not initialized"}), 500

        findings = file_scanner.scan_text(text, f"browser_upload:{file_name}")

        # Determine action based on severity
        severity = "none"
        if findings:
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            severity = max(findings, key=lambda f: severity_order.get(f.severity, 0)).severity

        action = "allow"
        if severity in ("critical",):
            action = "block"
        elif severity in ("high",):
            action = "warn"

        # Store in DB
        if database:
            database.add_scan_result(
                scan_type="browser_extension",
                source=f"{domain}/{file_name}",
                findings=[f.to_dict() for f in findings],
                severity=severity,
                file_path=file_name,
                file_size=file_size,
                user=data.get('user', 'browser_user'),
                host=domain,
            )

        return jsonify({
            "status": "success",
            "action": action,
            "severity": severity,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "file_name": file_name,
            "domain": domain,
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/browser-file', methods=['POST'])
def scan_browser_file_payload():
    """Deep scan file bytes from browser extension (base64 payload)."""
    data = request.json or {}
    b64 = data.get('file_content_base64')
    file_name = data.get('file_name', 'upload.bin')

    if not b64:
        return jsonify({"inspected": False, "findings": [], "error": "file_content_base64 is required"}), 400

    if not file_scanner:
        return jsonify({"inspected": False, "findings": [], "error": "Scanner not initialized"}), 500

    tmp_path = None
    try:
        raw = base64.b64decode(b64)
        suffix = ''
        if isinstance(file_name, str) and '.' in file_name:
            suffix = '.' + file_name.split('.')[-1].lower()

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tf:
            tf.write(raw)
            tmp_path = tf.name

        result = file_scanner.scan_file(tmp_path)
        if not result:
            return jsonify({"inspected": False, "findings": []}), 200

        findings = [f.to_dict() for f in (result.findings or [])]

        # Apply active SIEM regex policies on extracted text too (including OCR-extracted image text).
        # This ensures custom rules such as "kathan" work for browser deep scans.
        try:
            if database:
                suffix = ''
                if isinstance(file_name, str) and '.' in file_name:
                    suffix = '.' + file_name.split('.')[-1].lower()

                extracted_text = file_scanner._read_file(Path(tmp_path), suffix) if file_scanner else None
                if extracted_text:
                    policies = database.get_policies(active_only=True)
                    for p in policies:
                        if not isinstance(p, dict):
                            continue
                        if str(p.get('rule_type') or '').lower() != 'regex':
                            continue

                        raw_rule_data = p.get('rule_data')
                        rule_data = raw_rule_data if isinstance(raw_rule_data, dict) else {}
                        regex_str = p.get('regex') or rule_data.get('pattern')
                        if not regex_str:
                            continue

                        try:
                            compiled = re.compile(str(regex_str), re.IGNORECASE | re.MULTILINE)
                        except re.error:
                            continue

                        for m in compiled.finditer(extracted_text):
                            matched = (m.group(0) or '').strip()
                            if not matched:
                                continue

                            findings.append({
                                "pattern_name": str(p.get('name') or 'SIEM_REGEX'),
                                "matched_text": matched,
                                "line_number": 0,
                                "severity": str(p.get('severity') or 'high').lower(),
                                "confidence": 0.9,
                                "context": matched[:120],
                                "description": str(p.get('description') or p.get('name') or 'SIEM policy match'),
                                "category": "SIEM Policy",
                                "source": "siem_policy",
                            })

                    # De-duplicate merged findings.
                    uniq = {}
                    for f in findings:
                        key = (
                            str(f.get('pattern_name') or ''),
                            str(f.get('matched_text') or ''),
                            str(f.get('severity') or ''),
                        )
                        uniq[key] = f
                    findings = list(uniq.values())
        except Exception:
            pass

        # Recompute severity after merge.
        severity = str(getattr(result, 'severity', 'none') or 'none')
        if findings:
            order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
            severity = max(findings, key=lambda f: order.get(str(f.get('severity') or 'none').lower(), 0)).get('severity', severity)

        return jsonify({
            "inspected": True,
            "file_name": file_name,
            "severity": severity,
            "finding_count": len(findings),
            "findings": findings,
        }), 200
    except Exception as e:
        return jsonify({"inspected": False, "findings": [], "error": str(e)}), 200
    finally:
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


@app.route('/api/browser/stats', methods=['GET'])
def get_browser_stats():
    """Get browser extension scan statistics."""
    if not database:
        return jsonify({"total_scans": 0, "blocked": 0, "warned": 0, "clean": 0, "recent": []}), 200

    results = database.get_scan_results(scan_type="browser_extension", limit=100)
    total = len(results)
    blocked = sum(1 for r in results if r.get('severity') in ('critical',))
    warned = sum(1 for r in results if r.get('severity') in ('high',))

    return jsonify({
        "total_scans": total,
        "blocked": blocked,
        "warned": warned,
        "clean": total - blocked - warned,
        "recent": results[:10],
    }), 200


# ============== SCAN RESULTS ==============

@app.route('/api/scans', methods=['GET'])
def get_scan_results():
    """Get scan results from database"""
    scan_type = request.args.get('type')
    limit = request.args.get('limit', 50, type=int)

    if not database:
        return jsonify({"total": 0, "results": []}), 200

    results = database.get_scan_results(scan_type=scan_type, limit=limit)
    return jsonify({
        "total": len(results),
        "results": results
    }), 200


# ============== ANALYTICS ==============

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Get analytics data for charts"""
    if not database:
        return jsonify({
            "incidents_over_time": [],
            "severity_distribution": [],
            "top_patterns": [],
            "top_users": [],
            "events_by_agent": [],
            "events_hourly": [],
            "status_breakdown": [],
            "kpi": {},
            "throughput": {},
            "risky_users": [],
            "risky_hosts": [],
            "repeat_offenders": [],
            "events_by_channel": [],
            "assignee_workload": [],
            "closure_leaderboard": [],
            "generated_at": datetime.now().isoformat(),
        }), 200

    try:
        window = (request.args.get('window', '7d') or '7d').lower()
        if window == '24h':
            incident_window_sql = "-24 hours"
            incident_bucket = "strftime('%Y-%m-%d %H:00', created_at)"
            event_window_sql = "-24 hours"
            event_bucket = "strftime('%Y-%m-%d %H:00', timestamp)"
            prev_incident_window_sql = "-48 hours"
            prev_event_window_sql = "-48 hours"
            window_label = "24H"
        elif window == '30d':
            incident_window_sql = "-30 days"
            incident_bucket = "date(created_at)"
            event_window_sql = "-30 days"
            event_bucket = "date(timestamp)"
            prev_incident_window_sql = "-60 days"
            prev_event_window_sql = "-60 days"
            window_label = "30D"
        else:
            incident_window_sql = "-7 days"
            incident_bucket = "date(created_at)"
            event_window_sql = "-7 days"
            event_bucket = "date(timestamp)"
            prev_incident_window_sql = "-14 days"
            prev_event_window_sql = "-14 days"
            window_label = "7D"

        # type: ignore below silences static checkers about protected member _cursor
        with database._cursor() as cur:  # type: ignore[attr-defined]
            # Incidents over selected window (24h/7d/30d)
            cur.execute(f"""
                SELECT {incident_bucket} as day, COUNT(*) as count
                FROM incidents
                WHERE created_at >= datetime('now', ?)
                GROUP BY day
                ORDER BY day ASC
            """, (incident_window_sql,))
            incidents_over_time = [{"day": r["day"], "count": r["count"]} for r in cur.fetchall()]

            # Severity distribution
            cur.execute("""
                SELECT
                    CASE
                        WHEN risk >= 80 THEN 'CRITICAL'
                        WHEN risk >= 60 THEN 'HIGH'
                        WHEN risk >= 40 THEN 'MEDIUM'
                        ELSE 'LOW'
                    END as severity_level,
                    COUNT(*) as count
                FROM incidents
                WHERE created_at >= datetime('now', ?)
                GROUP BY severity_level
            """, (incident_window_sql,))
            severity_dist = [{"severity": r["severity_level"], "count": r["count"]} for r in cur.fetchall()]

            # Top triggered patterns
            cur.execute("""
                SELECT pattern, COUNT(*) as count
                FROM incidents
                WHERE created_at >= datetime('now', ?)
                GROUP BY pattern
                ORDER BY count DESC
                LIMIT 10
            """, (incident_window_sql,))
            top_patterns = [{"pattern": r["pattern"], "count": r["count"]} for r in cur.fetchall()]

            # Top users by incident count
            cur.execute("""
                SELECT user, COUNT(*) as count, AVG(risk) as avg_risk
                FROM incidents
                WHERE created_at >= datetime('now', ?)
                GROUP BY user
                ORDER BY count DESC
                LIMIT 10
            """, (incident_window_sql,))
            top_users = [{"user": r["user"], "count": r["count"], "avg_risk": round(r["avg_risk"] or 0)} for r in cur.fetchall()]

            # Events by agent type
            cur.execute("""
                SELECT agent_type, COUNT(*) as count
                FROM events
                WHERE timestamp >= datetime('now', ?)
                GROUP BY agent_type
                ORDER BY count DESC
            """, (event_window_sql,))
            events_by_agent = [{"agent": r["agent_type"], "count": r["count"]} for r in cur.fetchall()]

            # Events over selected window
            cur.execute(f"""
                SELECT {event_bucket} as bucket, COUNT(*) as count
                FROM events
                WHERE timestamp >= datetime('now', ?)
                GROUP BY bucket
                ORDER BY bucket ASC
            """, (event_window_sql,))
            events_hourly = []
            for r in cur.fetchall():
                raw_bucket = r["bucket"]
                label = str(raw_bucket)
                try:
                    if window == '24h':
                        dt = datetime.fromisoformat(str(raw_bucket).replace(' ', 'T'))
                        label = dt.strftime('%H:00')
                    else:
                        dt = datetime.fromisoformat(str(raw_bucket))
                        label = dt.strftime('%b %d')
                except Exception:
                    pass
                events_hourly.append({"bucket": raw_bucket, "label": label, "count": r["count"]})

            # Status breakdown
            cur.execute("""
                SELECT status, COUNT(*) as count
                FROM incidents
                WHERE created_at >= datetime('now', ?)
                GROUP BY status
            """, (incident_window_sql,))
            status_breakdown = [{"status": r["status"], "count": r["count"]} for r in cur.fetchall()]

            # Throughput KPIs
            cur.execute("SELECT COUNT(*) as c FROM incidents WHERE created_at >= datetime('now', ?)", (incident_window_sql,))
            incidents_window = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) as c FROM incidents WHERE created_at >= datetime('now', ?) AND created_at < datetime('now', ?)",
                (prev_incident_window_sql, incident_window_sql),
            )
            incidents_prev_window = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM events WHERE timestamp >= datetime('now', ?)", (event_window_sql,))
            events_window = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) as c FROM events WHERE timestamp >= datetime('now', ?) AND timestamp < datetime('now', ?)",
                (prev_event_window_sql, event_window_sql),
            )
            events_prev_window = cur.fetchone()["c"]

            # Core KPIs from incidents
            cur.execute("SELECT COUNT(*) as c FROM incidents")
            total_incidents = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM incidents WHERE status = 'OPEN'")
            open_incidents = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM incidents WHERE status = 'OPEN' AND risk >= 80")
            critical_open_incidents = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM incidents WHERE status = 'OPEN' AND created_at < datetime('now', '-24 hours')")
            stale_open_incidents = cur.fetchone()["c"]

            cur.execute("SELECT AVG(risk) as a, MAX(risk) as m FROM incidents")
            risk_row = cur.fetchone()
            avg_risk = round(risk_row["a"] or 0, 1)
            max_risk = int(risk_row["m"] or 0)

            cur.execute("SELECT risk FROM incidents ORDER BY risk ASC")
            risk_values = [int(r["risk"] or 0) for r in cur.fetchall()]
            if risk_values:
                idx = max(0, min(len(risk_values) - 1, int(round(0.95 * (len(risk_values) - 1)))))
                p95_risk = int(risk_values[idx])
            else:
                p95_risk = 0

            cur.execute("SELECT AVG(fp) as a FROM incidents")
            avg_fp = round((cur.fetchone()["a"] or 0), 1)

            cur.execute("SELECT COUNT(*) as c FROM incidents WHERE status IN ('CLOSED', 'AUTO-CLOSED', 'TICKET_RAISED')")
            contained = cur.fetchone()["c"]
            containment_rate = round((contained / total_incidents) * 100, 2) if total_incidents else 0
            open_rate = round((open_incidents / total_incidents) * 100, 2) if total_incidents else 0

            # MTTR: average minutes from create to update for closed/ticket incidents
            cur.execute("""
                SELECT created_at, updated_at
                FROM incidents
                WHERE status IN ('CLOSED', 'AUTO-CLOSED', 'TICKET_RAISED')
            """)
            durations = []
            for row in cur.fetchall():
                try:
                    cts = datetime.fromisoformat(str(row["created_at"]))
                    uts = datetime.fromisoformat(str(row["updated_at"]))
                    durations.append((uts - cts).total_seconds() / 60)
                except Exception:
                    continue
            mttr_minutes = round(sum(durations) / len(durations), 1) if durations else 0

            # Risky users / hosts
            cur.execute("""
                SELECT user, ROUND(AVG(risk), 2) as avg_risk,
                       SUM(CASE WHEN status='OPEN' THEN 1 ELSE 0 END) as open_count
                FROM incidents
                WHERE created_at >= datetime('now', ?)
                GROUP BY user
                ORDER BY avg_risk DESC
                LIMIT 10
            """, (incident_window_sql,))
            risky_users = [{"user": r["user"], "avg_risk": float(r["avg_risk"] or 0), "open_count": int(r["open_count"] or 0)} for r in cur.fetchall()]

            cur.execute("""
                SELECT host, ROUND(AVG(risk), 2) as avg_risk,
                       SUM(CASE WHEN status='OPEN' THEN 1 ELSE 0 END) as open_count
                FROM incidents
                WHERE created_at >= datetime('now', ?)
                GROUP BY host
                ORDER BY avg_risk DESC
                LIMIT 10
            """, (incident_window_sql,))
            risky_hosts = [{"host": r["host"], "avg_risk": float(r["avg_risk"] or 0), "open_count": int(r["open_count"] or 0)} for r in cur.fetchall()]

            cur.execute("""
                SELECT user, COUNT(*) as count
                FROM incidents
                WHERE created_at >= datetime('now', ?)
                GROUP BY user
                HAVING COUNT(*) >= 3
                ORDER BY count DESC
                LIMIT 10
            """, (incident_window_sql,))
            repeat_offenders = [{"user": r["user"], "count": int(r["count"] or 0)} for r in cur.fetchall()]

            cur.execute("""
                SELECT channel, COUNT(*) as count
                FROM events
                WHERE timestamp >= datetime('now', ?)
                GROUP BY channel
                ORDER BY count DESC
                LIMIT 10
            """, (event_window_sql,))
            events_by_channel = [{"channel": r["channel"], "count": int(r["count"] or 0)} for r in cur.fetchall()]

            # Analyst workload & closure performance
            cur.execute("""
                SELECT
                    COALESCE(NULLIF(TRIM(assigned_to), ''), 'UNASSIGNED') as assignee,
                    COUNT(*) as total_assigned,
                    SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) as open_count,
                    SUM(CASE WHEN status = 'ESCALATED' THEN 1 ELSE 0 END) as escalated_count,
                    SUM(CASE WHEN status IN ('CLOSED', 'AUTO-CLOSED', 'TICKET_RAISED') THEN 1 ELSE 0 END) as resolved_count
                FROM incidents
                WHERE assigned_at IS NOT NULL
                  AND assigned_at >= datetime('now', ?)
                GROUP BY assignee
                ORDER BY total_assigned DESC
                LIMIT 15
            """, (incident_window_sql,))
            assignee_workload = [
                {
                    "assignee": r["assignee"],
                    "total_assigned": int(r["total_assigned"] or 0),
                    "open_count": int(r["open_count"] or 0),
                    "escalated_count": int(r["escalated_count"] or 0),
                    "resolved_count": int(r["resolved_count"] or 0),
                }
                for r in cur.fetchall()
            ]

            cur.execute("""
                SELECT
                    COALESCE(NULLIF(TRIM(closed_by), ''), 'UNKNOWN') as analyst,
                    COUNT(*) as closed_count,
                    AVG((julianday(closed_at) - julianday(created_at)) * 1440.0) as avg_resolution_minutes
                FROM incidents
                WHERE closed_at IS NOT NULL
                  AND closed_at >= datetime('now', ?)
                GROUP BY analyst
                ORDER BY closed_count DESC
                LIMIT 15
            """, (incident_window_sql,))
            closure_leaderboard = [
                {
                    "analyst": r["analyst"],
                    "closed_count": int(r["closed_count"] or 0),
                    "avg_resolution_minutes": round(float(r["avg_resolution_minutes"] or 0), 1),
                }
                for r in cur.fetchall()
            ]

            cur.execute("""
                SELECT COUNT(*) as c
                FROM incidents
                WHERE assigned_at IS NOT NULL
                  AND assigned_at >= datetime('now', ?)
            """, (incident_window_sql,))
            assignments_in_window = int(cur.fetchone()["c"] or 0)

            throughput = {
                "window": window,
                "window_label": window_label,
                "incidents_window": incidents_window,
                "incidents_prev_window": incidents_prev_window,
                "events_window": events_window,
                "events_prev_window": events_prev_window,
                "incident_to_event_ratio_window": round((incidents_window / events_window), 4) if events_window else 0,
                "assignments_window": assignments_in_window,
                # Backward-compatible keys
                "incidents_24h": incidents_window,
                "incidents_prev_24h": incidents_prev_window,
                "events_24h": events_window,
                "events_prev_24h": events_prev_window,
                "incident_to_event_ratio_24h": round((incidents_window / events_window), 4) if events_window else 0,
            }

            kpi = {
                "open_incidents": open_incidents,
                "critical_open_incidents": critical_open_incidents,
                "stale_open_incidents": stale_open_incidents,
                "open_rate": open_rate,
                "mttr_minutes": mttr_minutes,
                "p95_risk": p95_risk,
                "avg_risk": avg_risk,
                "max_risk": max_risk,
                "containment_rate": containment_rate,
                "avg_fp": avg_fp,
            }

        return jsonify({
            "incidents_over_time": incidents_over_time,
            "severity_distribution": severity_dist,
            "top_patterns": top_patterns,
            "top_users": top_users,
            "events_by_agent": events_by_agent,
            "events_hourly": events_hourly,
            "status_breakdown": status_breakdown,
            "risky_users": risky_users,
            "risky_hosts": risky_hosts,
            "repeat_offenders": repeat_offenders,
            "events_by_channel": events_by_channel,
            "assignee_workload": assignee_workload,
            "closure_leaderboard": closure_leaderboard,
            "throughput": throughput,
            "kpi": kpi,
            "generated_at": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============== DEBUG: ANALYTICS DATA INSPECTION ==============

@app.route('/api/debug/incidents-status', methods=['GET'])
def debug_incidents_status():
    """Debug endpoint: Show incident data state for troubleshooting analytics."""
    if not database:
        return jsonify({"error": "Database not initialized"}), 500

    try:
        with database._cursor() as cur:
            # Check schema columns
            cur.execute("PRAGMA table_info(incidents)")
            columns = {col[1]: col for col in cur.fetchall()}

            # Show recent incidents with critical fields
            cur.execute("""
                SELECT
                    incident_id,
                    user,
                    assigned_to,
                    assigned_at,
                    status,
                    closed_by,
                    closed_at,
                    created_at,
                    updated_at
                FROM incidents
                ORDER BY created_at DESC
                LIMIT 20
            """)
            incidents_data = [dict(row) for row in cur.fetchall()]

            # Count incidents by status
            cur.execute("""
                SELECT status, COUNT(*) as count FROM incidents GROUP BY status
            """)
            status_counts = {row['status']: row['count'] for row in cur.fetchall()}

            # Count with assigned_at set
            cur.execute("SELECT COUNT(*) as c FROM incidents WHERE assigned_at IS NOT NULL")
            assigned_count = cur.fetchone()['c']

            # Count with closed_by set
            cur.execute("SELECT COUNT(*) as c FROM incidents WHERE closed_by IS NOT NULL")
            closed_count = cur.fetchone()['c']

            return jsonify({
                "schema_has_assigned_at": "assigned_at" in columns,
                "schema_has_closed_by": "closed_by" in columns,
                "schema_has_closed_at": "closed_at" in columns,
                "total_incidents": len(incidents_data),
                "incidents_with_assigned_at": assigned_count,
                "incidents_with_closed_by": closed_count,
                "status_breakdown": status_counts,
                "recent_incidents": incidents_data[:5],
            }), 200
    except Exception as e:
        return jsonify({"error": str(e), "type": type(e).__name__}), 500


# ============== FLEET TRACKING ==============

# In-memory fleet registry (survives until server restart)
fleet_registry = {}
# In-memory command queue per agent (consumed on check-in)
fleet_command_queue: dict[str, list[dict]] = {}

@app.route('/api/fleet/checkin', methods=['POST'])
def fleet_checkin():
    """Agent check-in endpoint — agents call this periodically"""
    data = request.json or {}
    agent_id = data.get('agent_id', request.remote_addr)
    agent_type = data.get('agent_type', 'unknown')
    hostname = data.get('hostname', 'unknown')
    os_info = data.get('os', 'unknown')
    version = data.get('version', '1.0')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user = data.get('user', 'unknown')

    fleet_registry[agent_id] = {
        "agent_id": agent_id,
        "agent_type": agent_type,
        "hostname": hostname,
        "os": os_info,
        "version": version,
        "ip": ip,
        "user": user,
        "last_seen": datetime.now().isoformat(),
        "status": "online",
        "scans_reported": data.get('scans_reported', 0),
        "incidents_reported": data.get('incidents_reported', 0),
        "meta": data.get('meta', {}) if isinstance(data.get('meta'), dict) else {},
    }

    queued = fleet_command_queue.get(agent_id) or []
    command = queued.pop(0) if queued else None
    if queued:
        fleet_command_queue[agent_id] = queued
    else:
        fleet_command_queue.pop(agent_id, None)

    return jsonify({
        "status": "ok",
        "server_time": datetime.now().isoformat(),
        "command": command,
    }), 200


@app.route('/api/fleet/status', methods=['GET'])
def fleet_status():
    """Get all fleet agent statuses"""
    now = datetime.now()
    agents = []
    for agent_id, info in fleet_registry.items():
        last_seen = datetime.fromisoformat(info["last_seen"])
        delta = (now - last_seen).total_seconds()
        status = "online" if delta < 120 else "idle" if delta < 600 else "offline"
        agents.append({**info, "status": status, "last_seen_ago": int(delta)})

    # Sort: online first, then by last_seen
    agents.sort(key=lambda a: (0 if a["status"] == "online" else 1 if a["status"] == "idle" else 2, a["last_seen_ago"]))

    return jsonify({
        "total": len(agents),
        "online": sum(1 for a in agents if a["status"] == "online"),
        "idle": sum(1 for a in agents if a["status"] == "idle"),
        "offline": sum(1 for a in agents if a["status"] == "offline"),
        "agents": agents,
    }), 200


@app.route('/api/fleet/agents/<agent_id>/logs', methods=['GET'])
def fleet_agent_logs(agent_id):
    """Get scan/event/incident timeline for a specific agent."""
    if not database:
        return jsonify({"logs": [], "events": [], "incidents": []}), 200

    info = fleet_registry.get(agent_id, {})
    hostname = info.get('hostname')
    user = info.get('user')
    agent_type = info.get('agent_type')
    limit = request.args.get('limit', 200, type=int)

    logs = database.get_agent_scan_history(hostname or agent_id, limit=limit, agent_id=agent_id, user=user)
    events = database.get_events_for_agent(agent_id=agent_id, hostname=hostname, user=user, agent_type=agent_type, limit=limit)
    incidents = database.get_incidents_for_host(hostname, limit=100) if hostname else []

    return jsonify({"logs": logs, "events": events, "incidents": incidents}), 200


@app.route('/api/fleet/agents/<agent_id>/downloads', methods=['GET'])
def fleet_agent_downloads(agent_id):
    """Get download/file scan history for a specific agent."""
    if not database:
        return jsonify({"downloads": []}), 200

    info = fleet_registry.get(agent_id, {})
    hostname = info.get('hostname')
    user = info.get('user')
    limit = request.args.get('limit', 200, type=int)
    downloads = database.get_agent_downloads(hostname or agent_id, limit=limit, agent_id=agent_id, user=user)

    return jsonify({"downloads": downloads}), 200


@app.route('/api/fleet/agents/<agent_id>/operational', methods=['GET'])
def fleet_agent_operational(agent_id):
    """Get operational logs for an agent."""
    if not database:
        return jsonify({"logs": []}), 200
    limit = request.args.get('limit', 200, type=int)
    logs = database.get_operational_logs(agent_id, limit=limit)
    return jsonify({"logs": logs}), 200


@app.route('/api/fleet/agents/<agent_id>/operational', methods=['POST'])
def fleet_add_operational(agent_id):
    """Store operational log entry from extension/agent."""
    if not database:
        return jsonify({"error": "Database not configured"}), 500

    data = request.json or {}
    event_type = data.get('event_type', 'event')
    message = data.get('message', '')
    details = data.get('details', {}) if isinstance(data.get('details'), dict) else {}
    database.add_operational_log(agent_id, event_type, message, details)
    return jsonify({"status": "ok"}), 200


@app.route('/api/fleet/agents/<agent_id>/policy', methods=['GET'])
def fleet_agent_policy_get(agent_id):
    """Get managed policy knobs for an agent (in-memory)."""
    meta = (fleet_registry.get(agent_id) or {}).get('meta', {})
    managed = meta.get('managed_settings', {}) if isinstance(meta, dict) else {}
    managed = _normalize_managed_extension_settings(managed)
    return jsonify({
        "agent_id": agent_id,
        "managed_settings": managed
    }), 200


@app.route('/api/fleet/agents/<agent_id>/policy', methods=['POST'])
def fleet_agent_policy_set(agent_id):
    """Set managed policy knobs for an agent (in-memory)."""
    data = request.json or {}
    incoming = data.get('managed_settings', {}) if isinstance(data.get('managed_settings'), dict) else {}

    existing = fleet_registry.get(agent_id, {
        "agent_id": agent_id,
        "agent_type": "browser_extension",
        "hostname": agent_id,
        "os": "unknown",
        "version": "1.0",
        "ip": request.remote_addr,
        "user": "unknown",
        "last_seen": datetime.now().isoformat(),
        "status": "online",
        "scans_reported": 0,
        "incidents_reported": 0,
        "meta": {},
    })

    meta = existing.get('meta', {}) if isinstance(existing.get('meta'), dict) else {}
    managed = meta.get('managed_settings', {}) if isinstance(meta.get('managed_settings'), dict) else {}
    merged = dict(managed)
    merged.update(incoming)
    managed = _normalize_managed_extension_settings(merged)
    meta['managed_settings'] = managed
    existing['meta'] = meta
    fleet_registry[agent_id] = existing

    return jsonify({"status": "ok", "agent_id": agent_id, "managed_settings": managed}), 200


@app.route('/api/fleet/agents/<agent_id>/upgrade', methods=['POST'])
def fleet_agent_upgrade(agent_id):
    """Queue an upgrade command for an agent; delivered on next check-in."""
    data = request.json or {}
    download_url = str(data.get('download_url') or '').strip()
    install_command = str(data.get('install_command') or '').strip()
    target_version = str(data.get('target_version') or '').strip() or 'latest'
    actor = str(data.get('actor') or 'secops_analyst').strip()

    if not download_url and not install_command:
        return jsonify({"error": "Provide either download_url or install_command"}), 400

    command = {
        "command_id": f"CMD-{uuid.uuid4().hex[:10].upper()}",
        "type": "upgrade",
        "download_url": download_url or None,
        "install_command": install_command or None,
        "target_version": target_version,
        "requested_by": actor,
        "created_at": datetime.now().isoformat(),
    }

    queue = fleet_command_queue.get(agent_id) or []
    queue.append(command)
    # Keep only latest 20 queued commands per agent
    fleet_command_queue[agent_id] = queue[-20:]

    if database:
        try:
            database.add_operational_log(
                agent_id,
                'upgrade_queued',
                f"Upgrade queued by {actor} for target version {target_version}",
                {
                    "command_id": command["command_id"],
                    "download_url": bool(download_url),
                    "install_command": bool(install_command),
                    "target_version": target_version,
                }
            )
        except Exception:
            pass

    return jsonify({
        "status": "queued",
        "agent_id": agent_id,
        "command": command,
        "queue_depth": len(fleet_command_queue.get(agent_id) or []),
    }), 200


@app.route('/api/incidents/<incident_id>/artifacts', methods=['GET'])
def incident_artifacts(incident_id):
    """Get artifacts associated with this incident only."""
    if not database:
        return jsonify({"artifacts": []}), 200

    inc = database.get_incident(incident_id)
    if not inc:
        return jsonify({"artifacts": []}), 200

    user = str(inc.get('user') or '')
    raw_event_ids = inc.get('events')
    event_ids = raw_event_ids if isinstance(raw_event_ids, list) else []

    linked_artifact_ids: set[str] = set()
    linked_scan_ids: set[str] = set()
    linked_hashes: set[str] = set()
    linked_hosts: set[str] = set()
    linked_file_names: set[str] = set()

    for event_id in event_ids:
        evt = database.get_event(str(event_id))
        if not evt:
            continue

        linked_hosts.add(_normalize_host(evt.get('source_host')))
        raw_geo = evt.get('geo')
        geo = raw_geo if isinstance(raw_geo, dict) else {}

        aid = geo.get('artifact_id')
        sid = geo.get('scan_id')
        hsh = geo.get('content_sha256')
        domain = geo.get('domain')

        if aid:
            linked_artifact_ids.add(str(aid))
        if sid:
            linked_scan_ids.add(str(sid))
        if hsh:
            linked_hashes.add(str(hsh))
        if domain:
            linked_hosts.add(_normalize_host(domain))

        payload_sample = str(evt.get('payload_sample') or '')
        for line in payload_sample.split('\n'):
            if line.startswith('File: '):
                fname = line.replace('File: ', '').strip()
                if fname:
                    linked_file_names.add(fname)
                break

    artifacts = database.get_agent_upload_artifacts(limit=3000)

    # Primary strict linkage by explicit IDs/hashes.
    strict_matches = [
        a for a in artifacts
        if (
            (str(a.get('artifact_id') or '') in linked_artifact_ids)
            or (str(a.get('scan_id') or '') in linked_scan_ids)
            or (str(a.get('content_sha256') or '') in linked_hashes)
        )
    ]

    # Fallback for old records lacking IDs: same user + linked host + tight time window around incident.
    if strict_matches:
        filtered = strict_matches
    else:
        def _parse_dt(v: object | None):
            s = str(v or '').strip()
            if not s:
                return None
            try:
                return datetime.fromisoformat(s.replace('Z', '+00:00'))
            except Exception:
                return None

        incident_dt = _parse_dt(inc.get('created_at'))
        candidates = []
        for a in artifacts:
            if user and str(a.get('user') or '') != user:
                continue

            a_host = _normalize_host(a.get('source_host') or a.get('hostname'))
            if linked_hosts and a_host not in linked_hosts:
                continue

            if linked_file_names:
                a_file_name = str(a.get('file_name') or '')
                if a_file_name not in linked_file_names:
                    continue

            candidates.append(a)

        # Keep only nearest candidates to this incident when strict IDs are unavailable.
        if incident_dt:
            candidates.sort(
                key=lambda a: abs(((_parse_dt(a.get('created_at')) or incident_dt) - incident_dt).total_seconds())
            )

        max_fallback = max(1, len(event_ids))
        filtered = candidates[:max_fallback]

    # De-duplicate while preserving order.
    seen = set()
    out = []
    for a in filtered:
        aid = str(a.get('artifact_id') or '')
        if not aid or aid in seen:
            continue
        seen.add(aid)
        out.append(a)

    # Clipboard incidents usually have no uploaded file artifact; synthesize evidence from linked events.
    if not out and event_ids:
        virtual = []
        for event_id in event_ids:
            evt = database.get_event(str(event_id))
            if not evt:
                continue

            raw_geo = evt.get('geo')
            geo = raw_geo if isinstance(raw_geo, dict) else {}
            event_kind = str(geo.get('event_kind') or '').lower()
            payload_sample = str(evt.get('payload_sample') or '')

            is_clipboard = (
                event_kind == 'clipboard_paste_scan'
                or 'file: pasted_text' in payload_sample.lower()
                or str(evt.get('channel') or '').lower().find('clipboard') >= 0
            )
            if not is_clipboard:
                continue

            findings = []
            geo_findings = geo.get('findings')
            if isinstance(geo_findings, list):
                for f in geo_findings:
                    if not isinstance(f, dict):
                        continue
                    matched = str(f.get('matched_text') or '').strip()
                    if not matched:
                        continue
                    findings.append({
                        'pattern_name': str(f.get('pattern_name') or f.get('description') or f.get('category') or 'match'),
                        'matched_text': matched,
                        'severity': str(f.get('severity') or evt.get('severity') or 'high'),
                        'category': str(f.get('category') or 'clipboard'),
                    })

            # Fallback parse payload sample lines like: [PATTERN] matched_text
            if not findings:
                for line in payload_sample.split('\n'):
                    m = re.match(r'^\[([^\]]+)\]\s*(.+)$', line.strip())
                    if not m:
                        continue
                    findings.append({
                        'pattern_name': m.group(1).strip(),
                        'matched_text': m.group(2).strip(),
                        'severity': str(evt.get('severity') or 'high'),
                        'category': 'clipboard',
                    })

            if not findings:
                continue

            virtual.append({
                'artifact_id': f"VIRT-{event_id}",
                'is_virtual': True,
                'source': 'clipboard',
                'file_name': 'clipboard_paste.txt',
                'file_type': 'text/plain',
                'file_size': int(geo.get('file_size') or 0),
                'action': str(geo.get('action') or 'block'),
                'severity': str(evt.get('severity') or geo.get('severity') or 'high'),
                'created_at': evt.get('timestamp') or evt.get('created_at') or inc.get('created_at'),
                'findings': findings[:50],
                'match_reason': 'clipboard_event',
            })

        if virtual:
            out = virtual

    return jsonify({"artifacts": out[:100]}), 200


@app.route('/api/incidents/<incident_id>/user-analytics', methods=['GET'])
def incident_user_analytics(incident_id):
    """Return lightweight user analytics for incident detail page."""
    if not database:
        return jsonify({
            "summary": {}, "frequent_patterns": [], "severity_distribution": [],
            "daily_incidents": [], "channel_distribution": [], "hourly_activity": [],
            "recent_incidents": [], "same_pattern_history": []
        }), 200

    inc = database.get_incident(incident_id)
    if not inc:
        return jsonify({
            "summary": {}, "frequent_patterns": [], "severity_distribution": [],
            "daily_incidents": [], "channel_distribution": [], "hourly_activity": [],
            "recent_incidents": [], "same_pattern_history": []
        }), 200

    user = inc.get('user')
    host = inc.get('host')
    pattern = inc.get('pattern')
    incidents = database.get_all_incidents(limit=1000)
    related = [r for r in incidents if (user and r.get('user') == user) or (host and r.get('host') == host)]
    same_pattern = [r for r in related if pattern and r.get('pattern') == pattern]
    events = database.get_events_for_agent(hostname=host, user=user, limit=1000)

    def tally(items, key_fn):
        out = {}
        for i in items:
            k = key_fn(i)
            out[k] = out.get(k, 0) + 1
        return out

    pat = tally(related, lambda r: str(r.get('pattern') or 'unknown'))
    sev = tally(related, lambda r: str(r.get('verdict') or 'NEEDS_REVIEW'))
    chn = tally(related, lambda r: str(r.get('channel') or 'unknown'))
    hrs = tally(events, lambda e: (str(e.get('timestamp') or e.get('created_at') or '')[11:13] or '00'))
    days = tally(related, lambda r: (str(r.get('created_at') or '')[:10] or 'unknown'))

    created_vals = [str(r.get('created_at')) for r in related if r.get('created_at')]
    summary = {
        "total_related_incidents": len(related),
        "open_incidents": sum(1 for r in related if r.get('status') == 'OPEN'),
        "escalated_incidents": sum(1 for r in related if r.get('status') == 'ESCALATED'),
        "same_pattern_incidents": len(same_pattern),
        "same_host_incidents": sum(1 for r in related if host and r.get('host') == host),
        "event_count": len(events),
        "first_seen": min(created_vals) if created_vals else None,
        "last_seen": max(created_vals) if created_vals else None,
    }

    return jsonify({
        "summary": summary,
        "frequent_patterns": [{"pattern": k, "count": v} for k, v in sorted(pat.items(), key=lambda x: x[1], reverse=True)],
        "severity_distribution": [{"severity": k, "count": v} for k, v in sorted(sev.items(), key=lambda x: x[1], reverse=True)],
        "daily_incidents": [{"day": k, "count": v} for k, v in sorted(days.items())],
        "channel_distribution": [{"channel": k, "count": v} for k, v in sorted(chn.items(), key=lambda x: x[1], reverse=True)],
        "hourly_activity": [{"hour": k, "count": v} for k, v in sorted(hrs.items())],
        "recent_incidents": related[:20],
        "same_pattern_history": same_pattern[:20],
    }), 200


@app.route('/api/fleet/artifacts/<artifact_id>/content', methods=['GET'])
def fleet_artifact_content(artifact_id):
    """Get artifact content for incident evidence view."""
    if not database:
        return jsonify({"error": "Database not configured"}), 500

    art = database.get_upload_artifact(artifact_id)
    if not art:
        return jsonify({"error": "Artifact not found"}), 404

    content_path = art.get('content_path')
    if not content_path or not os.path.exists(content_path):
        return jsonify({"error": "Artifact file missing"}), 404

    try:
        with open(content_path, 'rb') as fh:
            raw = fh.read()
        try:
            return jsonify({"artifact_id": artifact_id, "content_type": "text", "content": raw.decode('utf-8')}), 200
        except Exception:
            return jsonify({"artifact_id": artifact_id, "content_type": "base64", "content_base64": base64.b64encode(raw).decode('utf-8')}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/fleet/artifacts/<artifact_id>/download', methods=['GET'])
def fleet_artifact_download(artifact_id):
    """Download raw artifact file for incident evidence."""
    if not database:
        return jsonify({"error": "Database not configured"}), 500

    art = database.get_upload_artifact(artifact_id)
    if not art:
        return jsonify({"error": "Artifact not found"}), 404

    content_path = art.get('content_path')
    if not content_path or not os.path.exists(content_path):
        return jsonify({"error": "Artifact file missing"}), 404

    try:
        return send_file(
            content_path,
            as_attachment=True,
            download_name=art.get('file_name') or f"{artifact_id}.bin",
            mimetype=art.get('file_type') or 'application/octet-stream'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/fleet/artifacts/<artifact_id>/view', methods=['GET'])
def fleet_artifact_view(artifact_id):
    """View artifact inline in browser when possible."""
    if not database:
        return jsonify({"error": "Database not configured"}), 500

    art = database.get_upload_artifact(artifact_id)
    if not art:
        return jsonify({"error": "Artifact not found"}), 404

    content_path = art.get('content_path')
    if not content_path or not os.path.exists(content_path):
        return jsonify({"error": "Artifact file missing"}), 404

    try:
        return send_file(
            content_path,
            as_attachment=False,
            download_name=art.get('file_name') or f"{artifact_id}.bin",
            mimetype=art.get('file_type') or 'application/octet-stream'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/report', methods=['POST'])
def ingest_scan_report():
    """Ingest extension scan reports into scan_results table."""
    if not database:
        return jsonify({"error": "Database not configured"}), 500

    data = request.json or {}
    try:
        database.add_scan_result(
            scan_type=data.get('scan_type', 'web_upload'),
            source=data.get('source', data.get('file_path', 'unknown')),
            findings=data.get('findings', []),
            severity=data.get('severity', 'none'),
            file_path=data.get('file_path'),
            file_hash=data.get('file_hash'),
            file_size=data.get('file_size'),
            user=data.get('user'),
            host=data.get('host'),
            agent_id=data.get('agent_id'),
        )
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/browser/artifact', methods=['POST'])
def upload_browser_artifact_json():
    """Upload flagged artifact via JSON base64 payload."""
    if not database:
        return jsonify({"error": "Database not configured"}), 500

    data = request.json or {}
    content_b64 = data.get('content_base64')
    if not content_b64:
        return jsonify({"error": "content_base64 is required"}), 400

    try:
        raw = base64.b64decode(content_b64)
        artifact_id = f"ART-{uuid.uuid4().hex[:10].upper()}"
        user_value = data.get('user', 'browser_user')
        file_name = data.get('file_name', 'upload.bin')
        ext = os.path.splitext(file_name)[1] or '.bin'
        artifacts_dir = os.path.join(os.getcwd(), 'data', 'artifacts', 'by_user', _safe_user_folder(user_value))
        os.makedirs(artifacts_dir, exist_ok=True)
        content_path = os.path.join(artifacts_dir, f"{artifact_id}{ext}")

        source_host = data.get('source_host', '')
        hostname = data.get('hostname', '') or source_host
        with open(content_path, 'wb') as fh:
            fh.write(raw)

        sha = hashlib.sha256(raw).hexdigest()
        database.add_upload_artifact(
            artifact_id=artifact_id,
            agent_id=data.get('agent_id', ''),
            scan_id=data.get('scan_id', ''),
            hostname=hostname,
            user=user_value,
            source_host=source_host,
            file_name=file_name,
            file_type=data.get('file_type', 'application/octet-stream'),
            file_size=int(data.get('file_size') or len(raw)),
            action=data.get('action', 'block'),
            severity=data.get('severity', 'high'),
            findings=data.get('findings', []),
            content_path=content_path,
            content_sha256=sha,
        )
        return jsonify({"status": "stored", "artifact_id": artifact_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/browser/artifact/raw', methods=['POST'])
def upload_browser_artifact_raw():
    """Upload flagged artifact via multipart file payload."""
    if not database:
        return jsonify({"error": "Database not configured"}), 500

    file = request.files.get('file')
    if not file:
        return jsonify({"error": "file is required"}), 400

    try:
        raw = file.read()
        artifact_id = f"ART-{uuid.uuid4().hex[:10].upper()}"

        user_value = request.form.get('user', 'browser_user')
        file_name = request.form.get('file_name', file.filename or 'upload.bin')
        ext = os.path.splitext(file_name)[1] or '.bin'
        artifacts_dir = os.path.join(os.getcwd(), 'data', 'artifacts', 'by_user', _safe_user_folder(user_value))
        os.makedirs(artifacts_dir, exist_ok=True)
        content_path = os.path.join(artifacts_dir, f"{artifact_id}{ext}")

        source_host = request.form.get('source_host', '')
        hostname = request.form.get('hostname', '') or source_host
        with open(content_path, 'wb') as fh:
            fh.write(raw)

        sha = hashlib.sha256(raw).hexdigest()
        findings_raw = request.form.get('findings', '[]')
        try:
            findings = json.loads(findings_raw)
        except Exception:
            findings = []

        database.add_upload_artifact(
            artifact_id=artifact_id,
            agent_id=request.form.get('agent_id', ''),
            scan_id=request.form.get('scan_id', ''),
            hostname=hostname,
            user=user_value,
            source_host=source_host,
            file_name=file_name,
            file_type=request.form.get('file_type', file.mimetype or 'application/octet-stream'),
            file_size=int(request.form.get('file_size') or len(raw)),
            action=request.form.get('action', 'block'),
            severity=request.form.get('severity', 'high'),
            findings=findings,
            content_path=content_path,
            content_sha256=sha,
        )
        return jsonify({"status": "stored", "artifact_id": artifact_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============== SCREENSHOTS ==============

screenshots_store = []  # In-memory for simplicity (last 100)

@app.route('/api/screenshots', methods=['POST'])
def upload_screenshot():
    """Receive a screenshot from the browser extension"""
    data = request.json or {}
    entry = {
        "id": f"SS-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": datetime.now().isoformat(),
        "domain": data.get("domain", "unknown"),
        "user": data.get("user", "browser_user"),
        "incident_type": data.get("incident_type", "violation"),
        "severity": data.get("severity", "medium"),
        "image_data": data.get("image_data", ""),  # base64
        "url": data.get("url", ""),
        "findings_summary": data.get("findings_summary", ""),
    }
    screenshots_store.insert(0, entry)
    if len(screenshots_store) > 100:
        screenshots_store[:] = screenshots_store[:100]

    return jsonify({"status": "stored", "id": entry["id"]}), 200


@app.route('/api/screenshots', methods=['GET'])
def get_screenshots():
    """Get recent screenshots (without image data for list view)"""
    limit = request.args.get('limit', 20, type=int)
    results = []
    for ss in screenshots_store[:limit]:
        results.append({k: v for k, v in ss.items() if k != "image_data"})
    return jsonify({"screenshots": results}), 200


@app.route('/api/screenshots/<ss_id>', methods=['GET'])
def get_screenshot(ss_id):
    """Get a specific screenshot with full image data"""
    for ss in screenshots_store:
        if ss["id"] == ss_id:
            return jsonify(ss), 200
    return jsonify({"error": "Screenshot not found"}), 404


# ============== REAL-TIME SSE STREAM ==============

notification_queues = []

@app.route('/api/stream', methods=['GET'])
def event_stream():
    """Server-Sent Events stream for real-time notifications"""
    def generate():
        q = queue.Queue()
        notification_queues.append(q)
        try:
            # Send initial connection event
            yield f"data: {json.dumps({'type': 'connected', 'message': 'SIEM stream connected'})}\n\n"
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield f"data: {json.dumps(msg)}\n\n"
                except queue.Empty:
                    # Send heartbeat to keep connection alive
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        except GeneratorExit:
            notification_queues.remove(q)

    return app.response_class(
        response=generate(),  # type: ignore
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


def broadcast_notification(notification):
    """Push a notification to all connected SSE clients"""
    for q in notification_queues[:]:
        try:
            q.put_nowait(notification)
        except Exception:
            pass


# ============== POLICIES ==============

@app.route('/api/policies', methods=['GET'])
def get_policies():
    """Get all policies"""
    if not database:
        return jsonify({"policies": []}), 200
        
    active_only = request.args.get('active_only', 'false').lower() == 'true'
    policies = database.get_policies(active_only=active_only)
    return jsonify({"policies": policies}), 200

@app.route('/api/policies/sync', methods=['GET'])
def sync_policies():
    """Endpoint for agents/extensions to sync active patterns"""
    if not database:
        return jsonify({"patterns": [], "managed_settings": _normalize_managed_extension_settings({})}), 200
        
    policies = database.get_policies(active_only=True)
    exceptions = database.get_exceptions(active_only=True)
    global_exception_sets = [_exception_to_rule_set(e) for e in exceptions if str(e.get('scope_type') or '').lower() == 'global']
    policy_exception_sets: dict[str, list[dict]] = {}
    for e in exceptions:
        if str(e.get('scope_type') or '').lower() != 'policy':
            continue
        pids = _to_clean_list(e.get('policy_ids'))
        if not pids:
            pid = str(e.get('policy_id') or '').strip()
            pids = [pid] if pid else []
        if not pids:
            continue
        normalized_set = _exception_to_rule_set(e)
        for pid in pids:
            policy_exception_sets.setdefault(pid, []).append(normalized_set)
    
    # Format for agents to consume easily (backward + new schema)
    patterns = []
    for p in policies:
        rule_data = p.get("rule_data") or {}
        if not isinstance(rule_data, dict):
            rule_data = {}
        regex_value = p.get("regex_pattern") or p.get("regex") or rule_data.get("pattern") or ""
        policy_id = p.get('policy_id')
        scoped_sets = list(global_exception_sets)
        if policy_id and policy_id in policy_exception_sets:
            scoped_sets.extend(policy_exception_sets[policy_id])

        existing_legacy = rule_data.get('exceptions') if isinstance(rule_data.get('exceptions'), dict) else {}
        merged_rule_data = dict(rule_data)
        merged_rule_data['exception_sets'] = scoped_sets
        merged_rule_data['exceptions'] = _aggregate_legacy_exceptions(scoped_sets, existing_legacy)

        patterns.append({
            "id": policy_id,
            "name": p.get("name"),
            "regex": regex_value,
            "rule_type": p.get("rule_type", "regex"),
            "rule_data": merged_rule_data,
            "description": p.get("description", ""),
            "severity": p.get("severity", "MEDIUM"),
            "action": p.get("action", "monitor"),
            "threshold": p.get("threshold_count", 1),
            "window": p.get("threshold_window_mins", 60)
        })
        
    agent_id = str(request.args.get('agent_id') or '').strip()
    managed_settings = _normalize_managed_extension_settings({})
    if agent_id:
        meta = (fleet_registry.get(agent_id) or {}).get('meta', {})
        managed = meta.get('managed_settings', {}) if isinstance(meta, dict) else {}
        managed_settings = _normalize_managed_extension_settings(managed)

    return jsonify({"patterns": patterns, "managed_settings": managed_settings}), 200


@app.route('/api/exceptions', methods=['GET'])
def get_exceptions():
    """Get exception rules."""
    if not database:
        return jsonify({'exceptions': []}), 200
    active_only = request.args.get('active_only', 'false').lower() == 'true'
    rows = database.get_exceptions(active_only=active_only)
    return jsonify({'exceptions': rows}), 200


@app.route('/api/exceptions', methods=['POST'])
def create_exception():
    """Create a global or policy-scoped exception rule."""
    if not database:
        return jsonify({'error': 'Database not configured'}), 500

    payload = request.json or {}
    normalized = _normalize_exception_payload(payload)
    actor = _actor_from_request('admin')
    normalized['actor'] = actor
    if not normalized['name']:
        return jsonify({'error': 'Name is required'}), 400
    if normalized['scope_type'] == 'policy' and not (normalized['policy_id'] or normalized.get('policy_ids')):
        return jsonify({'error': 'policy_id or policy_ids is required for policy scope'}), 400
    if str(payload.get('expires_at') or '').strip() and not normalized['expires_at']:
        return jsonify({'error': 'expires_at must be a valid ISO datetime'}), 400

    try:
        exception_id = database.add_exception(**normalized)
        return jsonify({'status': 'success', 'exception_id': exception_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/exceptions/<exception_id>', methods=['PUT', 'PATCH'])
def update_exception(exception_id):
    """Update an exception rule."""
    if not database:
        return jsonify({'error': 'Database not configured'}), 500

    payload = request.json or {}
    normalized = _normalize_exception_payload(payload)
    if normalized['scope_type'] == 'policy' and not (normalized['policy_id'] or normalized.get('policy_ids')):
        return jsonify({'error': 'policy_id or policy_ids is required for policy scope'}), 400
    if str(payload.get('expires_at') or '').strip() and not normalized['expires_at']:
        return jsonify({'error': 'expires_at must be a valid ISO datetime'}), 400

    try:
        actor = _actor_from_request('admin')
        success = database.update_exception(exception_id, actor=actor, **normalized)
        if success:
            return jsonify({'status': 'success'}), 200
        return jsonify({'error': 'Failed to update or no changes'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/exceptions/<exception_id>', methods=['DELETE'])
def delete_exception(exception_id):
    """Delete an exception rule."""
    if not database:
        return jsonify({'error': 'Database not configured'}), 500

    try:
        iam_settings = _get_iam_settings()
        if _bool_setting(iam_settings.get('enforce_policy_delete_confirmation_ticket'), False):
            payload = request.get_json(silent=True) or {}
            ticket = str(payload.get('ticket_id') or request.args.get('ticket_id') or '').strip()
            if not ticket:
                return jsonify({'error': 'ticket_id_required_for_delete'}), 400
        database.delete_exception(exception_id)
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============== AI POLICY LAB ==============

@app.route('/api/lab/generate_rule', methods=['POST'])
def generate_rule():
    """Generate a policy rule from natural language using AI"""
    if not ai_analyzer:
        return jsonify({"error": "AI analyzer not configured"}), 500
    
    data = request.json or {}
    prompt = data.get('prompt', '').strip()
    
    if not prompt:
        return jsonify({"error": "Prompt is required"}), 400
    
    try:
        import re

        ai_rule = ai_analyzer.generate_rule_from_prompt(prompt)
        if not isinstance(ai_rule, dict):
            ai_rule = {}

        # Fallback/local normalization for noisy client prompts (typos, vague wording)
        prompt_l = prompt.lower()
        inferred_type = ai_rule.get('rule_type') or 'regex'
        if inferred_type not in {'regex', 'file_size', 'extension', 'network'}:
            if any(k in prompt_l for k in ['.exe', '.dll', '.pdf', '.doc', 'extension', 'file type', 'filetype']):
                inferred_type = 'extension'
            elif any(k in prompt_l for k in ['mb', 'gb', 'kb', 'file size', 'larger than', 'greater than']):
                inferred_type = 'file_size'
            elif any(k in prompt_l for k in ['domain', 'url', 'site', 'ip address', 'hostname']):
                inferred_type = 'network'
            else:
                inferred_type = 'regex'

        raw_rule_data = ai_rule.get('rule_data')
        rule_data = raw_rule_data if isinstance(raw_rule_data, dict) else {}

        if inferred_type == 'regex':
            # Prefer quoted phrase (handles "image" even if surrounding prompt has typos)
            quoted = re.search(r"'([^']+)'|\"([^\"]+)\"", prompt)
            pattern_val = rule_data.get('pattern')
            pattern = (str(pattern_val or (quoted.group(1) or quoted.group(2) if quoted else ''))).strip()
            if not pattern:
                # basic token fallback
                toks = re.findall(r"[a-zA-Z0-9_]+", prompt)
                pattern = toks[-1] if toks else 'sensitive'
            rule_data = {'pattern': pattern}
            preview = pattern

        elif inferred_type == 'file_size':
            max_size_mb = rule_data.get('max_size_mb')
            if not isinstance(max_size_mb, int):
                m = re.search(r"(\d+)\s*(kb|mb|gb)", prompt_l)
                if m:
                    n = int(m.group(1))
                    unit = m.group(2)
                    if unit == 'kb':
                        max_size_mb = max(1, n // 1024)
                    elif unit == 'gb':
                        max_size_mb = n * 1024
                    else:
                        max_size_mb = n
                else:
                    max_size_mb = 10
            rule_data = {'max_size_mb': max_size_mb}
            preview = str(max_size_mb)

        elif inferred_type == 'extension':
            blocked_raw = rule_data.get('blocked_extensions')
            blocked = blocked_raw if isinstance(blocked_raw, list) else []
            if not blocked:
                blocked = [f".{x.lower()}" for x in re.findall(r"\.([a-zA-Z0-9]+)", prompt)]
            blocked = [ext if ext.startswith('.') else f".{ext}" for ext in blocked]
            if not blocked:
                blocked = ['.exe']
            rule_data = {'blocked_extensions': blocked}
            preview = '|'.join(ext.lstrip('.') for ext in blocked)

        else:  # network
            blocked_domains_raw = rule_data.get('blocked_domains')
            blocked_domains = blocked_domains_raw if isinstance(blocked_domains_raw, list) else []
            if not blocked_domains:
                blocked_domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", prompt_l)
            if not blocked_domains:
                blocked_domains = ['example.com']
            rule_data = {'blocked_domains': blocked_domains}
            preview = ', '.join(blocked_domains)

        severity = (ai_rule.get('severity') or 'MEDIUM').upper()
        if severity not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
            severity = 'MEDIUM'

        action = (ai_rule.get('action') or 'block').lower()
        if action not in {'monitor', 'warn', 'block'}:
            action = 'block'

        name = (ai_rule.get('name') or 'CUSTOM_RULE').strip() or 'CUSTOM_RULE'
        description = (ai_rule.get('description') or prompt).strip() or prompt

        return jsonify({
            'name': name,
            'description': description,
            'rule_type': inferred_type,
            'rule_data': rule_data,
            'pattern': preview,
            'action': action,
            'severity': severity,
            'ai_generated': True,
            'ai_prompt': prompt,
            'ai_model': 'VertexAI',
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to generate rule: {str(e)}"}), 500

@app.route('/api/lab/test_rule', methods=['POST'])
def test_rule():
    """Test a generated rule against sample input"""
    data = request.json or {}
    rule = data.get('rule', {})
    test_input = data.get('input', '').strip()
    
    if not rule or not test_input:
        return jsonify({"error": "Rule and input are required"}), 400
    
    try:
        rule_type = rule.get('rule_type', 'regex')
        raw_rule_data = rule.get('rule_data')
        rule_data = raw_rule_data if isinstance(raw_rule_data, dict) else {}
        pattern = rule.get('pattern', '')
        match = False
        reason = ''
        
        if rule_type == 'file_size':
            # Test file size (input should be a number in MB)
            try:
                input_size = float(test_input)
                threshold = float(rule_data.get('max_size_mb', pattern or 10))
                match = input_size > threshold
                reason = f"File size {input_size}MB {'exceeds' if match else 'is below'} threshold {threshold}MB"
            except ValueError:
                reason = "Invalid file size input (expected number in MB)"
                
        elif rule_type == 'extension':
            # Test file extension
            test_lower = test_input.lower()
            blocked_raw = rule_data.get('blocked_extensions')
            extensions = blocked_raw if isinstance(blocked_raw, list) else []
            if not extensions:
                extensions = pattern.split('|') if pattern else []
            match = any(test_lower.endswith(f'.{ext}') or test_lower.endswith(ext) for ext in extensions)
            reason = f"File extension {'matches' if match else 'does not match'} blocked types: {', '.join(extensions)}"
            
        elif rule_type == 'network':
            domains_raw = rule_data.get('blocked_domains')
            domains = domains_raw if isinstance(domains_raw, list) else []
            lowered_input = test_input.lower()
            domain_strings = [str(d) for d in domains]
            match = any(d.lower() in lowered_input for d in domain_strings)
            reason = f"Input {'contains' if match else 'does not contain'} blocked domain(s): {', '.join(domain_strings)}"
            
        else:  # regex
            # Test regex pattern
            import re
            try:
                if not pattern:
                    pattern = str(rule_data.get('pattern', ''))
                match = bool(re.search(pattern, test_input))
                reason = f"Pattern {'matches' if match else 'does not match'} input"
            except Exception as e:
                reason = f"Regex error: {str(e)}"
        
        return jsonify({
            "match": match,
            "reason": reason
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Test failed: {str(e)}"}), 500

@app.route('/api/policies', methods=['POST'])
def create_policy():
    """Create a new dynamically managed policy"""
    if not database:
        return jsonify({"error": "Database not configured"}), 500
        
    data = request.json or {}
    name = data.get('name')
    if not name:
        return jsonify({"error": "Name is required"}), 400

    rule_type = data.get('rule_type', 'regex')
    if rule_type not in {'regex', 'file_size', 'extension', 'network'}:
        rule_type = 'regex'

    incoming_rule_data = data.get('rule_data')
    rule_data = incoming_rule_data if isinstance(incoming_rule_data, dict) else {}

    # Preserve AI-lab source metadata for policy tagging/history.
    if bool(data.get('ai_generated')):
        raw_meta = rule_data.get('_meta')
        meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
        meta.update({
            'source': 'ai_lab',
            'ai_generated': True,
            'ai_model': str(data.get('ai_model') or 'VertexAI'),
        })
        ai_prompt = str(data.get('ai_prompt') or '').strip()
        if ai_prompt:
            meta['ai_prompt'] = ai_prompt
        rule_data['_meta'] = meta

    # Backward compatibility with existing UI payloads
    regex_pattern = (data.get('regex_pattern') or data.get('pattern') or '').strip()

    if rule_type == 'regex':
        if not rule_data.get('pattern'):
            rule_data['pattern'] = regex_pattern
        if not rule_data.get('pattern'):
            return jsonify({"error": "Pattern is required for regex rule"}), 400

    elif rule_type == 'extension':
        blocked = rule_data.get('blocked_extensions') if isinstance(rule_data.get('blocked_extensions'), list) else []
        if not blocked and regex_pattern:
            blocked = [f".{x.strip().lstrip('.')}" for x in regex_pattern.split('|') if x.strip()]
        if not blocked:
            return jsonify({"error": "blocked_extensions is required for extension rule"}), 400
        rule_data['blocked_extensions'] = blocked

    elif rule_type == 'file_size':
        if 'max_size_mb' not in rule_data:
            try:
                rule_data['max_size_mb'] = int(float(regex_pattern)) if regex_pattern else 10
            except ValueError:
                rule_data['max_size_mb'] = 10

    elif rule_type == 'network':
        blocked_domains = rule_data.get('blocked_domains') if isinstance(rule_data.get('blocked_domains'), list) else []
        if not blocked_domains and regex_pattern:
            blocked_domains = [x.strip() for x in regex_pattern.split(',') if x.strip()]
        if not blocked_domains:
            return jsonify({"error": "blocked_domains is required for network rule"}), 400
        rule_data['blocked_domains'] = blocked_domains
        
    try:
        actor = _actor_from_request('admin')
        policy_id = database.add_policy(
            name=name,
            rule_type=rule_type,
            rule_data=rule_data,
            description=data.get('description', ''),
            severity=data.get('severity', 'MEDIUM'),
            action=data.get('action', 'block'),
            threshold_count=data.get('threshold_count', 1),
            threshold_window_mins=data.get('threshold_window_mins', 60),
            actor=actor
        )
        return jsonify({"status": "success", "policy_id": policy_id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/policies/<policy_id>', methods=['PUT', 'PATCH'])
def update_policy(policy_id):
    """Update a policy"""
    if not database:
        return jsonify({"error": "Database not configured"}), 500
        
    data = request.json or {}
    try:
        actor = _actor_from_request('admin')
        success = database.update_policy(policy_id, actor=actor, **data)
        if success:
            return jsonify({"status": "success"}), 200
        return jsonify({"error": "Failed to update or no changes"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/policies/<policy_id>', methods=['DELETE'])
def delete_policy(policy_id):
    """Delete a policy"""
    if not database:
        return jsonify({"error": "Database not configured"}), 500
        
    try:
        iam_settings = _get_iam_settings()
        if _bool_setting(iam_settings.get('enforce_policy_delete_confirmation_ticket'), False):
            payload = request.get_json(silent=True) or {}
            ticket = str(payload.get('ticket_id') or request.args.get('ticket_id') or '').strip()
            if not ticket:
                return jsonify({'error': 'ticket_id_required_for_delete'}), 400
        database.delete_policy(policy_id)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============== AUDIT LOG ==============

@app.route('/api/audit', methods=['GET'])
def get_audit_log():
    """Get audit log entries"""
    limit = request.args.get('limit', 50, type=int)
    actor = str(request.args.get('actor', '') or '').strip() or None
    action = str(request.args.get('action', '') or '').strip() or None
    query = str(request.args.get('query', '') or '').strip() or None
    since = str(request.args.get('since', '') or '').strip() or None
    action_only = str(request.args.get('action_only', 'false') or 'false').strip().lower() in {'1', 'true', 'yes'}

    if not database:
        return jsonify({"total": 0, "entries": []}), 200

    entries = database.get_audit_log(limit=limit, actor=actor, action=action, query=query, since=since, action_only=action_only)
    return jsonify({
        "total": len(entries),
        "entries": entries
    }), 200

# ============== DASHBOARD STATS ==============

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""

    if not incident_store:
        return jsonify({
            "total_incidents": 0,
            "open_incidents": 0,
            "closed_incidents": 0,
            "escalated_incidents": 0,
            "avg_risk_score": 0,
            "total_events": 0,
        }), 200

    stats = incident_store.stats()

    return jsonify(stats), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""

    db_status = "ok"
    try:
        if database:
            database.stats()  # Quick DB check
    except Exception:
        db_status = "error"

    return jsonify({
        "status": "healthy",
        "version": "2.0.0",
        "storage": "sqlite_persistent",
        "components": {
            "incident_store": "ok" if incident_store else "unconfigured",
            "rules_engine": "ok" if rules_engine else "unconfigured",
            "database": db_status,
            "file_scanner": "ok" if file_scanner else "unconfigured",
            "telegram_bot": "ok" if telegram_bot and telegram_bot.bot_token else "unconfigured",
            "slack": "ok" if escalation_engine and escalation_engine.slack_webhook else "unconfigured",
            "gemini_ai": "ok" if ai_analyzer and ai_analyzer.api_key else "unconfigured",
        }
    }), 200


# ============== ERROR HANDLERS ==============

@app.errorhandler(404)
def not_found(_error):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(_error):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    app.run(
        host=Config.FLASK_HOST,
        port=Config.FLASK_PORT,
        debug=Config.DEBUG
    )
