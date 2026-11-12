"""
Platform endpoints: retention, SIEM forwarding, data protection status, Indexed Document
Matching, audit chain verification and metrics.

Registered on the main app by src.api. Authentication and RBAC are enforced by the app's
before_request guard (see `_required_permission_for_request`), not here.
"""

from __future__ import annotations

import hmac
import os

from flask import Blueprint, jsonify, request

from src import metrics, retention, siem
from src.detection.idm import DocumentTooShort, MIN_WORDS
from src.extraction import MAX_INPUT_BYTES, extract

bp = Blueprint("platform", __name__)


def _core():
    from src import api
    return api


def _db_required():
    return jsonify({"error": "database_unavailable"}), 503


# ============== RETENTION ==============

@bp.route("/api/settings/retention", methods=["GET"])
def get_retention():
    core = _core()
    if not core.database:
        return _db_required()
    return jsonify({
        "retention_days": retention.current(core.database),
        "data_classes": retention.DATA_CLASSES,
        "last_run": core.database.get_platform_setting("retention_last_run"),
        "max_days": retention.MAX_DAYS,
    }), 200


@bp.route("/api/settings/retention", methods=["PUT"])
def put_retention():
    core = _core()
    if not core.database:
        return _db_required()
    body = request.get_json(silent=True) or {}
    try:
        config = retention.normalize(body.get("retention_days"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    actor = core._actor_from_request()
    core.database.set_platform_setting(retention.SETTING_KEY, config, actor=actor)
    core._write_portal_audit("retention_updated", "platform", "retention", actor, config)
    return jsonify({"status": "ok", "retention_days": config}), 200


@bp.route("/api/settings/retention/run", methods=["POST"])
def run_retention():
    core = _core()
    if not core.database:
        return _db_required()
    counts = retention.run_once(core.database, core._artifacts_root())
    core._write_portal_audit("retention_run_requested", "platform", "retention", core._actor_from_request(), counts)
    return jsonify({"status": "ok", "deleted": counts}), 200


# ============== DATA PROTECTION ==============

@bp.route("/api/settings/data-protection", methods=["GET"])
def data_protection():
    core = _core()
    if not core.database:
        return _db_required()
    from src import agent_auth
    return jsonify({
        "encryption_at_rest": core.database.cipher.enabled,
        "data_key_source": "environment" if os.getenv("TRON_DATA_KEY", "").strip() else
                           ("key_file" if core.database.cipher.enabled else "disabled"),
        "agent_auth_mode": agent_auth.auth_mode(),
        "enrollment_enabled": bool(agent_auth.enrollment_token()),
        "auth_secret_persistent": bool(os.getenv("APP_AUTH_SECRET", "").strip()),
        "metrics_enabled": bool(os.getenv("TRON_METRICS_TOKEN", "").strip()),
        "audit_chain": core.database.verify_audit_chain(),
    }), 200


@bp.route("/api/audit/verify", methods=["GET"])
def audit_verify():
    core = _core()
    if not core.database:
        return _db_required()
    return jsonify(core.database.verify_audit_chain()), 200


# ============== SIEM FORWARDING ==============

@bp.route("/api/siem/config", methods=["GET"])
def siem_get_config():
    core = _core()
    if not core.siem_forwarder:
        return _db_required()
    return jsonify({
        "config": siem.redact_config(core.siem_forwarder.config(max_age=0)),
        "record_kinds": list(siem.RECORD_KINDS),
        "outbox": core.database.siem_outbox_stats(),
        "delivered": core.siem_forwarder.delivered,
        "failed": core.siem_forwarder.failed,
    }), 200


@bp.route("/api/siem/config", methods=["PUT"])
def siem_put_config():
    core = _core()
    if not core.siem_forwarder:
        return _db_required()
    body = request.get_json(silent=True) or {}
    try:
        config = siem.validate_config(body.get("config"))
    except siem.ConfigError as exc:
        return jsonify({"error": str(exc)}), 400
    config = siem.merge_secrets(config, core.siem_forwarder.config(max_age=0))
    actor = core._actor_from_request()
    core.siem_forwarder.save_config(config, actor=actor)
    core._write_portal_audit("siem_config_updated", "platform", "siem", actor, siem.redact_config(config))
    return jsonify({"status": "ok", "config": siem.redact_config(config)}), 200


@bp.route("/api/siem/test", methods=["POST"])
def siem_test():
    """Send one synthetic record to a configured destination and report the outcome."""
    core = _core()
    if not core.siem_forwarder:
        return _db_required()
    dest_id = str((request.get_json(silent=True) or {}).get("destination_id") or "")
    dest = next((d for d in core.siem_forwarder.config(max_age=0).get("destinations", []) if d["id"] == dest_id), None)
    if dest is None:
        return jsonify({"error": "destination_not_found"}), 404
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    record = {"kind": "audit", "action": "siem_test", "id": "TEST", "actor": core._actor_from_request(),
              "severity": "info", "message": "Tron DLP test record", "product": "tron-dlp",
              "timestamp": now.isoformat(timespec="seconds"), "timestamp_ms": int(now.timestamp() * 1000)}
    try:
        siem.deliver(dest, [record])
    except Exception as exc:
        # The collector's response body is deliberately not echoed back.
        return jsonify({"status": "failed", "error": f"{type(exc).__name__}: {str(exc)[:200]}"}), 502
    return jsonify({"status": "delivered"}), 200


# ============== INDEXED DOCUMENT MATCHING ==============

def _idm_public(doc: dict) -> dict:
    return {k: doc.get(k) for k in (
        "doc_id", "name", "description", "sensitivity", "content_sha256", "size_bytes", "word_count",
        "fingerprint_count", "is_active", "created_at", "created_by")}


def _idm_input():
    """(name, text, raw bytes, error response) from a multipart upload or a JSON body."""
    upload = request.files.get("file")
    if upload is not None:
        raw = upload.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            return None, None, None, (jsonify({"error": "file_too_large"}), 413)
        name = os.path.basename(upload.filename or "document")
        extraction = extract(data=raw, name=name)
        if extraction.encrypted:
            return None, None, None, (jsonify({"error": "encrypted_document",
                                               "message": "Password-protected files cannot be fingerprinted."}), 400)
        return name, extraction.text or "", raw, None
    body = request.get_json(silent=True) or {}
    text = str(body.get("text") or "")
    return str(body.get("name") or "").strip(), text, None, None


@bp.route("/api/idm/documents", methods=["GET"])
def idm_list():
    core = _core()
    if not core.database:
        return _db_required()
    return jsonify({"documents": [_idm_public(d) for d in core.database.list_idm_documents()],
                    "min_words": MIN_WORDS}), 200


@bp.route("/api/idm/documents", methods=["POST"])
def idm_register():
    core = _core()
    if not core.idm_index:
        return _db_required()
    file_name, text, raw, error = _idm_input()
    if error:
        return error
    form = request.form if request.files else (request.get_json(silent=True) or {})
    name = str(form.get("name") or file_name or "").strip()[:200]
    if not name:
        return jsonify({"error": "name is required"}), 400
    sensitivity = str(form.get("sensitivity") or "HIGH").upper()
    if sensitivity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return jsonify({"error": "sensitivity must be LOW, MEDIUM, HIGH or CRITICAL"}), 400
    actor = core._actor_from_request()
    try:
        doc = core.idm_index.register(name=name, text=text, description=str(form.get("description") or "")[:1000],
                                      sensitivity=sensitivity, raw=raw, created_by=actor)
    except DocumentTooShort as exc:
        return jsonify({"error": "document_too_short", "message": str(exc)}), 400
    if doc.get("duplicate"):
        return jsonify({"status": "exists", "document": _idm_public(doc)}), 200
    core._write_portal_audit("idm_document_registered", "idm_document", doc["doc_id"], actor,
                             {"name": name, "sensitivity": sensitivity, "fingerprints": doc["fingerprint_count"]})
    return jsonify({"status": "registered", "document": _idm_public(doc)}), 201


@bp.route("/api/idm/documents/<doc_id>", methods=["PATCH"])
def idm_update(doc_id):
    core = _core()
    if not core.database:
        return _db_required()
    body = request.get_json(silent=True) or {}
    if "is_active" not in body:
        return jsonify({"error": "is_active is required"}), 400
    if not core.database.set_idm_document_active(doc_id, bool(body["is_active"])):
        return jsonify({"error": "document_not_found"}), 404
    core._write_portal_audit("idm_document_updated", "idm_document", doc_id, core._actor_from_request(),
                             {"is_active": bool(body["is_active"])})
    return jsonify({"status": "ok", "document": _idm_public(core.database.get_idm_document(doc_id))}), 200


@bp.route("/api/idm/documents/<doc_id>", methods=["DELETE"])
def idm_delete(doc_id):
    core = _core()
    if not core.database:
        return _db_required()
    if not core.database.delete_idm_document(doc_id):
        return jsonify({"error": "document_not_found"}), 404
    core._write_portal_audit("idm_document_deleted", "idm_document", doc_id, core._actor_from_request(), {})
    return jsonify({"status": "deleted"}), 200


@bp.route("/api/idm/match", methods=["POST"])
def idm_match():
    """Check a file or text against the protected document index (console test tool)."""
    core = _core()
    if not core.idm_index:
        return _db_required()
    _, text, _, error = _idm_input()
    if error:
        return error
    matches = [{"doc_id": m.doc_id, "name": m.name, "sensitivity": m.sensitivity, "matched": m.matched,
                "total": m.total, "containment": round(m.containment, 4)}
               for m in core.idm_index.match(text)]
    return jsonify({"matches": matches}), 200


# ============== METRICS ==============

@bp.route("/api/metrics", methods=["GET"])
def prometheus_metrics():
    core = _core()
    token = os.getenv("TRON_METRICS_TOKEN", "").strip()
    if not token:
        return jsonify({"error": "Not found"}), 404
    supplied = request.headers.get("Authorization", "")
    supplied = supplied[7:].strip() if supplied.startswith("Bearer ") else ""
    if not supplied or not hmac.compare_digest(supplied.encode(), token.encode()):
        return jsonify({"error": "metrics_token_required"}), 401
    body = metrics.render(core.database, core.siem_forwarder, version=core.APP_VERSION)
    return core.app.response_class(body, mimetype="text/plain; version=0.0.4; charset=utf-8")
