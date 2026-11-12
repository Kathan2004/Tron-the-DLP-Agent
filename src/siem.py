"""
SIEM forwarding: ship incidents, detection events and audit records to external collectors.

Destinations
    syslog   RFC 5424 over UDP, TCP or TLS; body is CEF (ArcSight/QRadar/Sentinel) or JSON.
    webhook  HTTPS POST of JSON. Optional HMAC-SHA256 signature and a static auth header,
             which covers Splunk HEC ("Authorization: Splunk <token>", format "splunk_hec"),
             Elastic, Sentinel data collectors and generic receivers.

Delivery is at-least-once. Records are written to a durable outbox (siem_outbox) in the
same database as the data they describe and drained by a background worker with
exponential backoff, so a collector outage neither blocks detection nor loses records.

Forwarded records never contain matched values or payload samples: detector names, counts,
severities and identities only.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
import ssl
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import requests

log = logging.getLogger("tron.siem")

SETTING_KEY = "siem_forwarding"
RECORD_KINDS = ("incident", "event", "audit", "agent")
PRODUCT_VERSION = "2.1.0"

_CEF_SEVERITY = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1, "none": 0}
_SYSLOG_SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6, "none": 6}
_FACILITY_LOCAL4 = 20


class ConfigError(ValueError):
    pass


# ---------------------------------------------------------------- configuration

def default_config() -> dict:
    return {"enabled": False, "destinations": []}


def _check_host(host: str) -> None:
    """Reject destinations that can only be an SSRF target (link-local / metadata ranges)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ConfigError(f"cannot resolve host '{host}'") from exc
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            raise ConfigError(f"host '{host}' resolves to a disallowed address range")


def _ca_pem(d: dict, dest_id: str) -> str:
    """Optional private CA bundle (PEM) used to verify the collector's certificate.

    Certificate verification is always on; a collector with a private or self-signed
    certificate is trusted by supplying its CA here, never by turning verification off.
    """
    pem = str(d.get("ca_pem") or "").strip()
    if not pem:
        return ""
    if len(pem) > 64 * 1024 or "-----BEGIN CERTIFICATE-----" not in pem:
        raise ConfigError(f"destination '{dest_id}': ca_pem must be a PEM certificate bundle")
    try:
        ssl.create_default_context(cadata=pem)
    except ssl.SSLError as exc:
        raise ConfigError(f"destination '{dest_id}': ca_pem could not be parsed") from exc
    return pem


def validate_config(raw: object, resolve: bool = True) -> dict:
    """Normalise a forwarding config from the console. Raises ConfigError with a readable reason."""
    if not isinstance(raw, dict):
        raise ConfigError("config must be an object")
    out = {"enabled": bool(raw.get("enabled")), "destinations": []}
    destinations = raw.get("destinations") or []
    if not isinstance(destinations, list) or len(destinations) > 8:
        raise ConfigError("destinations must be a list of at most 8 entries")
    seen = set()
    for i, d in enumerate(destinations):
        if not isinstance(d, dict):
            raise ConfigError(f"destination {i + 1} must be an object")
        dest_id = str(d.get("id") or f"dest-{i + 1}").strip()[:40]
        if not dest_id or dest_id in seen:
            raise ConfigError(f"destination {i + 1} needs a unique id")
        seen.add(dest_id)
        kind = str(d.get("type") or "").strip().lower()
        kinds = [k for k in (d.get("record_kinds") or list(RECORD_KINDS)) if k in RECORD_KINDS]
        if not kinds:
            raise ConfigError(f"destination '{dest_id}' selects no record kinds")
        entry = {"id": dest_id, "type": kind, "enabled": bool(d.get("enabled", True)),
                 "record_kinds": kinds, "min_severity": str(d.get("min_severity") or "low").lower()}
        if entry["min_severity"] not in _CEF_SEVERITY:
            raise ConfigError(f"destination '{dest_id}' has an unknown min_severity")
        if kind == "syslog":
            host = str(d.get("host") or "").strip()
            try:
                port = int(d.get("port") or 514)
            except (TypeError, ValueError):
                raise ConfigError(f"destination '{dest_id}' has an invalid port") from None
            protocol = str(d.get("protocol") or "udp").lower()
            fmt = str(d.get("format") or "cef").lower()
            if not host or not (0 < port < 65536):
                raise ConfigError(f"destination '{dest_id}' needs a host and a valid port")
            if protocol not in {"udp", "tcp", "tls"} or fmt not in {"cef", "json"}:
                raise ConfigError(f"destination '{dest_id}': protocol must be udp/tcp/tls and format cef/json")
            if resolve:
                _check_host(host)
            entry.update(host=host, port=port, protocol=protocol, format=fmt, ca_pem=_ca_pem(d, dest_id))
        elif kind == "webhook":
            url = str(d.get("url") or "").strip()
            parsed = urlparse(url)
            if parsed.scheme not in {"https", "http"} or not parsed.hostname:
                raise ConfigError(f"destination '{dest_id}' needs an http(s) URL")
            if parsed.scheme == "http" and not bool(d.get("allow_insecure")):
                raise ConfigError(f"destination '{dest_id}': plain http requires allow_insecure")
            if parsed.username or parsed.password:
                raise ConfigError(f"destination '{dest_id}': put credentials in auth_header, not the URL")
            fmt = str(d.get("format") or "json").lower()
            if fmt not in {"json", "splunk_hec"}:
                raise ConfigError(f"destination '{dest_id}': format must be json or splunk_hec")
            if resolve:
                _check_host(parsed.hostname)
            entry.update(url=url, format=fmt, allow_insecure=bool(d.get("allow_insecure")),
                         ca_pem=_ca_pem(d, dest_id),
                         secret=str(d.get("secret") or "")[:256],
                         auth_header=str(d.get("auth_header") or "")[:1024])
        else:
            raise ConfigError(f"destination '{dest_id}': type must be syslog or webhook")
        out["destinations"].append(entry)
    return out


def redact_config(config: dict) -> dict:
    """Config for display: secrets replaced by a boolean."""
    shown = {"enabled": bool(config.get("enabled")), "destinations": []}
    for d in config.get("destinations", []):
        e = {k: v for k, v in d.items() if k not in {"secret", "auth_header", "ca_pem"}}
        e["has_ca_pem"] = bool(d.get("ca_pem"))
        if d.get("type") == "webhook":
            e["has_secret"] = bool(d.get("secret"))
            e["has_auth_header"] = bool(d.get("auth_header"))
        shown["destinations"].append(e)
    return shown


def merge_secrets(new: dict, old: dict) -> dict:
    """Keep stored secrets for destinations the console re-submitted without them."""
    previous = {d["id"]: d for d in (old or {}).get("destinations", [])}
    for d in new.get("destinations", []):
        prior = previous.get(d["id"]) or {}
        for field in ("secret", "auth_header", "ca_pem"):
            if field in d and not d.get(field) and prior.get(field) and not d.get(f"clear_{field}"):
                d[field] = prior[field]
    return new


# ---------------------------------------------------------------- formatting

def _cef_escape_header(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_escape_ext(value: object) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\n", "\\n").replace("\r", ""))


def to_cef(record: dict) -> str:
    kind = record.get("kind", "event")
    severity = str(record.get("severity") or "info").lower()
    name = {
        "incident": f"DLP incident {record.get('action', 'updated')}",
        "event": "DLP detection",
        "audit": f"Audit: {record.get('action', 'action')}",
        "agent": f"Agent {record.get('action', 'activity')}",
    }.get(kind, "DLP record")
    signature = f"{kind}:{record.get('action') or 'detection'}"
    ext = {
        "rt": record.get("timestamp_ms"),
        "externalId": record.get("id"),
        "suser": record.get("user"),
        "shost": record.get("host"),
        "act": record.get("action"),
        "cs1Label": "detectors", "cs1": ",".join(record.get("detectors") or []) or None,
        "cs2Label": "channel", "cs2": record.get("channel"),
        "cs3Label": "status", "cs3": record.get("status"),
        "cs4Label": "actor", "cs4": record.get("actor"),
        "cn1Label": "riskScore", "cn1": record.get("risk"),
        "msg": record.get("message"),
    }
    pairs = []
    for key, value in ext.items():
        if key.endswith("Label"):
            continue
        if value is None or value == "":
            continue
        label_key = f"{key}Label"
        if label_key in ext:
            pairs.append(f"{label_key}={_cef_escape_ext(ext[label_key])}")
        pairs.append(f"{key}={_cef_escape_ext(value)}")
    header = "|".join(_cef_escape_header(p) for p in (
        "CEF:0", "Tron", "DLP", PRODUCT_VERSION, signature, name, _CEF_SEVERITY.get(severity, 1)))
    return f"{header}|{' '.join(pairs)}"


def to_syslog(record: dict, fmt: str, hostname: str) -> bytes:
    severity = _SYSLOG_SEVERITY.get(str(record.get("severity") or "info").lower(), 6)
    pri = _FACILITY_LOCAL4 * 8 + severity
    body = to_cef(record) if fmt == "cef" else json.dumps(record, separators=(",", ":"), default=str)
    timestamp = record.get("timestamp") or datetime.now(timezone.utc).isoformat(timespec="seconds")
    return f"<{pri}>1 {timestamp} {hostname} tron-dlp - {record.get('kind', '-')} - {body}".encode("utf-8")


# ---------------------------------------------------------------- senders

def _send_syslog(dest: dict, lines: List[bytes], timeout: float = 5.0) -> None:
    address = (dest["host"], int(dest["port"]))
    if dest["protocol"] == "udp":
        family = socket.getaddrinfo(dest["host"], dest["port"], type=socket.SOCK_DGRAM)[0][0]
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            for line in lines:
                sock.sendto(line[:65000], address)
        return
    raw = socket.create_connection(address, timeout=timeout)
    try:
        if dest["protocol"] == "tls":
            context = ssl.create_default_context(cadata=dest.get("ca_pem") or None)
            raw = context.wrap_socket(raw, server_hostname=dest["host"])
        # RFC 6587 octet counting: unambiguous framing even when a message contains newlines.
        raw.sendall(b"".join(str(len(line)).encode() + b" " + line for line in lines))
    finally:
        raw.close()


def _send_webhook(dest: dict, records: List[dict], timeout: float = 10.0) -> None:
    if dest.get("format") == "splunk_hec":
        body = "\n".join(json.dumps({
            "time": (r.get("timestamp_ms") or int(time.time() * 1000)) / 1000,
            "sourcetype": "tron:dlp", "source": "tron-dlp", "event": r,
        }, default=str) for r in records).encode("utf-8")
    else:
        body = json.dumps({"records": records}, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": f"tron-dlp/{PRODUCT_VERSION}"}
    if dest.get("auth_header"):
        headers["Authorization"] = dest["auth_header"]
    if dest.get("secret"):
        stamp = str(int(time.time()))
        signature = hmac.new(dest["secret"].encode("utf-8"), stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        headers["X-Tron-Timestamp"] = stamp
        headers["X-Tron-Signature"] = f"sha256={signature}"
    ca_file = None
    try:
        if dest.get("ca_pem"):
            ca_file = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
            ca_file.write(dest["ca_pem"])
            ca_file.close()
        response = requests.post(dest["url"], data=body, headers=headers, timeout=timeout,
                                 verify=ca_file.name if ca_file else True, allow_redirects=False)
    finally:
        if ca_file is not None:
            try:
                os.unlink(ca_file.name)
            except OSError:
                pass
    if response.status_code >= 300:
        raise RuntimeError(f"collector returned HTTP {response.status_code}")


def deliver(dest: dict, records: List[dict], hostname: Optional[str] = None) -> None:
    """Send records to one destination. Raises on failure."""
    if not records:
        return
    if dest["type"] == "syslog":
        host = hostname or socket.gethostname()
        _send_syslog(dest, [to_syslog(r, dest.get("format", "cef"), host) for r in records])
    else:
        _send_webhook(dest, records)


# ---------------------------------------------------------------- forwarder

def _severity_at_least(record: dict, minimum: str) -> bool:
    return _CEF_SEVERITY.get(str(record.get("severity") or "info").lower(), 1) >= _CEF_SEVERITY.get(minimum, 0) \
        or record.get("kind") in {"audit", "agent"}


class SiemForwarder:
    """Queues records for the configured destinations and drains the outbox."""

    def __init__(self, database, sender: Callable[[dict, List[dict]], None] = deliver):
        self.db = database
        self._sender = sender
        self._config: Optional[dict] = None
        self._config_loaded_at = 0.0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.delivered = 0
        self.failed = 0

    # ---- config ----

    def config(self, max_age: float = 5.0) -> dict:
        now = time.monotonic()
        if self._config is None or now - self._config_loaded_at > max_age:
            stored = self.db.get_platform_setting(SETTING_KEY)
            self._config = stored if isinstance(stored, dict) else default_config()
            self._config_loaded_at = now
        return self._config

    def save_config(self, config: dict, actor: Optional[str] = None) -> None:
        self.db.set_platform_setting(SETTING_KEY, config, actor=actor, secret=True)
        self._config = config
        self._config_loaded_at = time.monotonic()

    # ---- producer side ----

    def emit(self, record: Dict) -> None:
        """Queue a record for every destination that wants it. Never raises."""
        try:
            config = self.config()
            if not config.get("enabled"):
                return
            now = datetime.now(timezone.utc)
            record = {**record, "timestamp": record.get("timestamp") or now.isoformat(timespec="seconds"),
                      "timestamp_ms": int(now.timestamp() * 1000), "product": "tron-dlp"}
            for dest in config.get("destinations", []):
                if not dest.get("enabled", True) or record.get("kind") not in dest.get("record_kinds", []):
                    continue
                if not _severity_at_least(record, dest.get("min_severity", "low")):
                    continue
                self.db.siem_enqueue(dest["id"], record)
        except Exception:
            log.exception("could not queue SIEM record")

    # ---- consumer side ----

    def drain_once(self, batch: int = 200) -> int:
        """Deliver due rows. Returns the number of rows delivered."""
        config = self.config()
        destinations = {d["id"]: d for d in config.get("destinations", [])}
        rows = self.db.siem_due(limit=batch)
        if not rows:
            return 0
        by_dest: Dict[str, List[dict]] = {}
        for row in rows:
            by_dest.setdefault(row["destination"], []).append(row)
        sent = 0
        for dest_id, dest_rows in by_dest.items():
            dest = destinations.get(dest_id)
            if dest is None:
                # Destination was removed from the config: its queued records have nowhere to go.
                for row in dest_rows:
                    self.db.siem_ack(row["id"])
                continue
            if not config.get("enabled") or not dest.get("enabled", True):
                continue
            try:
                self._sender(dest, [r["payload"] for r in dest_rows])
            except Exception as exc:
                self.failed += len(dest_rows)
                reason = f"{type(exc).__name__}: {exc}"[:300]
                log.warning("SIEM delivery to %s failed: %s", dest_id, reason)
                for row in dest_rows:
                    self.db.siem_retry_later(row["id"], int(row["attempts"]) + 1, reason)
                continue
            for row in dest_rows:
                self.db.siem_ack(row["id"])
            sent += len(dest_rows)
            self.delivered += len(dest_rows)
        return sent

    def start(self, interval: float = 5.0) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop():
            while not self._stop.wait(interval):
                try:
                    while self.drain_once() and not self._stop.is_set():
                        pass
                except Exception:
                    log.exception("SIEM forwarder loop error")

        self._thread = threading.Thread(target=loop, name="tron-siem-forwarder", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
