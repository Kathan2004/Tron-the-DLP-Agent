"""Agent client (enrollment, key storage, rotation, offline spool) and OS-specific parsers."""

import json
import os
import stat

import pytest
import requests

from src import platform_support as ps
from src.agent_client import AgentClient, TransportRefused, safe_agent_id


class FlaskSession:
    """requests.Session look-alike that routes to the Flask test client."""

    def __init__(self, client):
        self.client = client
        self.down = False
        self.status_override = None

    def _wrap(self, r):
        class Res:
            status_code = r.status_code
            ok = 200 <= r.status_code < 300
            content = r.data

            @staticmethod
            def json():
                return r.get_json()
        return Res

    def _path(self, url):
        return url.split("://", 1)[1].split("/", 1)[1].join(["/", ""])

    def post(self, url, json=None, headers=None, timeout=None):
        if self.down:
            raise requests.ConnectionError("down")
        r = self.client.post(self._path(url), json=json, headers=headers or {})
        return self._wrap(r)

    def get(self, url, params=None, headers=None, timeout=None):
        if self.down:
            raise requests.ConnectionError("down")
        return self._wrap(self.client.get(self._path(url), query_string=params, headers=headers or {}))


EVENT = {"agent_type": "endpoint", "source_host": "h1", "user": "alice", "channel": "clipboard",
         "payload": "ssn 536-22-1234"}


def make(client, tmp_path, agent_id="endpoint-agent-h1-alice"):
    session = FlaskSession(client)
    return AgentClient("http://localhost:5001", agent_id, "endpoint_agent", "h1",
                       state_dir=tmp_path / "state", session=session), session


def test_enrolls_once_and_persists_key_privately(client, tmp_path, monkeypatch):
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    monkeypatch.setenv("TRON_AGENT_AUTH", "strict")
    agent, _ = make(client, tmp_path)
    assert agent.post("/api/events", EVENT).status_code == 200 and agent.enrolled
    key_file = tmp_path / "state" / "endpoint-agent-h1-alice.key.json"
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    # A restarted agent reuses the stored key and never re-enrolls (which would be refused).
    monkeypatch.delenv("TRON_AGENT_TOKEN")
    again, _ = make(client, tmp_path)
    assert again.enrolled and "X-Tron-Agent-Token" not in again.headers()
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    assert again.post("/api/events", EVENT).status_code == 200


def test_server_requested_key_rotation(client, tmp_path, monkeypatch, auth):
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    agent, _ = make(client, tmp_path)
    agent.post("/api/fleet/checkin", {"agent_id": agent.agent_id, "hostname": "h1"})
    before = agent.headers()["X-Tron-Agent-Key"]
    assert client.post(f"/api/fleet/agents/{agent.agent_id}/key/rotation", headers=auth).status_code == 200
    command = agent.post("/api/fleet/checkin", {"hostname": "h1"}).json()["command"]
    assert agent.handle_command(command) is True
    after = agent.headers()["X-Tron-Agent-Key"]
    assert after != before
    monkeypatch.setenv("TRON_AGENT_AUTH", "strict")
    assert agent.post("/api/events", EVENT).status_code == 200


def test_offline_spool_is_sealed_and_replayed_in_order(client, tmp_path):
    agent, session = make(client, tmp_path)
    session.down = True
    for i in range(3):
        assert agent.post("/api/events", {**EVENT, "payload": f"ssn 536-22-123{i}"}, spool=True) is None
    assert agent.spool_size() == 3
    spool = (tmp_path / "state" / f"{agent.agent_id}.spool").read_text()
    assert "536-22" not in spool
    assert stat.S_IMODE((tmp_path / "state" / f"{agent.agent_id}.spool").stat().st_mode) == 0o600

    session.down = False
    assert agent.post("/api/events", {**EVENT, "payload": "ssn 536-22-1239"}, spool=True).status_code == 200
    assert agent.spool_size() == 0
    samples = [e["payload_sample"] for e in client.db.get_all_events(limit=10)]
    assert len(samples) == 4 and any("536-22-1230" in s for s in samples)


def test_spool_survives_partial_outage(client, tmp_path):
    agent, session = make(client, tmp_path)
    session.down = True
    agent.post("/api/events", EVENT, spool=True)
    assert agent.flush_spool() == 0 and agent.spool_size() == 1


def test_plain_http_to_remote_host_is_refused(tmp_path, monkeypatch):
    with pytest.raises(TransportRefused):
        AgentClient("http://dlp.example.com", "a-1", "endpoint_agent", state_dir=tmp_path)
    AgentClient("https://dlp.example.com", "a-1", "endpoint_agent", state_dir=tmp_path)
    monkeypatch.setenv("TRON_ALLOW_INSECURE_API", "1")
    AgentClient("http://dlp.example.com", "a-1", "endpoint_agent", state_dir=tmp_path)


def test_agent_ids_are_normalised_for_windows_identities():
    from src.agent_auth import valid_agent_id
    agent_id = safe_agent_id("endpoint-agent", "DESKTOP-7Q2", "CORP\\Jane Doe")
    assert agent_id == "endpoint-agent-DESKTOP-7Q2-CORP-Jane-Doe" and valid_agent_id(agent_id)


# ---------------------------------------------------------------- OS parsers (captured output)

NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1040
  TCP    192.168.1.20:50112     140.82.112.4:443       ESTABLISHED     8812
  TCP    [fe80::1%5]:50200      [2606:4700::6810:1]:443  ESTABLISHED   9120
"""
TASKLIST = '''"chrome.exe","8812","Console","1","412,004 K"
"rclone.exe","9120","Console","1","31,220 K"
"System Idle Process","0","Services","0","8 K"
'''


def test_windows_netstat_and_tasklist_parsing():
    procs = ps.parse_tasklist(TASKLIST)
    assert {p["process_name"] for p in procs} == {"chrome.exe", "rclone.exe", "System Idle Process"}
    conns = ps.parse_netstat(NETSTAT, {p["pid"]: p["process_name"] for p in procs})
    assert len(conns) == 2
    assert conns[0] == {"process": "chrome.exe", "pid": 8812, "user": "", "local_addr": "192.168.1.20",
                        "remote_addr": "140.82.112.4", "remote_port": 443, "domain": "", "state": "ESTABLISHED"}
    assert conns[1]["process"] == "rclone.exe" and conns[1]["remote_addr"] == "2606:4700::6810:1"


def test_windows_usb_and_volume_parsing():
    usb = ps.parse_windows_usb(json.dumps([
        {"FriendlyName": "USB Mass Storage Device", "Manufacturer": "Compatible USB storage device",
         "InstanceId": "USB\\VID_0781&PID_5581\\4C530001230415118452"},
        {"FriendlyName": "Intel Management Engine", "Manufacturer": "Intel", "InstanceId": "PCI\\VEN_8086"},
    ]))
    assert usb == [{"name": "USB Mass Storage Device", "vendor": "Compatible USB storage device",
                    "vendor_id": "0781", "product_id": "5581", "serial": "4C530001230415118452"}]
    # PowerShell emits a bare object, not a list, for a single result.
    vols = ps.parse_windows_volumes(json.dumps({"DeviceID": "E:", "VolumeName": "KINGSTON"}))
    assert vols == [{"name": "KINGSTON", "path": "E:\\", "type": "external"}]
    assert ps.parse_windows_usb("") == [] and ps.parse_windows_volumes("not json") == []


def test_linux_usb_enumeration(tmp_path):
    for name, cls, product in (("1-1", "00", "Cruzer Blade"), ("usb1", "09", "xHCI Host Controller")):
        dev = tmp_path / name
        dev.mkdir()
        (dev / "idVendor").write_text("0781\n")
        (dev / "idProduct").write_text("5567\n")
        (dev / "bDeviceClass").write_text(cls + "\n")
        (dev / "product").write_text(product + "\n")
        (dev / "manufacturer").write_text("SanDisk\n")
    devices = ps.usb_devices_linux(str(tmp_path))
    assert [d["name"] for d in devices] == ["Cruzer Blade"]  # hubs are skipped


def test_agents_import_on_this_platform():
    import importlib
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agents"))
    for module in ("endpoint_agent", "network_agent", "web_agent"):
        importlib.import_module(module)
