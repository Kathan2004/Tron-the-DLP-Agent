#!/usr/bin/env python3
"""
Real Network DLP Agent — TRON THE DLP AGENT
Monitors actual network traffic for data exfiltration.
No simulation — all real monitoring using native OS tools.
"""

import os
import sys
import json
import requests
import re
import time
import signal
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.network_monitor import NetworkMonitor, ProcessMonitor, BrowserHistoryScanner
from src.file_scanner import FileContentScanner
from src.database import Database


class NetworkDLPAgent:
    """Real network traffic monitor for data exfiltration detection."""

    def __init__(self, api_url="http://localhost:5001"):
        self.api_url = api_url
        self.agent_type = "network_agent"
        self.user = os.getenv("USER", "unknown")
        self.host = os.getenv("HOSTNAME", os.uname().nodename)
        self.session_id = hashlib.md5(f"net-{time.time()}".encode()).hexdigest()[:8]

        # Real monitors
        self.network_monitor = NetworkMonitor()
        self.process_monitor = ProcessMonitor()
        self.browser_scanner = BrowserHistoryScanner()
        self.file_scanner = FileContentScanner()
        self.db = Database()

        self._running = True
        self._stats = {
            "scans": 0,
            "connections_checked": 0,
            "alerts_sent": 0,
            "exfiltration_attempts": 0,
        }
        self.agent_version = "1.1"

    def _handle_server_command(self, command):
        if not isinstance(command, dict):
            return
        if command.get('type') != 'upgrade':
            return
        install_command = (command.get('install_command') or '').strip()
        download_url = (command.get('download_url') or '').strip()
        try:
            if install_command:
                subprocess.Popen(install_command, shell=True)
            elif download_url:
                subprocess.Popen(f"curl -fsSL '{download_url}' | bash", shell=True)
        except Exception as e:
            print(f"  ⚠️ Upgrade command failed: {e}")

    def send_event(self, user: str, host: str, channel: str, payload: str, metadata: Optional[dict] = None) -> bool:
        """Send network detection to DLP API."""
        try:
            event_data = {
                "user": user,
                "source_host": host,
                "channel": channel,
                "payload": payload[:1000],
                "agent_type": self.agent_type,
                "geo": metadata or {}
            }

            response = requests.post(
                f"{self.api_url}/api/events",
                json=event_data,
                timeout=5
            )

            if response.status_code == 200:
                self._stats["alerts_sent"] += 1
                result = response.json()
                print(f"  ✅ Event sent: {result.get('event_id')} | {channel}")
                return True

        except requests.exceptions.ConnectionError:
            print(f"  ⚠️  Cannot reach API at {self.api_url}")
        except Exception as e:
            print(f"  ⚠️  Error: {e}")

        return False

    def fleet_checkin(self):
        """Register agent with fleet management."""
        try:
            payload = {
                "agent_id": f"network-agent-{self.host}-{self.user}",
                "agent_type": self.agent_type,
                "hostname": self.host,
                "os": sys.platform,
                "user": self.user,
                "version": self.agent_version,
                "scans_reported": self._stats["scans"],
                "incidents_reported": self._stats["exfiltration_attempts"],
                "meta": {
                    "session_id": self.session_id,
                    "platform": sys.platform,
                    "python_version": sys.version.split()[0]
                }
            }
            res = requests.post(f"{self.api_url}/api/fleet/checkin", json=payload, timeout=5)
            if res.ok:
                body = res.json() if res.content else {}
                self._handle_server_command(body.get('command'))
        except Exception:
            pass

    def _checkin_loop(self):
        """Threaded check-in loop."""
        while self._running:
            self.fleet_checkin()
            # Wait 60 seconds between check-ins
            for _ in range(60):
                if not self._running: break
                time.sleep(1)

    def monitor_connections(self) -> int:
        """Monitor active network connections for exfiltration."""
        events = self.network_monitor.check_for_exfiltration()
        self._stats["scans"] += 1

        for event in events:
            self._stats["exfiltration_attempts"] += 1

            print(f"\n  🚨 [{event.risk_level.upper()}] {event.event_type}")
            print(f"     Process: {event.process} (PID: {event.pid})")
            print(f"     Target: {event.domain or event.remote_addr}:{event.remote_port}")
            print(f"     {event.details}")

            # Store locally
            self.db.add_scan_result(
                scan_type="network",
                source=event.process,
                findings=[event.to_dict()],
                severity=event.risk_level,
                user=self.user,
                host=self.host
            )

            # Send to API
            self.send_event(
                user=self.user,
                host=self.host,
                channel=f"network_{event.event_type}",
                payload=f"{event.details}\n"
                       f"Process: {event.process} (PID: {event.pid})\n"
                       f"Target: {event.domain or event.remote_addr}:{event.remote_port}",
                metadata=event.to_dict()
            )

        return len(events)

    def monitor_data_volume(self):
        """Monitor outbound data volume for anomalies."""
        volume = self.network_monitor.check_outbound_data_volume()
        if volume:
            bytes_out = volume.get("bytes_out", 0)
            # Alert if outbound exceeds threshold (100MB in one check)
            if bytes_out > 100_000_000:
                print(f"\n  📊 HIGH OUTBOUND: {bytes_out / 1_000_000:.1f} MB")
                self.send_event(
                    user=self.user,
                    host=self.host,
                    channel="high_data_volume",
                    payload=f"High outbound data volume: {bytes_out / 1_000_000:.1f} MB",
                    metadata=volume
                )

    def monitor_listening_ports(self):
        """Check for unexpected listening ports (backdoors)."""
        listeners = self.network_monitor.get_listening_ports()

        # Known safe ports
        safe_processes = {"python3", "python", "node", "nginx", "httpd", "postgres", "mongod"}

        for listener in listeners:
            process = listener.get("process", "").lower()
            if process not in safe_processes:
                addr = listener.get("address", "")
                if "0.0.0.0" in addr or "*:" in addr:
                    print(f"\n  ⚠️  LISTENING: {listener['process']} on {addr}")

                    self.db.add_scan_result(
                        scan_type="network",
                        source=listener['process'],
                        findings=[listener],
                        severity="medium",
                        user=self.user,
                        host=self.host
                    )

    def monitor_browser_activity(self):
        """Check browser history for risky site access."""
        chrome = self.browser_scanner.get_chrome_history(limit=20)
        safari = self.browser_scanner.get_safari_history(limit=20)

        risky = [e for e in (chrome + safari) if e.get('risk') == 'high']

        for entry in risky[:3]:
            print(f"\n  🌐 RISKY SITE: {entry['url'][:60]}")
            self.send_event(
                user=self.user,
                host=self.host,
                channel="risky_website",
                payload=f"Access to risky site: {entry['url']}",
                metadata=entry
            )

    def detect_email_exfiltration(self, email_content: str, sender: str) -> bool:
        """Detect sensitive data in email using real content scanning."""
        findings = self.file_scanner.scan_text(email_content, f"email from {sender}")

        if findings:
            pattern_names = list(set(f.pattern_name for f in findings))
            print(f"\n  🚨 EMAIL: Sensitive data from {sender}")
            print(f"     Patterns: {', '.join(pattern_names)}")

            self.db.add_scan_result(
                scan_type="email",
                source=sender,
                findings=[f.to_dict() for f in findings],
                severity=max(findings, key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.severity, 0)).severity,
                user=sender,
                host=self.host
            )

            return self.send_event(
                user=sender,
                host="MAIL-SERVER",
                channel="email",
                payload=f"Email from {sender} contains: {', '.join(pattern_names)}\n"
                       f"Findings: {len(findings)}",
                metadata={"patterns": pattern_names, "finding_count": len(findings)}
            )

        return False

    def detect_cloud_upload(self, user: str, filename: str, destination: str) -> bool:
        """Detect sensitive file uploads to cloud — scan file contents."""
        # Try to scan the actual file
        result = self.file_scanner.scan_file(filename)

        if result and result.findings:
            pattern_names = list(set(f.pattern_name for f in result.findings))
            print(f"\n  🚨 CLOUD UPLOAD: {user} -> {destination}")
            print(f"     File: {filename}")
            print(f"     Patterns: {', '.join(pattern_names)}")

            return self.send_event(
                user=user,
                host="CLOUD-ENDPOINT",
                channel=f"cloud_{destination}",
                payload=f"Cloud upload: {filename} to {destination}\n"
                       f"Sensitive: {', '.join(pattern_names)}",
                metadata={
                    "destination": destination,
                    "patterns": pattern_names,
                    "file_hash": result.file_hash,
                }
            )

        return False

    def detect_http_exfiltration(self, user: str, host: str, request_body: str, destination: str) -> bool:
        """Detect sensitive data in HTTP POST — real content scanning."""
        findings = self.file_scanner.scan_text(request_body, f"HTTP to {destination}")

        if findings:
            pattern_names = list(set(f.pattern_name for f in findings))
            print(f"\n  🚨 HTTP EXFILTRATION: {user} -> {destination}")

            return self.send_event(
                user=user,
                host=host,
                channel="http_upload",
                payload=f"HTTP POST to {destination}\nPatterns: {', '.join(pattern_names)}",
                metadata={
                    "destination": destination,
                    "patterns": pattern_names,
                }
            )

        return False

    def run_continuous_monitor(self, interval: int = 20):
        """Run continuous real network monitoring."""

        print(f"""
╔══════════════════════════════════════════════════════╗
║  🌐 TRON NETWORK DLP AGENT                      ║
║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
║  📱 Host:    {self.host:<39} ║
║  👤 User:    {self.user:<39} ║
║  🔗 API:     {self.api_url:<39} ║
║  🆔 Session: {self.session_id:<39} ║
║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
║  MONITORS:                                           ║
║    ✅ Active connection monitoring (lsof)            ║
║    ✅ Cloud storage detection                        ║
║    ✅ Suspicious port detection                      ║
║    ✅ SSH tunnel detection                           ║
║    ✅ Data volume monitoring                         ║
║    ✅ Listening port detection                       ║
║    ✅ Browser history scanning                       ║
║  Status: MONITORING                                  ║
╚══════════════════════════════════════════════════════╝
        """)

        scan_count = 0

        def handle_signal(sig, frame):
            self._running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        import threading
        # Start fleet check-in thread
        threading.Thread(target=self._checkin_loop, daemon=True).start()

        try:
            while self._running:
                scan_count += 1
                timestamp = datetime.now().strftime('%H:%M:%S')

                print(f"\n⏱️  Network scan #{scan_count} at {timestamp}", end="")

                # Connection monitoring (every scan)
                alert_count = self.monitor_connections()

                # Data volume check (every scan)
                self.monitor_data_volume()

                # Listening ports (every 5th scan)
                if scan_count % 5 == 0:
                    self.monitor_listening_ports()

                # Browser history (every 30th scan)
                if scan_count % 30 == 0:
                    self.monitor_browser_activity()

                # Stats
                conns = len(self.network_monitor.get_active_connections())
                self._stats["connections_checked"] += conns
                print(f" | Connections: {conns} | "
                      f"Alerts: {self._stats['alerts_sent']} | "
                      f"Exfil: {self._stats['exfiltration_attempts']}")

                time.sleep(interval)

        except KeyboardInterrupt:
            pass

        print(f"\n\n🛑 Network agent stopped")
        print(f"📊 Stats: {json.dumps(self._stats, indent=2)}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TRON Network DLP Agent")
    parser.add_argument("--api", default="http://localhost:5001", help="DLP API URL")
    parser.add_argument("--interval", type=int, default=20, help="Scan interval (seconds)")
    args = parser.parse_args()

    agent = NetworkDLPAgent(api_url=args.api)
    agent.run_continuous_monitor(interval=args.interval)
