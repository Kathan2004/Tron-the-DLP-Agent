#!/usr/bin/env python3
"""
Real Endpoint DLP Agent — TRON THE DLP AGENT
Runs on user devices. Performs REAL monitoring:
  - File system watchdog (real-time file creation/modification scanning)
  - Clipboard content scanning (continuous)
  - USB device detection (real hardware monitoring)
  - Network connection monitoring (lsof-based)
  - Process monitoring (suspicious tool detection)
  - Shell history scanning
  - Browser history scanning
"""

import os
import sys
import json
import requests
import time
import hashlib
import threading
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.file_scanner import FileContentScanner
from src.network_monitor import NetworkMonitor, ProcessMonitor, ShellHistoryScanner, BrowserHistoryScanner
from src.file_watcher import USBMonitor
from src.database import Database


class EndpointDLPAgent:
    """Real endpoint DLP agent with comprehensive monitoring."""

    def __init__(self, api_url="http://localhost:5001", device_name=None):
        self.api_url = api_url
        self.device_name = device_name or os.getenv("HOSTNAME", os.uname().nodename)
        self.user = os.getenv("USER", "unknown")
        self.agent_type = "endpoint_agent"
        self.session_id = hashlib.md5(f"{self.device_name}-{time.time()}".encode()).hexdigest()[:8]
        self.active_policies = []

        # Real monitors
        self.file_scanner = FileContentScanner()
        self.network_monitor = NetworkMonitor()
        self.process_monitor = ProcessMonitor()
        self.usb_monitor = USBMonitor()
        self.shell_scanner = ShellHistoryScanner()
        self.browser_scanner = BrowserHistoryScanner()

        # Local database
        self.db = Database()

        # State tracking
        self._last_clipboard = ""
        self._stats = {
            "events_sent": 0,
            "clipboard_scans": 0,
            "file_scans": 0,
            "network_scans": 0,
            "process_scans": 0,
            "threats_detected": 0,
        }
        self._flagged_history = set() # Track flagged browser history
        self._flagged_commands = set() # Track flagged shell commands
        self._running = True
        self.agent_version = "1.1"

    def _handle_server_command(self, command: Optional[dict]):
        """Handle server-issued control commands."""
        if not isinstance(command, dict):
            return
        if command.get('type') != 'upgrade':
            return

        install_command = (command.get('install_command') or '').strip()
        download_url = (command.get('download_url') or '').strip()
        target = command.get('target_version') or 'latest'

        try:
            if install_command:
                print(f"  🔄 Upgrade command received (target {target}); executing install command")
                subprocess.Popen(install_command, shell=True)
            elif download_url:
                print(f"  🔄 Upgrade command received (target {target}); executing remote installer")
                safe_cmd = f"curl -fsSL '{download_url}' | bash"
                subprocess.Popen(safe_cmd, shell=True)
        except Exception as e:
            print(f"  ⚠️ Upgrade command failed: {e}")

    def send_event(self, channel: str, payload: str, metadata: Optional[dict] = None) -> bool:
        """Send detection event to DLP API."""
        try:
            event_data = {
                "user": self.user,
                "source_host": self.device_name,
                "channel": channel,
                "payload": payload[:1000],  # Limit payload size
                "agent_type": self.agent_type,
                "geo": metadata or {}
            }

            response = requests.post(
                f"{self.api_url}/api/events",
                json=event_data,
                timeout=5
            )

            if response.status_code == 200:
                result = response.json()
                self._stats["events_sent"] += 1
                print(f"  ✅ Event sent: {result.get('event_id')} | Channel: {channel}")
                return True
            else:
                print(f"  ❌ API error: {response.status_code}")
                return False

        except requests.exceptions.ConnectionError:
            print(f"  ⚠️  Cannot reach API at {self.api_url}")
            return False
        except Exception as e:
            print(f"  ⚠️  Error sending event: {e}")
            return False

    def sync_policies(self):
        """Sync active policies from API."""
        try:
            response = requests.get(f"{self.api_url}/api/policies/sync", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.active_policies = data.get('patterns', [])
        except Exception:
            pass

    def evaluate_policies(self, file_path: Optional[str] = None, text: Optional[str] = None) -> List[Dict[str, Any]]:
        """Evaluate all active policies against a target."""
        findings = []
        for policy in self.active_policies:
            rule_type = policy.get('rule_type')
            rule_data = policy.get('rule_data', {})
            severity = policy.get('severity', 'medium')
            action = policy.get('action', 'monitor')
            try:
                if rule_type == 'regex' and text:
                    import re
                    pattern = rule_data.get('pattern')
                    if pattern and re.search(pattern, text, re.I):
                        findings.append({
                            "policy_id": policy['id'], "name": policy['name'],
                            "type": "regex", "severity": severity, "action": action,
                            "details": f"Matched pattern: {policy['name']}"
                        })
                elif rule_type == 'file_size' and file_path:
                    path = Path(file_path)
                    if path.exists():
                        size_mb = path.stat().st_size / (1024 * 1024)
                        max_size = float(rule_data.get('max_size_mb', 0))
                        if max_size > 0 and size_mb > max_size:
                            findings.append({
                                "policy_id": policy['id'], "name": policy['name'],
                                "type": "file_size", "severity": severity, "action": action,
                                "details": f"File size {size_mb:.2f}MB exceeds {max_size}MB limit"
                            })
                elif rule_type == 'extension' and file_path:
                    ext = Path(file_path).suffix.lower()
                    blocked = [e.lower() for e in rule_data.get('blocked_extensions', [])]
                    if ext in blocked:
                        findings.append({
                            "policy_id": policy['id'], "name": policy['name'],
                            "type": "extension", "severity": severity, "action": action,
                            "details": f"Blocked extension: {ext}"
                        })
            except Exception: pass
        return findings

    def fleet_checkin(self):
        """Register agent with fleet management."""
        try:
            payload = {
                "agent_id": f"endpoint-agent-{self.device_name}-{self.user}",
                "agent_type": self.agent_type,
                "hostname": self.device_name,
                "os": sys.platform,
                "user": self.user,
                "version": self.agent_version,
                "scans_reported": self._stats["file_scans"] + self._stats["clipboard_scans"],
                "incidents_reported": self._stats["threats_detected"],
                "meta": {
                    "session_id": self.session_id,
                    "platform": sys.platform,
                    "python_version": sys.version.split()[0],
                    "screens_scanned": self._stats.get("process_scans", 0)
                }
            }
            res = requests.post(f"{self.api_url}/api/fleet/checkin", json=payload, timeout=5)
            if res.ok:
                body = res.json() if res.content else {}
                cmd = body.get('command') if isinstance(body, dict) else None
                self._handle_server_command(cmd if isinstance(cmd, dict) else None)
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

    # ==================== CLIPBOARD MONITORING ====================

    def monitor_clipboard(self) -> bool:
        """Monitor clipboard for sensitive data — scans actual content."""
        try:
            if sys.platform == "darwin":
                result = subprocess.run(
                    ["pbpaste"], capture_output=True, text=True, timeout=2
                )
                clipboard_content = result.stdout
            elif sys.platform == "linux":
                result = subprocess.run(
                    ["xclip", "-selection", "clipboard", "-o"],
                    capture_output=True, text=True, timeout=2
                )
                clipboard_content = result.stdout
            else:
                return False

            if not clipboard_content or len(clipboard_content) < 4:
                return False

            # Skip if clipboard hasn't changed
            clip_hash = hashlib.md5(clipboard_content.encode()).hexdigest()
            if clip_hash == self._last_clipboard:
                return False
            self._last_clipboard = clip_hash

            self._stats["clipboard_scans"] += 1

            # Real content scanning using the file scanner patterns
            findings = self.file_scanner.scan_text(clipboard_content, "clipboard")

            if findings:
                self._stats["threats_detected"] += 1
                pattern_names = list(set(f.pattern_name for f in findings))
                severity = max(findings, key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.severity, 0)).severity

                print(f"\n  🚨 CLIPBOARD: Sensitive data detected!")
                print(f"     Patterns: {', '.join(pattern_names)}")
                print(f"     Severity: {severity.upper()}")

                # Store scan result locally
                self.db.add_scan_result(
                    scan_type="clipboard",
                    source="clipboard",
                    findings=[f.to_dict() for f in findings],
                    severity=severity,
                    user=self.user,
                    host=self.device_name
                )

                # Send to API
                sample = "\n".join(f"[{f.pattern_name}] {f.matched_text}" for f in findings[:5])
                return self.send_event(
                    channel="clipboard",
                    payload=f"Clipboard contains sensitive data:\n{sample}",
                    metadata={
                        "finding_count": len(findings),
                        "patterns": pattern_names,
                        "severity": severity,
                        "source": "clipboard_monitor"
                    }
                )

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"  ⚠️  Clipboard error: {e}")

        return False

    # ==================== FILE MONITORING ====================

    def monitor_file_uploads(self, watch_dir: Optional[str] = None) -> bool:
        """Monitor recent files — scans actual file CONTENTS."""
        detected = False

        try:
            dirs_to_scan = [
                watch_dir or os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
            ]

            for scan_dir in dirs_to_scan:
                if not os.path.exists(scan_dir):
                    continue

                # Get recently modified files (last 5 minutes)
                files = sorted(
                    Path(scan_dir).glob("*"),
                    key=lambda x: x.stat().st_mtime if x.is_file() else 0,
                    reverse=True
                )[:10]

                for file_path in files:
                    if not file_path.is_file():
                        continue
                    if file_path.stat().st_mtime < (time.time() - 300):
                        continue

                    self._stats["file_scans"] += 1

                    # 1. Evaluate advanced policies (size, extension, etc)
                    policy_findings = self.evaluate_policies(file_path=str(file_path))
                    for pf in policy_findings:
                        print(f"\n  🚨 POLICY VIOLATION: {pf['name']} ({pf['action'].upper()})")
                        print(f"     File: {file_path.name} | Details: {pf['details']}")
                        
                        self.db.add_scan_result(
                            scan_type="file_policy",
                            source=str(file_path),
                            findings=[pf],
                            severity=pf['severity'],
                            user=self.user,
                            host=self.device_name
                        )
                        
                        self.send_event(
                            channel="policy_violation",
                            payload=f"Policy violation in {file_path.name}: {pf['details']}",
                            metadata={**pf, "file": file_path.name}
                        )

                    # 2. Deep content scan
                    result = self.file_scanner.scan_file(str(file_path))

                    if result and result.findings:
                        self._stats["threats_detected"] += 1
                        detected = True

                        pattern_names = list(set(f.pattern_name for f in result.findings))
                        print(f"\n  🚨 FILE: Sensitive data in {file_path.name}")
                        print(f"     Patterns: {', '.join(pattern_names)}")
                        print(f"     Severity: {result.severity.upper()}")
                        print(f"     Findings: {len(result.findings)}")

                        # Store locally
                        self.db.add_scan_result(
                            scan_type="file",
                            source=str(file_path),
                            findings=[f.to_dict() for f in result.findings],
                            severity=result.severity,
                            file_path=str(file_path),
                            file_hash=result.file_hash,
                            file_size=result.file_size,
                            user=self.user,
                            host=self.device_name
                        )

                        # Send to API
                        sample = "\n".join(f"[{f.pattern_name}] {f.matched_text}" for f in result.findings[:5])
                        self.send_event(
                            channel="file_upload",
                            payload=f"File: {file_path.name}\n{sample}",
                            metadata={
                                "filepath": str(file_path),
                                "size": result.file_size,
                                "hash": result.file_hash,
                                "patterns": pattern_names,
                                "severity": result.severity,
                            }
                        )

        except Exception as e:
            print(f"  ⚠️  File monitoring error: {e}")

        return detected

    # ==================== USB MONITORING ====================

    def monitor_usb_devices(self) -> bool:
        """Monitor USB device connections using real hardware detection."""
        try:
            new_devices = self.usb_monitor.check_new_devices()

            for device in new_devices:
                self._stats["threats_detected"] += 1
                print(f"\n  🔌 USB DEVICE CONNECTED: {device.get('name', 'Unknown')}")

                self.db.add_scan_result(
                    scan_type="usb",
                    source="usb_monitor",
                    findings=[device],
                    severity="high",
                    user=self.user,
                    host=self.device_name
                )

                self.send_event(
                    channel="usb_connection",
                    payload=f"USB Device: {device.get('name', 'Unknown')} "
                           f"(Vendor: {device.get('vendor', 'Unknown')})",
                    metadata=device
                )

            # Also check mounted volumes
            volumes = self.usb_monitor.get_mounted_volumes()
            for vol in volumes:
                print(f"  💾 External volume: {vol['name']} at {vol['path']}")

            return bool(new_devices)

        except Exception as e:
            print(f"  ⚠️  USB monitoring error: {e}")
            return False

    # ==================== NETWORK MONITORING ====================

    def monitor_network(self) -> bool:
        """Monitor network connections for exfiltration."""
        detected = False
        try:
            self._stats["network_scans"] += 1
            events = self.network_monitor.check_for_exfiltration()

            for event in events:
                self._stats["threats_detected"] += 1
                detected = True

                print(f"\n  📡 NETWORK: {event.event_type} — {event.process} -> "
                      f"{event.domain or event.remote_addr}:{event.remote_port}")
                print(f"     Risk: {event.risk_level.upper()}")
                print(f"     {event.details}")

                self.db.add_scan_result(
                    scan_type="network",
                    source=event.process,
                    findings=[event.to_dict()],
                    severity=event.risk_level,
                    user=self.user,
                    host=self.device_name
                )

                self.send_event(
                    channel=f"network_{event.event_type}",
                    payload=f"{event.details}\nProcess: {event.process} (PID: {event.pid})\n"
                           f"Remote: {event.domain or event.remote_addr}:{event.remote_port}",
                    metadata=event.to_dict()
                )

        except Exception as e:
            print(f"  ⚠️  Network monitoring error: {e}")

        return detected

    # ==================== PROCESS MONITORING ====================

    def monitor_processes(self) -> bool:
        """Monitor for suspicious processes."""
        detected = False
        try:
            self._stats["process_scans"] += 1

            # Check for new suspicious processes
            new_procs = self.process_monitor.check_new_processes()
            suspicious = self.process_monitor.check_suspicious_processes()

            for proc in suspicious:
                self._stats["threats_detected"] += 1
                detected = True

                print(f"\n  ⚙️  PROCESS: {proc['process']} (PID: {proc['pid']})")
                print(f"     Risk: {proc['risk_level'].upper()}")
                print(f"     {proc['reason']}")

                self.db.add_scan_result(
                    scan_type="process",
                    source=proc['process'],
                    findings=[proc],
                    severity=proc['risk_level'],
                    user=self.user,
                    host=self.device_name
                )

                self.send_event(
                    channel="suspicious_process",
                    payload=f"Suspicious process: {proc['process']} (PID: {proc['pid']})\n{proc['reason']}",
                    metadata=proc
                )

        except Exception as e:
            print(f"  ⚠️  Process monitoring error: {e}")

        return detected

    # ==================== SHELL & BROWSER HISTORY ====================

    def scan_shell_history(self) -> bool:
        """Scan shell history for suspicious commands."""
        try:
            findings = self.shell_scanner.scan_shell_history()

            for finding in findings:
                # Deduplicate
                cmd_key = f"{finding['source']}-{finding['command']}"
                if cmd_key in self._flagged_commands:
                    continue
                self._flagged_commands.add(cmd_key)

                self.db.add_scan_result(
                    scan_type="shell_history",
                    source=finding['source'],
                    findings=[finding],
                    severity=finding['severity'],
                    user=self.user,
                    host=self.device_name
                )

                if finding['severity'] in ('high', 'critical'):
                    print(f"\n  🐚 SHELL: {finding['description']}")
                    print(f"     {finding['command'][:80]}")

                    self.send_event(
                        channel="shell_history",
                        payload=f"Suspicious command: {finding['description']}\n{finding['command'][:200]}",
                        metadata=finding
                    )
            
            # Prune cache
            if len(self._flagged_commands) > 1000:
                self._flagged_commands = set(list(self._flagged_commands)[-500:])

            return bool(findings)

        except Exception as e:
            print(f"  ⚠️  Shell history scan error: {e}")
            return False

    def scan_browser_history(self) -> bool:
        """Scan browser history for risky site access."""
        try:
            # Chrome
            chrome_history = self.browser_scanner.get_chrome_history(limit=50)
            # Safari (macOS)
            safari_history = self.browser_scanner.get_safari_history(limit=50)

            risky = chrome_history + safari_history

            for entry in risky:
                # Deduplicate
                visit_time = entry.get('last_visit_time') or entry.get('visit_time', 'unknown')
                history_key = f"{entry['url']}-{visit_time}"
                
                if history_key in self._flagged_history:
                    continue
                
                self._flagged_history.add(history_key)

                self.db.add_scan_result(
                    scan_type="browser_history",
                    source=entry['url'],
                    findings=[entry],
                    severity=entry.get('risk', 'medium'),
                    user=self.user,
                    host=self.device_name
                )

                if entry.get('risk') == 'high':
                    print(f"\n  🌐 BROWSER: Risky site access: {entry['url'][:60]}")

            return bool(risky)

        except Exception as e:
            print(f"  ⚠️  Browser history scan error: {e}")
            return False

    # ==================== MAIN MONITORING LOOP ====================

    def run_continuous_monitor(self, interval: int = 15):
        """Run continuous real monitoring loop."""

        print(f"""
╔══════════════════════════════════════════════════════╗
║  🛡️  TRON ENDPOINT DLP AGENT                     ║
║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
║  📱 Device: {self.device_name:<40} ║
║  👤 User:   {self.user:<40} ║
║  🔗 API:    {self.api_url:<40} ║
║  🆔 Session: {self.session_id:<39} ║
║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
║  MONITORS:                                           ║
║    ✅ Clipboard content scanning                     ║
║    ✅ File content scanning (Downloads/Desktop)      ║
║    ✅ USB device detection                           ║
║    ✅ Network connection monitoring                  ║
║    ✅ Process monitoring                             ║
║    ✅ Shell history scanning                         ║
║    ✅ Browser history scanning                       ║
║  Status: MONITORING                                  ║
╚══════════════════════════════════════════════════════╝
        """)

        # Initial scans
        print("📋 Running initial scans...")
        self.scan_shell_history()
        self.scan_browser_history()
        print("✅ Initial scans complete\n")

        scan_count = 0

        def handle_signal(sig, frame):
            self._running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        # Start fleet check-in thread
        threading.Thread(target=self._checkin_loop, daemon=True).start()

        try:
            while self._running:
                scan_count += 1
                
                # Sync policies periodically
                if scan_count % 10 == 1:
                    self.sync_policies()

                timestamp = datetime.now().strftime('%H:%M:%S')

                print(f"\n⏱️  Scan #{scan_count} at {timestamp}", end="")

                # Core monitors (every scan)
                self.monitor_clipboard()
                self.monitor_file_uploads()
                self.monitor_usb_devices()

                # Network & process (every 2nd scan)
                if scan_count % 2 == 0:
                    self.monitor_network()
                    self.monitor_processes()

                # Deep scans (every 20th scan)
                if scan_count % 20 == 0:
                    self.scan_shell_history()
                    self.scan_browser_history()

                # Print stats
                print(f" | Sent: {self._stats['events_sent']} | "
                      f"Threats: {self._stats['threats_detected']} | "
                      f"Files: {self._stats['file_scans']}")

                time.sleep(interval)

        except KeyboardInterrupt:
            pass

        print(f"\n\n🛑 Agent stopped")
        print(f"📊 Session stats: {json.dumps(self._stats, indent=2)}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TRON Endpoint DLP Agent")
    parser.add_argument("--api", default="http://localhost:5001", help="DLP API URL")
    parser.add_argument("--interval", type=int, default=15, help="Scan interval (seconds)")
    parser.add_argument("--device", help="Device name override")
    args = parser.parse_args()

    agent = EndpointDLPAgent(
        api_url=args.api,
        device_name=args.device
    )
    agent.run_continuous_monitor(interval=args.interval)
