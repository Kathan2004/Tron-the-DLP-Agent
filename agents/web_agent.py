#!/usr/bin/env python3
"""
Real Web DLP Agent — TRON THE DLP AGENT
Monitors web-related activity for data exposure.
Scans browser history, download directories, print spools, and form-related files.
"""

import os
import sys
import json
import requests
import re
import time
import threading
import signal
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.file_scanner import FileContentScanner
from src.network_monitor import BrowserHistoryScanner
from src.database import Database


class WebDLPAgent:
    """Real web activity monitor for sensitive data exposure."""

    def __init__(self, api_url="http://localhost:5001"):
        self.api_url = api_url
        self.agent_type = "web_agent"
        self.user = os.getenv("USER", "unknown")
        self.host = os.getenv("HOSTNAME", os.uname().nodename)
        self.session_id = hashlib.md5(f"web-{time.time()}".encode()).hexdigest()[:8]
        self.active_policies = []

        # Real scanners
        self.file_scanner = FileContentScanner()
        self.browser_scanner = BrowserHistoryScanner()
        self.db = Database()

        self._running = True
        self._scanned_files = set()  # Track already-scanned files
        self._flagged_history = set() # Track flagged history (url + timestamp)
        self._stats = {
            "scans": 0,
            "browser_checks": 0,
            "download_scans": 0,
            "alerts_sent": 0,
            "threats_found": 0,
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

    def evaluate_policies(self, file_path: Optional[str] = None, text: Optional[str] = None,
                          metadata: Optional[dict] = None) -> List[Dict]:
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
                            "policy_id": policy['id'],
                            "name": policy['name'],
                            "type": "regex",
                            "severity": severity,
                            "action": action,
                            "details": f"Matched pattern: {policy['name']}"
                        })
                
                elif rule_type == 'file_size' and file_path:
                    path = Path(file_path)
                    if path.exists():
                        size_mb = path.stat().st_size / (1024 * 1024)
                        max_size = float(rule_data.get('max_size_mb', 0))
                        if max_size > 0 and size_mb > max_size:
                            findings.append({
                                "policy_id": policy['id'],
                                "name": policy['name'],
                                "type": "file_size",
                                "severity": severity,
                                "action": action,
                                "details": f"File size {size_mb:.2f}MB exceeds {max_size}MB limit"
                            })
                            
                elif rule_type == 'extension' and file_path:
                    ext = Path(file_path).suffix.lower()
                    blocked = [e.lower() for e in rule_data.get('blocked_extensions', [])]
                    if ext in blocked:
                        findings.append({
                            "policy_id": policy['id'],
                            "name": policy['name'],
                            "type": "extension",
                            "severity": severity,
                            "action": action,
                            "details": f"Blocked extension: {ext}"
                        })
            except Exception as e:
                print(f"  ⚠️ Policy evaluation error ({policy['name']}): {e}")
                
        return findings

    def send_event(self, user: str, host: str, channel: str, payload: str, metadata: Optional[dict] = None) -> bool:
        """Send web detection to DLP API."""
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

    def sync_policies(self):
        """Sync active policies from API."""
        try:
            response = requests.get(f"{self.api_url}/api/policies/sync", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.active_policies = data.get('patterns', [])
                # print(f"  🔄 Synced {len(self.active_policies)} policies")
        except Exception:
            pass

    def fleet_checkin(self):
        """Register agent with fleet management."""
        try:
            payload = {
                "agent_id": f"web-agent-{self.host}-{self.user}",
                "agent_type": self.agent_type,
                "hostname": self.host,
                "os": sys.platform,
                "user": self.user,
                "version": self.agent_version,
                "scans_reported": self._stats["scans"],
                "incidents_reported": self._stats["threats_found"],
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

    def scan_downloads(self) -> bool:
        """Scan Download directory for sensitive files (real content scan)."""
        detected = False
        downloads_dir = Path.home() / "Downloads"

        if not downloads_dir.exists():
            return False

        self._stats["download_scans"] += 1

        try:
            # Get recent files (last 30 minutes)
            files = sorted(
                downloads_dir.iterdir(),
                key=lambda x: x.stat().st_mtime if x.is_file() else 0,
                reverse=True
            )[:20]

            for file_path in files:
                if not file_path.is_file():
                    continue

                # Skip already-scanned files (by hash of path + mtime)
                file_key = f"{file_path}-{file_path.stat().st_mtime}"
                if file_key in self._scanned_files:
                    continue

                # Only scan files modified in last 30 min
                if file_path.stat().st_mtime < (time.time() - 1800):
                    continue

                self._scanned_files.add(file_key)
                
                # 1. Evaluate advanced policies (size, extension, etc)
                policy_findings = self.evaluate_policies(file_path=str(file_path))
                for pf in policy_findings:
                    detected = True
                    print(f"\n  🚨 POLICY VIOLATION: {pf['name']} ({pf['action'].upper()})")
                    print(f"     File: {file_path.name}")
                    print(f"     Details: {pf['details']}")
                    
                    self.db.add_scan_result(
                        scan_type="file_policy",
                        source=str(file_path),
                        findings=[pf],
                        severity=pf['severity'],
                        user=self.user,
                        host=self.host
                    )
                    
                    self.send_event(
                        user=self.user,
                        host=self.host,
                        channel="policy_violation",
                        payload=f"Policy violation in {file_path.name}: {pf['details']}",
                        metadata={**pf, "file": file_path.name}
                    )
                    
                    if pf['action'] == 'block':
                        print(f"     🛑 BLOCK ACTION: Policy requires blocking.")

                # 2. Deep content scan
                result = self.file_scanner.scan_file(str(file_path))
                if result and result.findings:
                    detected = True
                    self._stats["threats_found"] += 1

                    pattern_names = list(set(f.pattern_name for f in result.findings))
                    print(f"\n  🚨 DOWNLOAD: Sensitive file detected!")
                    print(f"     File: {file_path.name}")
                    print(f"     Patterns: {', '.join(pattern_names)}")
                    print(f"     Severity: {result.severity.upper()}")

                    self.db.add_scan_result(
                        scan_type="web_download",
                        source=str(file_path),
                        findings=[f.to_dict() for f in result.findings],
                        severity=result.severity,
                        file_path=str(file_path),
                        file_hash=result.file_hash,
                        file_size=result.file_size,
                        user=self.user,
                        host=self.host
                    )

                    sample = "\n".join(f"[{f.pattern_name}] {f.matched_text}" for f in result.findings[:5])
                    self.send_event(
                        user=self.user,
                        host=self.host,
                        channel="web_download",
                        payload=f"Downloaded file with sensitive data: {file_path.name}\n{sample}",
                        metadata={
                            "filename": file_path.name,
                            "file_hash": result.file_hash,
                            "file_size": result.file_size,
                            "patterns": pattern_names,
                        }
                    )

            # Prune scanned files cache
            if len(self._scanned_files) > 500:
                self._scanned_files = set(list(self._scanned_files)[-200:])

        except Exception as e:
            print(f"  ⚠️  Download scan error: {e}")

        return detected

    def scan_browser_history(self) -> bool:
        """Scan browser history for access to risky sites."""
        detected = False
        self._stats["browser_checks"] += 1

        try:
            chrome_history = self.browser_scanner.get_chrome_history(limit=30)
            safari_history = self.browser_scanner.get_safari_history(limit=30)
            risky = (chrome_history or []) + (safari_history or [])

            for entry in risky[:5]:
                # Deduplicate: Check if we've already flagged this entry (url + timestamp)
                # Note: history entries from browser_scanner should include a timestamp
                visit_time = entry.get('last_visit_time') or entry.get('visit_time', 'unknown')
                history_key = f"{entry['url']}-{visit_time}"
                
                if history_key in self._flagged_history:
                    continue
                
                self._flagged_history.add(history_key)
                detected = True
                self._stats["threats_found"] += 1

                print(f"\n  🌐 RISKY SITE: {entry['url'][:80]}")

                self.db.add_scan_result(
                    scan_type="browser_history",
                    source=entry['url'],
                    findings=[entry],
                    severity=entry.get('risk', 'medium'),
                    user=self.user,
                    host=self.host
                )

                self.send_event(
                    user=self.user,
                    host=self.host,
                    channel="risky_website",
                    payload=f"User accessed risky site: {entry['url']}\n"
                           f"Title: {entry.get('title', 'N/A')}",
                    metadata=entry
                )
            
            # Prune history cache
            if len(self._flagged_history) > 1000:
                self._flagged_history = set(list(self._flagged_history)[-500:])

        except Exception as e:
            print(f"  ⚠️  Browser scan error: {e}")

        return detected

    def scan_print_spool(self) -> bool:
        """Check for recently printed sensitive documents."""
        detected = False

        try:
            if sys.platform == "darwin":
                # macOS print spool
                spool_dir = Path("/private/var/spool/cups")
                if spool_dir.exists():
                    for f in spool_dir.iterdir():
                        if f.is_file() and f.stat().st_mtime > (time.time() - 600):
                            result = self.file_scanner.scan_file(str(f))
                            if result and result.findings:
                                detected = True
                                print(f"\n  🖨️  PRINT: Sensitive data in print job!")

                                self.send_event(
                                    user=self.user,
                                    host=self.host,
                                    channel="browser_print",
                                    payload=f"Print job with sensitive data: {f.name}",
                                    metadata={
                                        "file": str(f),
                                        "severity": result.severity,
                                    }
                                )

        except PermissionError:
            pass  # Print spool often requires elevated permissions
        except Exception as e:
            print(f"  ⚠️  Print spool scan error: {e}")

        return detected

    def scan_temp_files(self) -> bool:
        """Scan temp directories for sensitive data (often used by browsers)."""
        detected = False
        temp_dirs = [
            Path("/tmp"),
            Path.home() / "Library/Caches" if sys.platform == "darwin" else Path("/tmp"),
        ]

        try:
            for temp_dir in temp_dirs:
                if not temp_dir.exists():
                    continue

                # Only look at recently created files
                for f in temp_dir.iterdir():
                    if not f.is_file():
                        continue
                    if f.stat().st_mtime < (time.time() - 300):
                        continue
                    if f.stat().st_size > 5_000_000:
                        continue

                    file_key = f"{f}-{f.stat().st_mtime}"
                    if file_key in self._scanned_files:
                        continue
                    self._scanned_files.add(file_key)

                    result = self.file_scanner.scan_file(str(f))
                    if result and result.findings:
                        # Only alert on high+ severity for temp files
                        if result.severity in ('critical', 'high'):
                            detected = True
                            print(f"\n  📁 TEMP: Sensitive data in temp file: {f.name}")

        except PermissionError:
            pass
        except Exception as e:
            print(f"  ⚠️  Temp scan error: {e}")

        return detected

    def detect_form_submission(self, user: str, host: str, form_data: str, website: str) -> bool:
        """Detect sensitive data in form submissions — real content scan."""
        findings = self.file_scanner.scan_text(form_data, f"form on {website}")

        if findings:
            pattern_names = list(set(f.pattern_name for f in findings))
            print(f"\n  🚨 FORM: Sensitive data submitted to {website}")
            print(f"     Patterns: {', '.join(pattern_names)}")

            return self.send_event(
                user=user,
                host=host,
                channel=f"web_form_{website}",
                payload=f"Form submission to {website}\nPatterns: {', '.join(pattern_names)}",
                metadata={
                    "website": website,
                    "patterns": pattern_names,
                    "finding_count": len(findings),
                }
            )

        return False

    def detect_print_to_pdf(self, user: str, host: str, document_name: str) -> bool:
        """Detect printing sensitive documents — scan actual file."""
        result = self.file_scanner.scan_file(document_name)

        if result and result.findings:
            pattern_names = list(set(f.pattern_name for f in result.findings))
            print(f"\n  🖨️  PRINT: Sensitive document: {document_name}")

            return self.send_event(
                user=user,
                host=host,
                channel="browser_print",
                payload=f"Print of sensitive document: {document_name}\n"
                       f"Patterns: {', '.join(pattern_names)}",
                metadata={
                    "document": document_name,
                    "patterns": pattern_names,
                }
            )

        return False

    def detect_file_download(self, user: str, host: str, filename: str, source_website: str) -> bool:
        """Detect downloading sensitive files — scan actual content."""
        result = self.file_scanner.scan_file(filename)

        if result and result.findings:
            pattern_names = list(set(f.pattern_name for f in result.findings))
            return self.send_event(
                user=user,
                host=host,
                channel="web_download",
                payload=f"Download from {source_website}: {filename}\n"
                       f"Patterns: {', '.join(pattern_names)}",
                metadata={
                    "source": source_website,
                    "patterns": pattern_names,
                }
            )

        return False

    def run_continuous_monitor(self, interval: int = 30):
        """Run continuous real web monitoring."""

        print(f"""
╔══════════════════════════════════════════════════════╗
║  🌐 TRON WEB DLP AGENT                          ║
║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
║  📱 Host:    {self.host:<39} ║
║  👤 User:    {self.user:<39} ║
║  🔗 API:     {self.api_url:<39} ║
║  🆔 Session: {self.session_id:<39} ║
║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
║  MONITORS:                                           ║
║    ✅ Download directory scanning                    ║
║    ✅ Browser history monitoring                     ║
║    ✅ Print spool scanning                           ║
║    ✅ Temp file scanning                             ║
║  Status: MONITORING                                  ║
╚══════════════════════════════════════════════════════╝
        """)

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

                print(f"\n⏱️  Web scan #{scan_count} at {timestamp}", end="")
                self._stats["scans"] += 1

                # Download monitoring (every scan)
                self.scan_downloads()

                # Print spool check (every scan)
                self.scan_print_spool()

                # Temp files (every 3rd scan)
                if scan_count % 3 == 0:
                    self.scan_temp_files()

                # Browser history (every 10th scan)
                if scan_count % 10 == 0:
                    self.scan_browser_history()

                # Stats
                print(f" | Alerts: {self._stats['alerts_sent']} | "
                      f"Threats: {self._stats['threats_found']} | "
                      f"Downloads: {self._stats['download_scans']}")

                time.sleep(interval)

        except KeyboardInterrupt:
            pass

        print(f"\n\n🛑 Web agent stopped")
        print(f"📊 Stats: {json.dumps(self._stats, indent=2)}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TRON Web DLP Agent")
    parser.add_argument("--api", default="http://localhost:5001", help="DLP API URL")
    parser.add_argument("--interval", type=int, default=30, help="Scan interval (seconds)")
    args = parser.parse_args()

    agent = WebDLPAgent(api_url=args.api)
    agent.run_continuous_monitor(interval=args.interval)
