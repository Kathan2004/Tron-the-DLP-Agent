#!/usr/bin/env python3
"""
Real Network Monitor — TRON THE DLP AGENT
Monitors actual network connections, DNS queries, and outbound traffic
for data exfiltration patterns. Uses native macOS/Linux tools.
"""

import os
import sys
import re
import json
import subprocess
import socket
import time
import threading
from datetime import datetime
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path

# Known risky domains / cloud storage
CLOUD_STORAGE_DOMAINS = {
    "drive.google.com", "docs.google.com",
    "dropbox.com", "www.dropbox.com", "dl.dropboxusercontent.com",
    "onedrive.live.com", "1drv.ms",
    "box.com", "app.box.com",
    "mega.nz", "mega.co.nz",
    "wetransfer.com",
    "mediafire.com",
    "sendspace.com",
    "transfer.sh",
    "file.io",
    "0x0.st",
    "temp.sh",
    "gofile.io",
    "anonfiles.com",
}

# Paste/file sharing sites
PASTE_SITES = {
    "pastebin.com", "paste.ee", "hastebin.com", "dpaste.org",
    "ghostbin.com", "rentry.co", "del.dog",
    "gist.github.com",
}

# Known suspicious ports for exfiltration
SUSPICIOUS_PORTS = {
    21,     # FTP
    22,     # SSH (outbound)
    23,     # Telnet
    69,     # TFTP
    6667,   # IRC
    6697,   # IRC SSL
    8080,   # Alt HTTP
    8443,   # Alt HTTPS
    9090,   # Various
    4444,   # Metasploit default
    5555,   # ADB
    31337,  # Elite backdoor
}

# Personal email domains (sending corporate data to personal email = exfiltration)
PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "tutanota.com", "aol.com",
    "icloud.com", "mail.com", "yandex.com",
}


@dataclass
class NetworkEvent:
    """A detected network event."""
    timestamp: str
    event_type: str  # 'connection', 'dns', 'upload', 'suspicious_port'
    process: str
    pid: int
    user: str
    local_addr: str
    remote_addr: str
    remote_port: int
    domain: str
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    details: str

    def to_dict(self):
        return asdict(self)


class NetworkMonitor:
    """Monitor real network connections for data exfiltration."""

    def __init__(self):
        self.platform = sys.platform
        self.hostname = socket.gethostname()
        self.user = os.getenv("USER", "unknown")
        self._seen_connections: Set[str] = set()
        self._dns_cache: Dict[str, str] = {}

    def get_active_connections(self) -> List[Dict]:
        """Get all active network connections with process info."""
        connections = []

        try:
            if self.platform == "darwin":
                # macOS: use lsof for better process info
                result = subprocess.run(
                    ["lsof", "-i", "-n", "-P", "+c", "0"],
                    capture_output=True, text=True, timeout=10
                )
                connections = self._parse_lsof(result.stdout)

            elif self.platform == "linux":
                # Linux: use ss + /proc for process info
                result = subprocess.run(
                    ["ss", "-tupn"],
                    capture_output=True, text=True, timeout=10
                )
                connections = self._parse_ss(result.stdout)

        except subprocess.TimeoutExpired:
            print("⚠️  Network scan timed out")
        except FileNotFoundError as e:
            print(f"⚠️  Tool not found: {e}")
        except Exception as e:
            print(f"⚠️  Network monitoring error: {e}")

        return connections

    def get_dns_queries(self) -> List[Dict]:
        """Get recent DNS queries from system resolver logs."""
        queries = []

        try:
            if self.platform == "darwin":
                # macOS: check DNS cache
                result = subprocess.run(
                    ["dscacheutil", "-cachedump", "-entries"],
                    capture_output=True, text=True, timeout=5
                )
                # Also try: log stream for DNS activity
                # For real deployment, you'd monitor /var/log/system.log

            # Alternative: parse /etc/hosts resolution logs
            # In production, you'd want a DNS proxy or tap

        except Exception as e:
            print(f"⚠️  DNS monitoring error: {e}")

        return queries

    def check_for_exfiltration(self) -> List[NetworkEvent]:
        """Check current connections for exfiltration indicators."""
        events = []
        connections = self.get_active_connections()

        for conn in connections:
            # Generate unique key to avoid duplicate alerts
            conn_key = f"{conn.get('pid')}-{conn.get('remote_addr')}-{conn.get('remote_port')}"

            if conn_key in self._seen_connections:
                continue

            event = self._analyze_connection(conn)
            if event:
                self._seen_connections.add(conn_key)
                events.append(event)

        # Prune seen connections cache (keep last 1000)
        if len(self._seen_connections) > 1000:
            self._seen_connections = set(list(self._seen_connections)[-500:])

        return events

    def check_outbound_data_volume(self) -> Optional[Dict]:
        """Check for unusually high outbound data transfer."""
        try:
            if self.platform == "darwin":
                result = subprocess.run(
                    ["netstat", "-I", "en0", "-b"],
                    capture_output=True, text=True, timeout=5
                )
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 2:
                    parts = lines[1].split()
                    if len(parts) >= 7:
                        return {
                            "interface": "en0",
                            "bytes_in": int(parts[6]) if parts[6].isdigit() else 0,
                            "bytes_out": int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0,
                            "timestamp": datetime.now().isoformat()
                        }
        except Exception:
            pass
        return None

    def get_listening_ports(self) -> List[Dict]:
        """Get all listening ports on this machine."""
        listeners = []
        try:
            if self.platform == "darwin":
                result = subprocess.run(
                    ["lsof", "-i", "-n", "-P", "+c", "0", "-sTCP:LISTEN"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 9:
                        listeners.append({
                            "process": parts[0],
                            "pid": parts[1],
                            "user": parts[2],
                            "address": parts[8],
                        })
        except Exception:
            pass
        return listeners

    def _analyze_connection(self, conn: Dict) -> Optional[NetworkEvent]:
        """Analyze a single connection for exfiltration risk."""
        remote_addr = conn.get("remote_addr", "")
        remote_port = conn.get("remote_port", 0)
        process = conn.get("process", "unknown")
        domain = conn.get("domain", "")

        # Skip loopback
        if remote_addr.startswith("127.") or remote_addr == "::1":
            return None

        # Resolve domain if we have IP
        if not domain and remote_addr:
            domain = self._resolve_domain(remote_addr)

        risk_level = "low"
        event_type = "connection"
        details = ""

        # Check 1: Cloud storage destinations
        if any(d in domain for d in CLOUD_STORAGE_DOMAINS):
            risk_level = "high"
            event_type = "cloud_upload"
            details = f"Connection to cloud storage: {domain}"

        # Check 2: Paste/file sharing sites
        elif any(d in domain for d in PASTE_SITES):
            risk_level = "high"
            event_type = "paste_site"
            details = f"Connection to paste/file sharing: {domain}"

        # Check 3: Suspicious ports
        elif remote_port in SUSPICIOUS_PORTS:
            risk_level = "medium"
            event_type = "suspicious_port"
            details = f"Outbound connection on suspicious port {remote_port}"

        # Check 4: SSH outbound (potential tunnel)
        elif remote_port == 22 and process not in ("ssh", "sshd", "git"):
            risk_level = "high"
            event_type = "ssh_tunnel"
            details = f"Non-SSH process using SSH port: {process}"

        # Check 5: Personal email services
        elif any(d in domain for d in PERSONAL_EMAIL_DOMAINS):
            risk_level = "medium"
            event_type = "personal_email"
            details = f"Connection to personal email: {domain}"

        # Check 6: FTP traffic
        elif remote_port == 21:
            risk_level = "critical"
            event_type = "ftp_transfer"
            details = f"FTP connection detected to {remote_addr}"

        # Only return events with medium+ risk
        if risk_level in ("low",):
            return None

        return NetworkEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            process=process,
            pid=conn.get("pid", 0),
            user=self.user,
            local_addr=conn.get("local_addr", ""),
            remote_addr=remote_addr,
            remote_port=remote_port,
            domain=domain,
            risk_level=risk_level,
            details=details
        )

    def _resolve_domain(self, ip: str) -> str:
        """Reverse DNS lookup with caching."""
        if ip in self._dns_cache:
            return self._dns_cache[ip]

        try:
            domain = socket.gethostbyaddr(ip)[0]
            self._dns_cache[ip] = domain
            return domain
        except (socket.herror, socket.gaierror, OSError):
            self._dns_cache[ip] = ip
            return ip

    def _parse_lsof(self, output: str) -> List[Dict]:
        """Parse lsof -i output into connection dicts."""
        connections = []
        lines = output.strip().split('\n')

        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) < 9:
                continue

            process = parts[0]
            pid = int(parts[1]) if parts[1].isdigit() else 0
            user = parts[2]

            # Parse the name column (last) - format: host:port->remote:port
            name = parts[-1]
            if '->' in name:
                local, remote = name.split('->')
                remote_parts = remote.rsplit(':', 1)
                remote_addr = remote_parts[0] if len(remote_parts) >= 1 else ""
                remote_port = int(remote_parts[1]) if len(remote_parts) > 1 and remote_parts[1].isdigit() else 0

                local_parts = local.rsplit(':', 1)
                local_addr = local_parts[0] if len(local_parts) >= 1 else ""

                connections.append({
                    "process": process,
                    "pid": pid,
                    "user": user,
                    "local_addr": local_addr,
                    "remote_addr": remote_addr,
                    "remote_port": remote_port,
                    "domain": "",
                    "state": parts[-2] if len(parts) > 9 else "ESTABLISHED"
                })

        return connections

    def _parse_ss(self, output: str) -> List[Dict]:
        """Parse ss -tupn output (Linux)."""
        connections = []
        lines = output.strip().split('\n')

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue

            # Parse local and remote addresses
            local = parts[3] if len(parts) > 3 else ""
            remote = parts[4] if len(parts) > 4 else ""

            remote_parts = remote.rsplit(':', 1)
            remote_addr = remote_parts[0] if remote_parts else ""
            remote_port = int(remote_parts[1]) if len(remote_parts) > 1 and remote_parts[1].isdigit() else 0

            # Extract process info
            process = "unknown"
            pid = 0
            if len(parts) > 5:
                proc_match = re.search(r'"([^"]+)",pid=(\d+)', parts[5])
                if proc_match:
                    process = proc_match.group(1)
                    pid = int(proc_match.group(2))

            connections.append({
                "process": process,
                "pid": pid,
                "user": os.getenv("USER", "unknown"),
                "local_addr": local,
                "remote_addr": remote_addr,
                "remote_port": remote_port,
                "domain": "",
                "state": parts[0]
            })

        return connections


class ProcessMonitor:
    """Monitor running processes for suspicious DLP-related activity."""

    # Suspicious process names that could be used for exfiltration
    SUSPICIOUS_PROCESSES = {
        "nc", "ncat", "netcat",       # Network tools
        "curl", "wget",               # Download/upload tools
        "scp", "rsync",               # File transfer
        "ftp", "sftp",                # FTP clients
        "rclone",                     # Cloud sync
        "tor", "torsocks",            # Anonymization
        "nmap", "masscan",            # Network scanning
        "tcpdump", "wireshark",       # Packet capture
        "screencapture",              # Screen capture
        "teamviewer", "anydesk",      # Remote access
        "ngrok",                      # Tunneling
    }

    # Screen recording / capture tools
    SCREEN_CAPTURE_TOOLS = {
        "screencapture", "screenshot", "obs", "OBS",
        "loom", "screenflow", "camtasia",
        "quicktime player",
    }

    def __init__(self):
        self.platform = sys.platform
        self.user = os.getenv("USER", "unknown")
        self._known_pids: Set[int] = set()

    def get_running_processes(self) -> List[Dict]:
        """Get list of running processes."""
        processes = []
        try:
            if self.platform == "darwin":
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            "user": parts[0],
                            "pid": int(parts[1]) if parts[1].isdigit() else 0,
                            "cpu": float(parts[2]) if parts[2].replace('.', '').isdigit() else 0,
                            "mem": float(parts[3]) if parts[3].replace('.', '').isdigit() else 0,
                            "command": parts[10],
                            "process_name": Path(parts[10].split()[0]).name if parts[10] else "unknown"
                        })
            elif self.platform == "linux":
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            "user": parts[0],
                            "pid": int(parts[1]) if parts[1].isdigit() else 0,
                            "cpu": float(parts[2]) if parts[2].replace('.', '').isdigit() else 0,
                            "mem": float(parts[3]) if parts[3].replace('.', '').isdigit() else 0,
                            "command": parts[10],
                            "process_name": Path(parts[10].split()[0]).name if parts[10] else "unknown"
                        })
        except Exception as e:
            print(f"⚠️  Process monitoring error: {e}")

        return processes

    def check_suspicious_processes(self) -> List[Dict]:
        """Check for suspicious processes that may indicate exfiltration."""
        suspicious = []
        processes = self.get_running_processes()

        for proc in processes:
            proc_name = proc.get("process_name", "").lower()
            command = proc.get("command", "").lower()

            risk_level = None
            reason = ""

            # Check against suspicious process names
            if proc_name in self.SUSPICIOUS_PROCESSES:
                risk_level = "high"
                reason = f"Suspicious tool running: {proc_name}"

            # Check for screen capture
            elif proc_name in self.SCREEN_CAPTURE_TOOLS:
                risk_level = "medium"
                reason = f"Screen capture tool detected: {proc_name}"

            # Check for data being piped to curl/wget
            elif "curl" in command and ("post" in command or "-d" in command or "--data" in command):
                risk_level = "high"
                reason = f"Data upload via curl detected"

            # Check for base64 encoding (common exfil technique)
            elif "base64" in command:
                risk_level = "medium"
                reason = "Base64 encoding detected (possible data exfiltration prep)"

            # Check for zip/tar with sensitive keywords
            elif any(tool in command for tool in ["zip", "tar", "gzip", "7z"]):
                if any(kw in command for kw in ["password", "secret", "credential", "key", "aadhaar", "pan"]):
                    risk_level = "high"
                    reason = f"Compression of potentially sensitive files"

            if risk_level:
                suspicious.append({
                    "timestamp": datetime.now().isoformat(),
                    "process": proc_name,
                    "pid": proc.get("pid", 0),
                    "user": proc.get("user", "unknown"),
                    "command": command[:200],
                    "risk_level": risk_level,
                    "reason": reason,
                })

        return suspicious

    def check_new_processes(self) -> List[Dict]:
        """Detect newly spawned processes since last check."""
        current_pids = set()
        new_suspicious = []

        processes = self.get_running_processes()
        for proc in processes:
            pid = proc.get("pid", 0)
            current_pids.add(pid)

            if pid not in self._known_pids:
                # New process - check if suspicious
                proc_name = proc.get("process_name", "").lower()
                if proc_name in self.SUSPICIOUS_PROCESSES:
                    new_suspicious.append({
                        "timestamp": datetime.now().isoformat(),
                        "event": "new_suspicious_process",
                        "process": proc_name,
                        "pid": pid,
                        "user": proc.get("user", "unknown"),
                        "command": proc.get("command", "")[:200],
                    })

        self._known_pids = current_pids
        return new_suspicious


class BrowserHistoryScanner:
    """Scan browser history for access to risky sites."""

    def __init__(self):
        self.platform = sys.platform

    def get_chrome_history(self, limit: int = 100) -> List[Dict]:
        """Read Chrome browser history (last N entries)."""
        history = []

        try:
            if self.platform == "darwin":
                history_path = Path.home() / "Library/Application Support/Google/Chrome/Default/History"
            elif self.platform == "linux":
                history_path = Path.home() / ".config/google-chrome/Default/History"
            else:
                return []

            if not history_path.exists():
                return []

            # Copy the file since Chrome locks it
            import shutil
            import tempfile
            import sqlite3

            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
                tmp_path = tmp.name

            shutil.copy2(str(history_path), tmp_path)

            conn = sqlite3.connect(tmp_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT ?
            """, (limit,))

            for row in cursor.fetchall():
                url = row['url']
                # Check if URL matches risky domains
                risk = self._assess_url_risk(url)
                if risk:
                    history.append({
                        "url": url,
                        "title": row['title'],
                        "visit_count": row['visit_count'],
                        "risk": risk,
                    })

            conn.close()
            os.unlink(tmp_path)

        except Exception as e:
            print(f"⚠️  Browser history scan error: {e}")

        return history

    def get_safari_history(self, limit: int = 100) -> List[Dict]:
        """Read Safari browser history."""
        history = []

        try:
            if self.platform != "darwin":
                return []

            history_path = Path.home() / "Library/Safari/History.db"
            if not history_path.exists():
                return []

            import shutil
            import tempfile
            import sqlite3

            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
                tmp_path = tmp.name

            shutil.copy2(str(history_path), tmp_path)

            conn = sqlite3.connect(tmp_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT hi.url, hv.visit_time
                FROM history_items hi
                JOIN history_visits hv ON hi.id = hv.history_item
                ORDER BY hv.visit_time DESC
                LIMIT ?
            """, (limit,))

            for row in cursor.fetchall():
                url = row['url']
                risk = self._assess_url_risk(url)
                if risk:
                    history.append({
                        "url": url,
                        "risk": risk,
                    })

            conn.close()
            os.unlink(tmp_path)

        except Exception as e:
            print(f"⚠️  Safari history scan error: {e}")

        return history

    def _assess_url_risk(self, url: str) -> Optional[str]:
        """Assess risk level of a URL."""
        url_lower = url.lower()

        for domain in CLOUD_STORAGE_DOMAINS:
            if domain in url_lower:
                return "high"

        for domain in PASTE_SITES:
            if domain in url_lower:
                return "high"

        for domain in PERSONAL_EMAIL_DOMAINS:
            if domain in url_lower:
                return "medium"

        return None


class ShellHistoryScanner:
    """Scan shell history for suspicious commands."""

    SUSPICIOUS_PATTERNS = [
        (r"curl.*-[dX].*POST", "high", "HTTP POST with curl"),
        (r"scp\s+.*@", "high", "SCP file transfer"),
        (r"rsync\s+.*@", "high", "rsync file transfer"),
        (r"base64\s+", "medium", "Base64 encoding"),
        (r"openssl\s+enc", "medium", "OpenSSL encryption"),
        (r"nc\s+-", "high", "Netcat connection"),
        (r"ncat\s+", "high", "Ncat connection"),
        (r"python.*http\.server", "medium", "Python HTTP server"),
        (r"ngrok", "high", "Ngrok tunnel"),
        (r"rclone", "high", "Rclone cloud sync"),
        (r"wget.*\.(zip|tar|gz|7z)", "medium", "Archive download"),
        (r"tar.*password|secret|credential", "high", "Archiving sensitive files"),
    ]

    def scan_shell_history(self) -> List[Dict]:
        """Scan shell history files for suspicious commands."""
        findings = []
        history_files = [
            Path.home() / ".bash_history",
            Path.home() / ".zsh_history",
            Path.home() / ".local/share/fish/fish_history",
        ]

        for hist_file in history_files:
            if not hist_file.exists():
                continue

            try:
                content = hist_file.read_text(errors='replace')
                lines = content.split('\n')

                # Check last 500 commands
                for line_num, line in enumerate(lines[-500:], 1):
                    # zsh history format: : timestamp:0;command
                    if line.startswith(': '):
                        parts = line.split(';', 1)
                        if len(parts) > 1:
                            line = parts[1]

                    for pattern, severity, description in self.SUSPICIOUS_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                "timestamp": datetime.now().isoformat(),
                                "source": str(hist_file),
                                "command": line[:200],
                                "severity": severity,
                                "description": description,
                            })
                            break

            except Exception as e:
                print(f"⚠️  Cannot read {hist_file}: {e}")

        return findings


if __name__ == "__main__":
    print("\nTRON THE DLP AGENT — Network & System Monitor\n")

    # Network scan
    print("=" * 50)
    print("Active Network Connections")
    print("=" * 50)
    net = NetworkMonitor()
    events = net.check_for_exfiltration()
    if events:
        for e in events:
            print(f"  [{e.risk_level.upper()}] {e.event_type}: {e.process} -> {e.domain or e.remote_addr}:{e.remote_port}")
            print(f"    {e.details}")
    else:
        print("  ✅ No suspicious connections detected")

    # Process scan
    print(f"\n{'=' * 50}")
    print("⚙️  Suspicious Processes")
    print("=" * 50)
    proc = ProcessMonitor()
    suspicious = proc.check_suspicious_processes()
    if suspicious:
        for s in suspicious:
            print(f"  [{s['risk_level'].upper()}] {s['process']} (PID: {s['pid']})")
            print(f"    {s['reason']}")
    else:
        print("  ✅ No suspicious processes detected")

    # Shell history
    print(f"\n{'=' * 50}")
    print("Shell History Scan")
    print("=" * 50)
    shell = ShellHistoryScanner()
    shell_findings = shell.scan_shell_history()
    if shell_findings:
        for f in shell_findings[:10]:
            print(f"  [{f['severity'].upper()}] {f['description']}")
            print(f"    {f['command'][:80]}")
    else:
        print("  ✅ No suspicious commands in shell history")
