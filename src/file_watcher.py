#!/usr/bin/env python3
"""
Real-Time File Watcher — TRON THE DLP AGENT
Uses watchdog for real filesystem event monitoring.
Scans file contents on creation/modification and alerts on sensitive data.
"""

import os
import sys
import time
import hashlib
import threading
import json
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from collections import defaultdict

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    print("⚠️  watchdog not installed. Install with: pip install watchdog")

# Add parent dir
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.file_scanner import FileContentScanner, SCANNABLE_TEXT_EXTENSIONS


class DLPFileEventHandler(FileSystemEventHandler):
    """Handle filesystem events and scan for sensitive data."""

    def __init__(self, scanner: FileContentScanner, api_url: str,
                 db=None, user: str = None, host: str = None):
        super().__init__()
        self.scanner = scanner
        self.api_url = api_url
        self.db = db
        self.user = user or os.getenv("USER", "unknown")
        self.host = host or os.getenv("HOSTNAME", "unknown")
        self._recent_events: Dict[str, float] = {}  # Debouncing
        self._lock = threading.Lock()
        self._alert_count = 0
        self._stats = defaultdict(int)

    def on_created(self, event: FileSystemEvent):
        """Handle file creation."""
        if event.is_directory:
            return
        self._handle_file_event(event.src_path, "file_created")

    def on_modified(self, event: FileSystemEvent):
        """Handle file modification."""
        if event.is_directory:
            return
        self._handle_file_event(event.src_path, "file_modified")

    def on_moved(self, event: FileSystemEvent):
        """Handle file move/rename."""
        if event.is_directory:
            return
        self._handle_file_event(event.dest_path, "file_moved")

    def _handle_file_event(self, file_path: str, event_type: str):
        """Process a file event."""
        # Debounce: ignore duplicate events within 3 seconds
        with self._lock:
            now = time.time()
            last_event = self._recent_events.get(file_path, 0)
            if now - last_event < 3:
                return
            self._recent_events[file_path] = now

            # Prune old entries
            if len(self._recent_events) > 500:
                cutoff = now - 60
                self._recent_events = {
                    k: v for k, v in self._recent_events.items() if v > cutoff
                }

        # Check if file is scannable
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return

        ext = path.suffix.lower()
        if ext not in SCANNABLE_TEXT_EXTENSIONS and ext not in {'.pdf', '.docx', '.xlsx'}:
            return

        # Skip small/system files
        try:
            size = path.stat().st_size
            if size == 0 or size > 50_000_000:  # 50MB
                return
        except OSError:
            return

        self._stats['files_scanned'] += 1

        # Scan file
        try:
            result = self.scanner.scan_file(file_path)
            if result and result.findings:
                self._stats['threats_found'] += 1
                self._alert_count += 1

                print(f"\n[ALERT] [{event_type.upper()}] Sensitive data detected!")
                print(f"   File: {file_path}")
                print(f"   Severity: {result.severity.upper()}")
                print(f"   Findings: {len(result.findings)}")

                for finding in result.findings[:3]:
                    print(f"     - [{finding.severity}] {finding.pattern_name}: {finding.matched_text}")

                # Send to DLP API
                self._send_alert(result, event_type)

                # Store in local DB
                if self.db:
                    self.db.add_scan_result(
                        scan_type="file_watch",
                        source=file_path,
                        findings=[f.to_dict() for f in result.findings],
                        severity=result.severity,
                        file_path=file_path,
                        file_hash=result.file_hash,
                        file_size=result.file_size,
                        user=self.user,
                        host=self.host
                    )

        except Exception as e:
            print(f"Warning: Error scanning {file_path}: {e}")

    def _send_alert(self, result, event_type: str):
        """Send detection alert to DLP API."""
        try:
            # Build payload summary
            pattern_names = list(set(f.pattern_name for f in result.findings))
            sample = "\n".join(f"[{f.pattern_name}] {f.matched_text}" for f in result.findings[:5])

            payload = {
                "user": self.user,
                "source_host": self.host,
                "channel": event_type,
                "payload": f"File: {result.file_path}\nPatterns: {', '.join(pattern_names)}\n{sample}",
                "agent_type": "file_watcher",
                "geo": {
                    "file_hash": result.file_hash,
                    "file_size": result.file_size,
                    "finding_count": len(result.findings),
                    "severity": result.severity,
                }
            }

            response = requests.post(
                f"{self.api_url}/api/events",
                json=payload,
                timeout=5
            )

            if response.status_code == 200:
                event_id = response.json().get("event_id")
                print(f"   OK: Alert sent: {event_id}")
            else:
                print(f"   API error: {response.status_code}")

        except Exception as e:
            print(f"   Warning: Cannot reach API: {e}")

    @property
    def statistics(self) -> Dict:
        return {
            "files_scanned": self._stats['files_scanned'],
            "threats_found": self._stats['threats_found'],
            "total_alerts": self._alert_count,
        }


class USBMonitor:
    """Monitor USB device connections in real-time."""

    def __init__(self):
        self.platform = sys.platform
        self._known_devices: Set[str] = set()
        self._initialized = False

    def get_usb_devices(self) -> List[Dict]:
        """Get currently connected USB devices."""
        devices = []
        try:
            if self.platform == "darwin":
                import subprocess
                result = subprocess.run(
                    ["system_profiler", "SPUSBDataType", "-json"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    usb_data = data.get("SPUSBDataType", [])
                    self._extract_usb_devices(usb_data, devices)

        except json.JSONDecodeError:
            # Fallback to text parsing
            try:
                import subprocess
                result = subprocess.run(
                    ["system_profiler", "SPUSBDataType"],
                    capture_output=True, text=True, timeout=10
                )
                # Simple text parsing
                current_device = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if ':' in line:
                        key, _, value = line.partition(':')
                        key = key.strip()
                        value = value.strip()
                        if key and value:
                            current_device[key] = value
                    elif line == '' and current_device:
                        if current_device.get('Product ID') or current_device.get('Vendor ID'):
                            devices.append(current_device)
                        current_device = {}
            except Exception:
                pass
        except Exception as e:
            print(f"Warning: USB scan error: {e}")

        return devices

    def _extract_usb_devices(self, items: list, devices: list, depth: int = 0):
        """Recursively extract USB devices from system_profiler JSON."""
        for item in items:
            if isinstance(item, dict):
                name = item.get("_name", "Unknown")
                vendor = item.get("manufacturer", "Unknown")
                serial = item.get("serial_num", "")
                product_id = item.get("product_id", "")
                vendor_id = item.get("vendor_id", "")

                if name != "Unknown" and vendor_id:
                    devices.append({
                        "name": name,
                        "vendor": vendor,
                        "serial": serial,
                        "product_id": product_id,
                        "vendor_id": vendor_id,
                    })

                # Check for child items
                for key in item:
                    if isinstance(item[key], list):
                        self._extract_usb_devices(item[key], devices, depth + 1)

    def check_new_devices(self) -> List[Dict]:
        """Check for newly connected USB devices."""
        current_devices = self.get_usb_devices()
        current_ids = set()
        new_devices = []

        for dev in current_devices:
            dev_id = f"{dev.get('vendor', '')}-{dev.get('name', '')}-{dev.get('serial', '')}"
            current_ids.add(dev_id)

            if self._initialized and dev_id not in self._known_devices:
                new_devices.append({
                    **dev,
                    "timestamp": datetime.now().isoformat(),
                    "event": "usb_connected",
                })
                print(f"NEW USB DEVICE: {dev.get('name')} ({dev.get('vendor')})")

        # Check for removed devices
        removed = self._known_devices - current_ids
        for dev_id in removed:
            print(f"USB DEVICE REMOVED: {dev_id}")

        self._known_devices = current_ids
        self._initialized = True

        return new_devices

    def get_mounted_volumes(self) -> List[Dict]:
        """Get mounted external volumes."""
        volumes = []
        try:
            if sys.platform == "darwin":
                volumes_path = Path("/Volumes")
                if volumes_path.exists():
                    for vol in volumes_path.iterdir():
                        if vol.name == "Macintosh HD":
                            continue
                        if vol.is_dir() or vol.is_mount():
                            try:
                                stat = vol.stat()
                                volumes.append({
                                    "name": vol.name,
                                    "path": str(vol),
                                    "type": "external",
                                })
                            except OSError:
                                pass
        except Exception as e:
            print(f"Warning: Volume scan error: {e}")

        return volumes


class RealTimeWatcher:
    """Main real-time file watcher orchestrator."""

    def __init__(self, api_url: str = "http://localhost:5001",
                 watch_dirs: List[str] = None, db=None):
        self.api_url = api_url
        self.db = db
        self.scanner = FileContentScanner()
        self.user = os.getenv("USER", "unknown")
        self.host = os.getenv("HOSTNAME", "unknown")
        self.usb_monitor = USBMonitor()

        # Default directories to watch
        self.watch_dirs = watch_dirs or [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
        ]

        self.handler = DLPFileEventHandler(
            scanner=self.scanner,
            api_url=self.api_url,
            db=self.db,
            user=self.user,
            host=self.host
        )

        self.observer = None if not HAS_WATCHDOG else Observer()

    def start(self):
        """Start watching directories."""
        if not HAS_WATCHDOG:
            print("Error: watchdog package not installed. Run: pip install watchdog")
            return

        print(f"""
        ╔═══════════════════════════════════════════════╗
        ║  REAL-TIME FILE WATCHER — TRON THE DLP AGENT        ║
        ║  User: {self.user:<37} ║
        ║  Host: {self.host:<37} ║
        ║  Status: ACTIVE                               ║
        ╚═══════════════════════════════════════════════╝
        """)

        for watch_dir in self.watch_dirs:
            path = Path(watch_dir)
            if path.exists():
                self.observer.schedule(self.handler, str(path), recursive=True)
                print(f"  Watching: {watch_dir}")
            else:
                print(f"  Skipping (not found): {watch_dir}")

        self.observer.start()
        print(f"\n  File watcher started at {datetime.now().strftime('%H:%M:%S')}")

        try:
            while True:
                # Periodic USB check
                new_usb = self.usb_monitor.check_new_devices()
                for dev in new_usb:
                    self._send_usb_alert(dev)

                # Print stats every 60 seconds
                stats = self.handler.statistics
                if stats['files_scanned'] > 0:
                      print(f"\r  Scanned: {stats['files_scanned']} | "
                          f"Threats: {stats['threats_found']} | "
                          f"Alerts: {stats['total_alerts']}", end="", flush=True)

                time.sleep(10)

        except KeyboardInterrupt:
            print("\n\n  File watcher stopped")
            self.observer.stop()

        self.observer.join()

    def _send_usb_alert(self, device: Dict):
        """Send USB device alert to DLP API."""
        try:
            payload = {
                "user": self.user,
                "source_host": self.host,
                "channel": "usb_connection",
                "payload": f"USB Device Connected: {device.get('name', 'Unknown')} "
                          f"(Vendor: {device.get('vendor', 'Unknown')}, "
                          f"Serial: {device.get('serial', 'N/A')})",
                "agent_type": "file_watcher",
                "geo": {
                    "device_name": device.get("name"),
                    "device_vendor": device.get("vendor"),
                    "device_serial": device.get("serial"),
                }
            }

            response = requests.post(
                f"{self.api_url}/api/events",
                json=payload,
                timeout=5
            )

            if response.status_code == 200:
                print(f"\n  USB alert sent: {device.get('name')}")

        except Exception as e:
            print(f"\n  Warning: USB alert failed: {e}")

    def scan_existing_files(self) -> List[Dict]:
        """One-time scan of existing files in watched directories."""
        all_results = []
        for watch_dir in self.watch_dirs:
            print(f"\n  Scanning: {watch_dir}")
            results = self.scanner.scan_directory(watch_dir)
            if results:
                for r in results:
                    print(f"    ALERT {r.file_path} — {r.severity.upper()} ({len(r.findings)} findings)")
                    all_results.append(r.to_dict())
        return all_results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TRON THE DLP AGENT File Watcher")
    parser.add_argument("--api", default="http://localhost:5001", help="DLP API URL")
    parser.add_argument("--dirs", nargs="+", help="Directories to watch")
    parser.add_argument("--scan-first", action="store_true", help="Scan existing files first")
    args = parser.parse_args()

    watcher = RealTimeWatcher(
        api_url=args.api,
        watch_dirs=args.dirs
    )

    if args.scan_first:
        print("\nInitial file scan...")
        results = watcher.scan_existing_files()
        if results:
            print(f"\nFound {len(results)} files with sensitive data")
        else:
            print("\nNo sensitive data found in existing files")

    watcher.start()
