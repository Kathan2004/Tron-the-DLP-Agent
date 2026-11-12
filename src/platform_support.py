"""
Operating-system specifics for the endpoint agents (macOS, Linux, Windows).

Everything that shells out or touches an OS-specific path lives here so the monitors stay
platform-neutral. Parsers take the command output as an argument and are unit-tested with
captured output; the functions that run the commands are thin wrappers around them.
"""

from __future__ import annotations

import csv
import getpass
import io
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW: no console flash per poll


def hostname() -> str:
    return os.getenv("TRON_DEVICE_NAME") or platform.node() or os.getenv("COMPUTERNAME") or "unknown-host"


def username() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.getenv("USER") or os.getenv("USERNAME") or "unknown"


def os_label() -> str:
    return f"{platform.system()} {platform.release()}".strip() or sys.platform


def state_dir() -> Path:
    """Per-user directory for agent credentials and the offline spool."""
    override = os.getenv("TRON_AGENT_STATE_DIR")
    if override:
        return Path(override)
    if IS_WINDOWS:
        base = os.getenv("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "Tron"
    return Path.home() / ".tron"


def _run(argv: List[str], timeout: float = 10) -> str:
    """Run a fixed argv (never a shell string) and return stdout, '' on any failure."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                errors="replace", creationflags=_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _powershell(script: str, timeout: float = 15) -> str:
    return _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout)


# ---------------------------------------------------------------- clipboard

def read_clipboard() -> Optional[str]:
    """Current clipboard text, or None when no clipboard tool is available."""
    if IS_MAC:
        candidates = [["pbpaste"]]
    elif IS_WINDOWS:
        candidates = [["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"]]
    else:
        candidates = []
        if os.getenv("WAYLAND_DISPLAY"):
            candidates.append(["wl-paste", "--no-newline"])
        candidates += [["xclip", "-selection", "clipboard", "-o"], ["xsel", "--clipboard", "--output"]]
    for argv in candidates:
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=3, errors="replace",
                                    creationflags=_NO_WINDOW)
        except FileNotFoundError:
            continue
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode == 0:
            return result.stdout
    return None


# ---------------------------------------------------------------- USB / removable media

def parse_windows_usb(json_text: str) -> List[Dict]:
    """Parse `Get-PnpDevice -Class USB,DiskDrive -PresentOnly | ConvertTo-Json` output."""
    try:
        data = json.loads(json_text or "[]")
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    devices = []
    for item in data if isinstance(data, list) else []:
        instance = str(item.get("InstanceId") or "")
        if not instance.upper().startswith(("USB\\", "USBSTOR\\")):
            continue
        ids = {k: v for k, v in (part.split("_", 1) for part in instance.split("\\")[1].split("&") if "_" in part)}
        devices.append({
            "name": str(item.get("FriendlyName") or "USB device"),
            "vendor": str(item.get("Manufacturer") or ""),
            "vendor_id": ids.get("VID", ""),
            "product_id": ids.get("PID", ""),
            "serial": instance.split("\\")[-1],
        })
    return devices


def usb_devices_linux(sys_root: str = "/sys/bus/usb/devices") -> List[Dict]:
    devices = []
    root = Path(sys_root)
    if not root.is_dir():
        return devices

    def read(path: Path) -> str:
        try:
            return path.read_text(errors="replace").strip()
        except OSError:
            return ""

    for dev in sorted(root.iterdir()):
        vendor_id = read(dev / "idVendor")
        if not vendor_id:
            continue
        if read(dev / "bDeviceClass") == "09":  # hubs
            continue
        devices.append({
            "name": read(dev / "product") or "USB device",
            "vendor": read(dev / "manufacturer"),
            "vendor_id": vendor_id,
            "product_id": read(dev / "idProduct"),
            "serial": read(dev / "serial") or dev.name,
        })
    return devices


def usb_devices() -> Optional[List[Dict]]:
    """Connected USB devices on Linux and Windows; None on macOS (handled by system_profiler)."""
    if IS_LINUX:
        return usb_devices_linux()
    if IS_WINDOWS:
        return parse_windows_usb(_powershell(
            "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB*' } | "
            "Select-Object FriendlyName,Manufacturer,InstanceId | ConvertTo-Json -Compress"))
    return None


def parse_windows_volumes(json_text: str) -> List[Dict]:
    """Parse `Get-CimInstance Win32_LogicalDisk -Filter DriveType=2 | ConvertTo-Json`."""
    try:
        data = json.loads(json_text or "[]")
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [{"name": str(d.get("VolumeName") or d.get("DeviceID") or "removable"),
             "path": f"{d.get('DeviceID')}\\", "type": "external"}
            for d in data if isinstance(d, dict) and d.get("DeviceID")]


def removable_volumes() -> List[Dict]:
    volumes: List[Dict] = []
    if IS_MAC:
        root = Path("/Volumes")
        if root.exists():
            for vol in root.iterdir():
                if vol.name != "Macintosh HD" and (vol.is_dir() or vol.is_mount()):
                    volumes.append({"name": vol.name, "path": str(vol), "type": "external"})
    elif IS_LINUX:
        user = username()
        for base in (Path("/media") / user, Path("/run/media") / user, Path("/mnt")):
            if base.is_dir():
                for vol in base.iterdir():
                    if vol.is_mount():
                        volumes.append({"name": vol.name, "path": str(vol), "type": "external"})
    elif IS_WINDOWS:
        volumes = parse_windows_volumes(_powershell(
            "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | "
            "Select-Object DeviceID,VolumeName | ConvertTo-Json -Compress"))
    return volumes


# ---------------------------------------------------------------- processes / network (Windows)

def parse_tasklist(csv_text: str) -> List[Dict]:
    """Parse `tasklist /FO CSV /NH` output."""
    processes = []
    for row in csv.reader(io.StringIO(csv_text or "")):
        if len(row) < 2 or not row[1].strip().isdigit():
            continue
        processes.append({"user": "", "pid": int(row[1]), "cpu": 0.0, "mem": 0.0,
                          "command": row[0], "process_name": row[0]})
    return processes


def parse_netstat(netstat_text: str, process_names: Optional[Dict[int, str]] = None) -> List[Dict]:
    """Parse `netstat -ano -p TCP` output into the connection dicts NetworkMonitor uses."""
    names = process_names or {}
    connections = []
    for line in (netstat_text or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP" or parts[3].upper() != "ESTABLISHED":
            continue
        remote_addr, _, remote_port = parts[2].rpartition(":")
        local_addr = parts[1].rpartition(":")[0]
        pid = int(parts[4]) if parts[4].isdigit() else 0
        connections.append({
            "process": names.get(pid, f"pid-{pid}"), "pid": pid, "user": "",
            "local_addr": local_addr.strip("[]"), "remote_addr": remote_addr.strip("[]"),
            "remote_port": int(remote_port) if remote_port.isdigit() else 0,
            "domain": "", "state": "ESTABLISHED",
        })
    return connections


def windows_processes() -> List[Dict]:
    return parse_tasklist(_run(["tasklist.exe", "/FO", "CSV", "/NH"]))


def windows_connections() -> List[Dict]:
    names = {p["pid"]: p["process_name"] for p in windows_processes()}
    return parse_netstat(_run(["netstat.exe", "-ano", "-p", "TCP"]), names)


# ---------------------------------------------------------------- well-known paths

def watch_directories() -> List[str]:
    home = Path.home()
    return [str(home / name) for name in ("Downloads", "Documents", "Desktop") if (home / name).is_dir()]


def chromium_history_files() -> List[Path]:
    """History databases of Chromium-family browsers for the current user."""
    home = Path.home()
    if IS_MAC:
        bases = [home / "Library/Application Support/Google/Chrome",
                 home / "Library/Application Support/Microsoft Edge",
                 home / "Library/Application Support/BraveSoftware/Brave-Browser"]
    elif IS_WINDOWS:
        local = Path(os.getenv("LOCALAPPDATA") or home / "AppData" / "Local")
        bases = [local / "Google/Chrome/User Data", local / "Microsoft/Edge/User Data",
                 local / "BraveSoftware/Brave-Browser/User Data"]
    else:
        bases = [home / ".config/google-chrome", home / ".config/chromium",
                 home / ".config/microsoft-edge", home / ".config/BraveSoftware/Brave-Browser"]
    return [p for p in (base / "Default" / "History" for base in bases) if p.exists()]


def shell_history_files() -> List[Path]:
    home = Path.home()
    files = [home / ".bash_history", home / ".zsh_history", home / ".local/share/fish/fish_history"]
    if IS_WINDOWS:
        appdata = Path(os.getenv("APPDATA") or home / "AppData" / "Roaming")
        files.append(appdata / "Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt")
    else:
        files.append(home / ".local/share/powershell/PSReadLine/ConsoleHost_history.txt")
    return [f for f in files if f.exists()]
