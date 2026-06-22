#!/usr/bin/python3
# CanaryWatch — Personal Intrusion Detection System  (Enhanced Edition)
# Disclaimer: For defensive/educational use on your own systems only.
#
# New in this version:
#   • Dashboard tab — live stats, uptime, alert sparkline
#   • Network Canary — alert on unexpected connections to watched ports
#   • Registry Canary — alert when watched registry keys change
#   • Clipboard Canary — alert when clipboard content changes unexpectedly
#   • Fake AWS Credentials canary file
#   • Alert severity (LOW / MEDIUM / HIGH) with colour-coded log rows
#   • Alert detail popup (click any row)
#   • Per-canary enable / disable toggle without removing it
#   • System-tray icon — minimise silently to tray (requires pystray + Pillow)
#   • Optional sound alert (Windows Beep API)
#   • Auto-arm on startup option
#   • Test buttons for every notification channel in Config tab
#   • Graceful cross-platform no-op for Windows-only APIs

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import sys
import time
import json
import hashlib
import shutil
import smtplib
import random
import string
import subprocess
import socket
import platform
from pathlib import Path
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# optional deps — imported lazily so the app starts even if missing
try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    import watchdog.observers as wd_observers
    import watchdog.events as wd_events
    _HAS_WATCHDOG = True
except ImportError:
    _HAS_WATCHDOG = False

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import ctypes
    try:
        import winreg
        _HAS_WINREG = True
    except ImportError:
        _HAS_WINREG = False
else:
    _HAS_WINREG = False

# ── palette ───────────────────────────────────────────────────────────────────
BG      = "#090c10"
SURFACE = "#0d1117"
CARD    = "#161b22"
BORDER  = "#21262d"
ACCENT  = "#f78166"
ACCENT2 = "#58a6ff"
SUCCESS = "#3fb950"
DANGER  = "#f85149"
WARN    = "#e3b341"
TEXT    = "#e6edf3"
MUTED   = "#8b949e"
DIM     = "#484f58"
MONO    = "Courier New"
SANS    = "Segoe UI"

SEVERITY_COLOR = {
    "LOW":    ACCENT2,
    "MEDIUM": WARN,
    "HIGH":   DANGER,
}

CANARY_SEVERITY = {
    "File Canary":       "HIGH",
    "Folder Canary":     "MEDIUM",
    "USB Canary":        "HIGH",
    "Screenshot Canary": "MEDIUM",
    "Process Canary":    "MEDIUM",
    "Login Canary":      "HIGH",
    "Network Canary":    "HIGH",
    "Registry Canary":   "HIGH",
    "Clipboard Canary":  "LOW",
}

DATA_FILE = Path.home() / ".canarywatch" / "data.json"
LOG_FILE  = Path.home() / ".canarywatch" / "alerts.log"

# ── persistence ───────────────────────────────────────────────────────────────

def ensure_data_dir():
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)

def load_data() -> dict:
    ensure_data_dir()
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            pass
    return {"canaries": [], "alerts": [], "config": {}}

def save_data(data: dict):
    ensure_data_dir()
    DATA_FILE.write_text(json.dumps(data, indent=2))

def append_alert(data: dict, alert: dict):
    data["alerts"].insert(0, alert)
    data["alerts"] = data["alerts"][:1000]
    save_data(data)
    ensure_data_dir()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{alert['time']}] [{alert['severity']}] [{alert['type']}] {alert['message']}\n")

# ── sound ─────────────────────────────────────────────────────────────────────

def play_alert_sound():
    try:
        if IS_WINDOWS:
            import ctypes
            ctypes.windll.kernel32.Beep(880, 300)
            time.sleep(0.1)
            ctypes.windll.kernel32.Beep(660, 200)
        else:
            print("\a", end="", flush=True)
    except Exception:
        pass

# ── alert senders ─────────────────────────────────────────────────────────────

def send_email_alert(config: dict, subject: str, body: str):
    try:
        msg = MIMEMultipart()
        msg["From"]    = config["email_from"]
        msg["To"]      = config["email_to"]
        msg["Subject"] = f"🚨 CanaryWatch: {subject}"
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(config["email_from"], config["email_password"])
            s.sendmail(config["email_from"], config["email_to"], msg.as_string())
        return True
    except Exception as e:
        return str(e)

def send_telegram_alert(config: dict, message: str):
    if not _HAS_REQUESTS:
        return "requests not installed"
    try:
        token   = config["telegram_token"]
        chat_id = config["telegram_chat_id"]
        url     = f"https://api.telegram.org/bot{token}/sendMessage"
        r = requests.post(url, json={"chat_id": chat_id,
                                     "text": f"🚨 CanaryWatch\n\n{message}"},
                          timeout=5)
        return True if r.ok else r.text
    except Exception as e:
        return str(e)

def send_discord_alert(config: dict, message: str):
    if not _HAS_REQUESTS:
        return "requests not installed"
    try:
        r = requests.post(config["discord_webhook"],
                          json={"content": f"🚨 **CanaryWatch Alert**\n```\n{message}\n```"},
                          timeout=5)
        return True if r.ok else r.text
    except Exception as e:
        return str(e)

def dispatch_alert(data: dict, alert_type: str, message: str,
                   severity: str | None = None):
    if severity is None:
        severity = CANARY_SEVERITY.get(alert_type, "MEDIUM")
    alert = {
        "time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type":     alert_type,
        "severity": severity,
        "message":  message,
        "id":       ''.join(random.choices(string.hexdigits, k=8))
    }
    append_alert(data, alert)
    cfg = data.get("config", {})

    body = (f"Time:     {alert['time']}\n"
            f"Type:     {alert_type}\n"
            f"Severity: {severity}\n\n{message}")

    if cfg.get("sound_enabled"):
        threading.Thread(target=play_alert_sound, daemon=True).start()

    if cfg.get("email_enabled") and cfg.get("email_from"):
        threading.Thread(target=send_email_alert,
                         args=(cfg, alert_type, body), daemon=True).start()
    if cfg.get("telegram_enabled") and cfg.get("telegram_token"):
        threading.Thread(target=send_telegram_alert,
                         args=(cfg, body), daemon=True).start()
    if cfg.get("discord_enabled") and cfg.get("discord_webhook"):
        threading.Thread(target=send_discord_alert,
                         args=(cfg, body), daemon=True).start()

    return alert

# ── watchdog handlers ─────────────────────────────────────────────────────────

if _HAS_WATCHDOG:
    class FileCanaryHandler(wd_events.FileSystemEventHandler):
        def __init__(self, canary, data, callback):
            super().__init__()
            self.canary = canary; self.data = data; self.callback = callback

        def on_opened(self, event):
            if not event.is_directory and event.src_path == self.canary["path"]:
                self._fire(f"File opened: {event.src_path}")

        def on_modified(self, event):
            if not event.is_directory and event.src_path == self.canary["path"]:
                self._fire(f"File modified: {event.src_path}")

        def on_accessed(self, event):
            if not event.is_directory and event.src_path == self.canary["path"]:
                self._fire(f"File accessed: {event.src_path}")

        def _fire(self, msg):
            self.callback(dispatch_alert(self.data, self.canary["type"], msg))

    class FolderCanaryHandler(wd_events.FileSystemEventHandler):
        def __init__(self, canary, data, callback):
            super().__init__()
            self.canary = canary; self.data = data; self.callback = callback
            self._last = 0

        def on_any_event(self, event):
            now = time.time()
            if now - self._last < 2:
                return
            self._last = now
            msg = (f"Activity in watched folder: {self.canary['path']}\n"
                   f"Event: {event.event_type}  |  Path: {event.src_path}")
            self.callback(dispatch_alert(self.data, "Folder Canary", msg))

# ── USB monitor ───────────────────────────────────────────────────────────────

class USBMonitor(threading.Thread):
    def __init__(self, data, callback):
        super().__init__(daemon=True)
        self.data = data; self.callback = callback
        self._stop  = threading.Event()
        self._known = self._get_drives()

    def _get_drives(self) -> set:
        try:
            if IS_WINDOWS:
                out = subprocess.check_output(
                    ["wmic", "logicaldisk", "get", "DeviceID,DriveType"],
                    stderr=subprocess.DEVNULL).decode(errors="replace")
                drives = set()
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == "2":
                        drives.add(parts[0])
                return drives
            else:
                out = subprocess.check_output(
                    ["lsblk", "-o", "NAME,RM", "-J"],
                    stderr=subprocess.DEVNULL).decode(errors="replace")
                import re
                return set(re.findall(r'"name":"([^"]+)".*?"rm":"1"', out))
        except Exception:
            return set()

    def run(self):
        while not self._stop.wait(3):
            current = self._get_drives()
            for drive in current - self._known:
                msg = (f"New removable drive detected: {drive}\n"
                       f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                self.callback(dispatch_alert(self.data, "USB Canary", msg))
            self._known = current

    def stop(self): self._stop.set()

# ── Screenshot monitor ────────────────────────────────────────────────────────

class ScreenshotMonitor(threading.Thread):
    def __init__(self, data, callback):
        super().__init__(daemon=True)
        self.data = data; self.callback = callback
        self._stop = threading.Event()

    def run(self):
        if not IS_WINDOWS:
            return
        VK_SNAPSHOT = 0x2C
        last_state  = 0
        while not self._stop.wait(0.1):
            state = ctypes.windll.user32.GetAsyncKeyState(VK_SNAPSHOT)
            if state != 0 and state != last_state:
                msg = (f"Print Screen key detected!\n"
                       f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                self.callback(dispatch_alert(self.data, "Screenshot Canary", msg))
            last_state = state

    def stop(self): self._stop.set()

# ── Process monitor ───────────────────────────────────────────────────────────

class ProcessMonitor(threading.Thread):
    def __init__(self, process_names, data, callback):
        super().__init__(daemon=True)
        self.targets = [p.lower() for p in process_names]
        self.data = data; self.callback = callback
        self._stop = threading.Event()
        self._seen = set()

    def _running(self) -> set:
        try:
            if IS_WINDOWS:
                out = subprocess.check_output(
                    ["tasklist", "/fo", "csv", "/nh"],
                    stderr=subprocess.DEVNULL).decode(errors="replace")
                procs = set()
                for line in out.splitlines():
                    parts = line.strip('"').split('","')
                    if parts:
                        procs.add(parts[0].lower())
                return procs
            else:
                out = subprocess.check_output(
                    ["ps", "-e", "-o", "comm="],
                    stderr=subprocess.DEVNULL).decode(errors="replace")
                return {l.strip().lower() for l in out.splitlines() if l.strip()}
        except Exception:
            return set()

    def run(self):
        while not self._stop.wait(3):
            running = self._running()
            for target in self.targets:
                if target in running and target not in self._seen:
                    self._seen.add(target)
                    msg = (f"Watched process launched: {target}\n"
                           f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    self.callback(dispatch_alert(self.data, "Process Canary", msg))
                elif target not in running:
                    self._seen.discard(target)

    def stop(self): self._stop.set()

# ── Login monitor ─────────────────────────────────────────────────────────────

class LoginMonitor(threading.Thread):
    def __init__(self, data, callback):
        super().__init__(daemon=True)
        self.data = data; self.callback = callback
        self._stop = threading.Event()
        self._last = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    def run(self):
        while not self._stop.wait(10):
            if not IS_WINDOWS:
                continue
            try:
                cmd = (f'Get-WinEvent -FilterHashtable @{{LogName="Security";Id=4624;'
                       f'StartTime="{self._last}"}} -MaxEvents 5 -ErrorAction SilentlyContinue'
                       f' | Select-Object TimeCreated,Message | ConvertTo-Json')
                out = subprocess.check_output(
                    ["powershell", "-Command", cmd],
                    stderr=subprocess.DEVNULL, timeout=8
                ).decode(errors="replace").strip()
                if out and out != "null":
                    self._last = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
                    msg = (f"New Windows login event detected!\n"
                           f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                           f"Check Event Viewer → Security → Event 4624 for details.")
                    self.callback(dispatch_alert(self.data, "Login Canary", msg))
            except Exception:
                pass

    def stop(self): self._stop.set()

# ── Network Canary ────────────────────────────────────────────────────────────

class NetworkMonitor(threading.Thread):
    """Alert when a new connection appears on watched ports."""
    def __init__(self, ports: list, data, callback):
        super().__init__(daemon=True)
        self.ports    = set(int(p) for p in ports if str(p).strip().isdigit())
        self.data     = data
        self.callback = callback
        self._stop    = threading.Event()
        self._seen: set = set()

    def _get_connections(self) -> set:
        try:
            if IS_WINDOWS:
                out = subprocess.check_output(
                    ["netstat", "-ano", "-p", "TCP"],
                    stderr=subprocess.DEVNULL).decode(errors="replace")
            else:
                out = subprocess.check_output(
                    ["ss", "-tnp"],
                    stderr=subprocess.DEVNULL).decode(errors="replace")
            conns = set()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    # pick the local address column
                    local = parts[1] if not IS_WINDOWS else parts[1]
                    try:
                        port = int(local.rsplit(":", 1)[-1])
                        if port in self.ports:
                            conns.add((port, parts[3] if IS_WINDOWS else parts[3]))
                    except (ValueError, IndexError):
                        pass
            return conns
        except Exception:
            return set()

    def run(self):
        while not self._stop.wait(5):
            current = self._get_connections()
            new = current - self._seen
            for (port, state) in new:
                msg = (f"New connection on watched port {port}\n"
                       f"State: {state}\n"
                       f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                self.callback(dispatch_alert(self.data, "Network Canary", msg))
            self._seen = current

    def stop(self): self._stop.set()

# ── Registry Canary (Windows only) ───────────────────────────────────────────

class RegistryMonitor(threading.Thread):
    """Alert when a watched registry key's value changes."""
    def __init__(self, reg_paths: list, data, callback):
        super().__init__(daemon=True)
        self.reg_paths = reg_paths
        self.data      = data
        self.callback  = callback
        self._stop     = threading.Event()
        self._snapshots: dict = {}
        if _HAS_WINREG:
            self._snapshots = {p: self._read_key(p) for p in self.reg_paths}

    def _parse_path(self, path: str):
        hive_map = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        }
        parts    = path.replace("\\", "/").split("/", 1)
        hive_str = parts[0].upper()
        subkey   = parts[1] if len(parts) > 1 else ""
        hive     = hive_map.get(hive_str, winreg.HKEY_LOCAL_MACHINE)
        return hive, subkey

    def _read_key(self, path: str) -> dict:
        if not _HAS_WINREG:
            return {}
        try:
            hive, subkey = self._parse_path(path)
            values = {}
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        values[name] = data
                        i += 1
                    except OSError:
                        break
            return values
        except Exception:
            return {}

    def run(self):
        while not self._stop.wait(10):
            for path in self.reg_paths:
                current = self._read_key(path)
                prev    = self._snapshots.get(path, {})
                if current != prev:
                    added   = set(current) - set(prev)
                    removed = set(prev) - set(current)
                    changed = {k for k in current if k in prev and current[k] != prev[k]}
                    details = []
                    if added:   details.append(f"Added:   {', '.join(added)}")
                    if removed: details.append(f"Removed: {', '.join(removed)}")
                    if changed: details.append(f"Changed: {', '.join(changed)}")
                    msg = (f"Registry key modified: {path}\n" +
                           "\n".join(details) +
                           f"\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    self.callback(dispatch_alert(self.data, "Registry Canary", msg))
                    self._snapshots[path] = current

    def stop(self): self._stop.set()

# ── Clipboard Canary ──────────────────────────────────────────────────────────

class ClipboardMonitor(threading.Thread):
    """Alert when clipboard content changes (detects clipboard hijackers)."""
    def __init__(self, data, callback, root_widget):
        super().__init__(daemon=True)
        self.data      = data
        self.callback  = callback
        self.root      = root_widget
        self._stop     = threading.Event()
        self._last     = ""

    def _get_clipboard(self) -> str:
        try:
            return self.root.clipboard_get()
        except Exception:
            return ""

    def run(self):
        self._last = self._get_clipboard()
        while not self._stop.wait(2):
            current = self._get_clipboard()
            if current != self._last and current:
                preview = (current[:120] + "…") if len(current) > 120 else current
                msg = (f"Clipboard content changed!\n"
                       f"Length: {len(current)} chars\n"
                       f"Preview: {preview}\n"
                       f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                self.callback(dispatch_alert(self.data, "Clipboard Canary", msg))
                self._last = current

    def stop(self): self._stop.set()

# ── Canary file generators ─────────────────────────────────────────────────────

def create_fake_passwords_file(path: str):
    Path(path).write_text("""\
# My Passwords - DO NOT SHARE
# Last updated: 2024-01-15

[Email]
gmail:       john.doe.private@gmail.com / S3cur3P@ss2024!
outlook:     johndoe@outlook.com / MyP@ssw0rd#99

[Banking]
chase:       johndoe / Banking$ecure2024
paypal:      john.doe@email.com / P@yP@l$afe!

[Social]
facebook:    johndoe1990 / Faceb00k#2024
instagram:   john_doe_real / Insta$ecure!
twitter:     @johndoe / Tw1tter#Pass

[Work]
vpn:         jdoe / C0mp@nyVPN2024!
email:       j.doe@company.com / W0rkP@ss#24

[Crypto]
seed phrase: abandon ability able about above absent absorb abstract absurd abuse access accident
wallet:      0x742d35Cc6634C0532925a3b8D4C9B7F2a3c4D5E6
""")

def create_fake_private_key_file(path: str):
    Path(path).write_text("""\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29P2rFj7rS
pMHmMBT1FAKE3YcFAKEKEYDATAHEREXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx
FakePrivateKeyForCanaryPurposesOnlyDoNotUseThisForAnythingReal1234
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx
-----END RSA PRIVATE KEY-----
""")

def create_fake_config_file(path: str):
    Path(path).write_text("""\
{
  "database": {
    "host": "prod-db-server.internal",
    "port": 5432,
    "username": "admin",
    "password": "Pr0d$erver#2024!"
  },
  "api_keys": {
    "stripe": "sk_live_FAKE_CANARY_KEY_DO_NOT_USE_xxxxxxxxxxx",
    "aws_access": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  },
  "smtp": {
    "host": "mail.company.com",
    "user": "noreply@company.com",
    "pass": "M@ilS3rver2024!"
  }
}
""")

def create_fake_aws_credentials(path: str):
    Path(path).write_text("""\
[default]
aws_access_key_id     = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region                = us-east-1

[production]
aws_access_key_id     = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region                = us-west-2
""")

# ══════════════════════════════════════════════════════════════════════════════
# GUI
# ══════════════════════════════════════════════════════════════════════════════

class CanaryWatchApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CanaryWatch  —  Personal IDS")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(920, 660)

        self._data      = load_data()
        self._observers = []
        self._monitors  = []
        self._armed     = False
        self._start_time: datetime | None = None
        self._alert_history: list[int] = []   # counts per minute for sparkline

        self._build_ui()
        self._reload_alert_log()
        self._reload_canary_list()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._tick_dashboard()

        # auto-arm if configured
        if self._data.get("config", {}).get("auto_arm"):
            self.after(500, self._arm)

    # ── top-level UI ─────────────────────────────────────────────────────────

    def _build_ui(self):
        # top bar
        bar = tk.Frame(self, bg=BG, pady=12)
        bar.pack(fill="x", padx=24)
        tk.Label(bar, text="◈ CanaryWatch", font=(SANS, 18, "bold"),
                 bg=BG, fg=ACCENT).pack(side="left")
        self.status_lbl = tk.Label(bar, text="● DISARMED",
                                   font=(SANS, 9, "bold"), bg=BG, fg=DANGER)
        self.status_lbl.pack(side="left", padx=(16, 0))

        # tray button
        tk.Button(bar, text="⬇  Minimise to Tray", command=self._to_tray,
                  bg=BORDER, fg=MUTED, relief="flat",
                  font=(SANS, 9), padx=8, pady=6,
                  cursor="hand2").pack(side="right", padx=(0, 8))

        self.arm_btn = tk.Button(bar, text="▶  Arm All Canaries",
                                 command=self._toggle_arm,
                                 bg=SUCCESS, fg="#0d1117", relief="flat",
                                 font=(SANS, 9, "bold"), padx=12, pady=6,
                                 activebackground="#56d364", cursor="hand2")
        self.arm_btn.pack(side="right")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # notebook
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.TNotebook", background=BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab",
                        background=SURFACE, foreground=MUTED,
                        padding=[16, 8], font=(SANS, 9))
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", CARD)],
                  foreground=[("selected", TEXT)])

        nb = ttk.Notebook(self, style="Dark.TNotebook")
        nb.pack(fill="both", expand=True)

        self._tab_dash   = tk.Frame(nb, bg=BG)
        self._tab_deploy = tk.Frame(nb, bg=BG)
        self._tab_alerts = tk.Frame(nb, bg=BG)
        self._tab_config = tk.Frame(nb, bg=BG)

        nb.add(self._tab_dash,   text="  Dashboard  ")
        nb.add(self._tab_deploy, text="  Deploy  ")
        nb.add(self._tab_alerts, text="  Alert Log  ")
        nb.add(self._tab_config, text="  Config  ")

        self._build_dashboard_tab()
        self._build_deploy_tab()
        self._build_alerts_tab()
        self._build_config_tab()

    # ── Dashboard tab ─────────────────────────────────────────────────────────

    def _build_dashboard_tab(self):
        p = self._tab_dash

        top = tk.Frame(p, bg=BG)
        top.pack(fill="x", padx=24, pady=(20, 8))
        tk.Label(top, text="Live Overview", font=(SANS, 11, "bold"),
                 bg=BG, fg=TEXT).pack(side="left")

        # stat cards row
        cards_row = tk.Frame(p, bg=BG)
        cards_row.pack(fill="x", padx=24, pady=(0, 16))

        def stat_card(parent, label, textvars):
            f = tk.Frame(parent, bg=CARD, padx=18, pady=14,
                         highlightbackground=BORDER, highlightthickness=1)
            f.pack(side="left", padx=(0, 12), fill="y")
            tk.Label(f, text=label, font=(SANS, 8), bg=CARD, fg=MUTED).pack(anchor="w")
            lbl = tk.Label(f, textvariable=textvars, font=(MONO, 20, "bold"),
                           bg=CARD, fg=ACCENT2)
            lbl.pack(anchor="w")
            return lbl

        self._dash_status_var  = tk.StringVar(value="DISARMED")
        self._dash_uptime_var  = tk.StringVar(value="--:--:--")
        self._dash_total_var   = tk.StringVar(value="0")
        self._dash_canary_var  = tk.StringVar(value="0")
        self._dash_high_var    = tk.StringVar(value="0")

        lbl_status = stat_card(cards_row, "Status",        self._dash_status_var)
        stat_card(cards_row,              "Uptime",         self._dash_uptime_var)
        stat_card(cards_row,              "Total Alerts",   self._dash_total_var)
        stat_card(cards_row,              "Active Canaries",self._dash_canary_var)
        lbl_high   = stat_card(cards_row, "HIGH Severity",  self._dash_high_var)

        self._dash_status_lbl = lbl_status
        self._dash_high_lbl   = lbl_high

        # sparkline canvas
        spark_frame = tk.Frame(p, bg=CARD,
                               highlightbackground=BORDER, highlightthickness=1)
        spark_frame.pack(fill="x", padx=24, pady=(0, 16))
        tk.Label(spark_frame, text="Alert activity (last 30 min)",
                 font=(SANS, 8), bg=CARD, fg=MUTED).pack(anchor="w", padx=12, pady=(8, 0))
        self._spark_canvas = tk.Canvas(spark_frame, bg=CARD, height=70,
                                       highlightthickness=0)
        self._spark_canvas.pack(fill="x", padx=12, pady=(4, 10))

        # breakdown by type
        tk.Label(p, text="Alerts by type", font=(SANS, 9, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", padx=24, pady=(0, 6))
        self._breakdown_frame = tk.Frame(p, bg=BG)
        self._breakdown_frame.pack(fill="x", padx=24)

    def _tick_dashboard(self):
        """Update dashboard stats every second."""
        alerts = self._data.get("alerts", [])
        total  = len(alerts)
        high   = sum(1 for a in alerts if a.get("severity") == "HIGH")
        canaries = sum(1 for c in self._data.get("canaries", [])
                       if c.get("enabled", True))

        self._dash_total_var.set(str(total))
        self._dash_canary_var.set(str(canaries))
        self._dash_high_var.set(str(high))
        self._dash_high_lbl.config(fg=DANGER if high else ACCENT2)

        if self._armed:
            self._dash_status_var.set("ARMED")
            self._dash_status_lbl.config(fg=SUCCESS)
            if self._start_time:
                elapsed = datetime.now() - self._start_time
                h, rem  = divmod(int(elapsed.total_seconds()), 3600)
                m, s    = divmod(rem, 60)
                self._dash_uptime_var.set(f"{h:02d}:{m:02d}:{s:02d}")
        else:
            self._dash_status_var.set("DISARMED")
            self._dash_status_lbl.config(fg=DANGER)
            self._dash_uptime_var.set("--:--:--")

        # sparkline: count alerts in each of last 30 one-minute buckets
        now    = datetime.now()
        buckets = [0] * 30
        for a in alerts:
            try:
                t   = datetime.strptime(a["time"], "%Y-%m-%d %H:%M:%S")
                age = int((now - t).total_seconds() / 60)
                if 0 <= age < 30:
                    buckets[29 - age] += 1
            except Exception:
                pass
        self._draw_sparkline(buckets)

        # breakdown
        for w in self._breakdown_frame.winfo_children():
            w.destroy()
        from collections import Counter
        counts = Counter(a["type"] for a in alerts)
        for i, (typ, cnt) in enumerate(sorted(counts.items(),
                                              key=lambda x: -x[1])[:8]):
            sev  = CANARY_SEVERITY.get(typ, "MEDIUM")
            col  = SEVERITY_COLOR[sev]
            row  = tk.Frame(self._breakdown_frame, bg=BG)
            row.grid(row=i // 4, column=i % 4, padx=(0, 20), pady=2, sticky="w")
            tk.Label(row, text=f"● {typ}", font=(SANS, 8),
                     bg=BG, fg=col).pack(side="left")
            tk.Label(row, text=f"  {cnt}", font=(MONO, 8, "bold"),
                     bg=BG, fg=TEXT).pack(side="left")

        self.after(1000, self._tick_dashboard)

    def _draw_sparkline(self, buckets):
        c = self._spark_canvas
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 600
        h = 60
        n = len(buckets)
        if n == 0:
            return
        mx = max(buckets) or 1
        step = w / n
        pts  = []
        for i, v in enumerate(buckets):
            x = i * step + step / 2
            y = h - (v / mx) * (h - 4) - 2
            pts.extend([x, y])
        if len(pts) >= 4:
            c.create_line(*pts, fill=ACCENT2, width=2, smooth=True)
        # dots for non-zero
        for i, v in enumerate(buckets):
            if v:
                x = i * step + step / 2
                y = h - (v / mx) * (h - 4) - 2
                c.create_oval(x-3, y-3, x+3, y+3, fill=ACCENT, outline="")

    # ── Deploy tab ────────────────────────────────────────────────────────────

    def _build_deploy_tab(self):
        p = self._tab_deploy

        left = tk.Frame(p, bg=BG, width=360)
        left.pack(side="left", fill="both", padx=(16, 0), pady=16)
        left.pack_propagate(False)

        tk.Label(left, text="Active Canaries", font=(SANS, 10, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", pady=(0, 8))

        list_frame = tk.Frame(left, bg=CARD)
        list_frame.pack(fill="both", expand=True)

        self.canary_list = tk.Listbox(
            list_frame, bg=CARD, fg=TEXT, font=(SANS, 9),
            selectbackground=ACCENT, selectforeground="#0d1117",
            relief="flat", bd=0, activestyle="none", highlightthickness=0)
        self.canary_list.pack(fill="both", expand=True, padx=2, pady=2)

        btn_row = tk.Frame(left, bg=BG)
        btn_row.pack(fill="x", pady=(8, 0))
        tk.Button(btn_row, text="Remove", command=self._remove_canary,
                  bg=BORDER, fg=DANGER, relief="flat",
                  font=(SANS, 9), padx=8, pady=5, cursor="hand2").pack(side="left")
        tk.Button(btn_row, text="Toggle Enable", command=self._toggle_canary,
                  bg=BORDER, fg=WARN, relief="flat",
                  font=(SANS, 9), padx=8, pady=5, cursor="hand2").pack(side="left", padx=(6, 0))

        # right: cards grid
        right = tk.Frame(p, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=16, pady=16)
        tk.Label(right, text="Add New Canary", font=(SANS, 10, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", pady=(0, 12))

        cards = [
            ("📄 File Canary",        "Alert when a specific file is opened/modified",    self._add_file_canary),
            ("📁 Folder Canary",      "Alert when any activity occurs in a folder",        self._add_folder_canary),
            ("🔌 USB Canary",         "Alert when a USB drive is plugged in",              self._add_usb_canary),
            ("📸 Screenshot Canary",  "Alert when Print Screen is pressed",                self._add_screenshot_canary),
            ("⚙️ Process Canary",     "Alert when a watched process launches",             self._add_process_canary),
            ("🔐 Login Canary",       "Alert on any new Windows login event",              self._add_login_canary),
            ("🌐 Network Canary",     "Alert on new connections to watched ports",         self._add_network_canary),
            ("🗝️ Registry Canary",   "Alert when a watched registry key changes",         self._add_registry_canary),
            ("📋 Clipboard Canary",   "Alert when clipboard content changes",              self._add_clipboard_canary),
            ("🎣 Fake Passwords",     "Plant a fake passwords.txt as a tripwire",          self._deploy_fake_passwords),
            ("🔑 Fake Private Key",   "Plant a fake id_rsa as a tripwire",                 self._deploy_fake_key),
            ("🗄️ Fake Config",       "Plant a fake config.json as a tripwire",            self._deploy_fake_config),
            ("☁️ Fake AWS Creds",    "Plant a fake ~/.aws/credentials as a tripwire",     self._deploy_fake_aws),
        ]

        grid = tk.Frame(right, bg=BG)
        grid.pack(fill="both", expand=True)

        for i, (title, desc, cmd) in enumerate(cards):
            row, col = divmod(i, 3)
            card = tk.Frame(grid, bg=CARD, padx=12, pady=10,
                            highlightbackground=BORDER, highlightthickness=1)
            card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
            tk.Label(card, text=title, font=(SANS, 9, "bold"),
                     bg=CARD, fg=TEXT).pack(anchor="w")
            tk.Label(card, text=desc, font=(SANS, 8),
                     bg=CARD, fg=MUTED, wraplength=160, justify="left"
                     ).pack(anchor="w", pady=(4, 8))
            tk.Button(card, text="Deploy →", command=cmd,
                      bg=ACCENT, fg="#0d1117", relief="flat",
                      font=(SANS, 8, "bold"), padx=8, pady=4,
                      cursor="hand2").pack(anchor="w")
            grid.columnconfigure(col, weight=1)
            grid.rowconfigure(row, weight=1)

    # ── Alerts tab ────────────────────────────────────────────────────────────

    def _build_alerts_tab(self):
        p = self._tab_alerts

        # filter bar
        filter_bar = tk.Frame(p, bg=BG)
        filter_bar.pack(fill="x", padx=16, pady=(14, 4))
        tk.Label(filter_bar, text="Filter:", font=(SANS, 9),
                 bg=BG, fg=MUTED).pack(side="left")
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        tk.Entry(filter_bar, textvariable=self._filter_var, font=(MONO, 9),
                 bg=CARD, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=4, width=24).pack(side="left", padx=(6, 20))

        for sev, col in SEVERITY_COLOR.items():
            tk.Label(filter_bar, text=f"■ {sev}", font=(SANS, 8, "bold"),
                     bg=BG, fg=col).pack(side="left", padx=4)

        top = tk.Frame(p, bg=BG)
        top.pack(fill="x", padx=16, pady=(0, 6))
        tk.Label(top, text="Alert Log", font=(SANS, 10, "bold"),
                 bg=BG, fg=TEXT).pack(side="left")
        tk.Button(top, text="Clear Log", command=self._clear_alerts,
                  bg=BORDER, fg=DANGER, relief="flat",
                  font=(SANS, 9), padx=8, pady=4, cursor="hand2").pack(side="right")
        tk.Button(top, text="Export Log", command=self._export_log,
                  bg=BORDER, fg=ACCENT2, relief="flat",
                  font=(SANS, 9), padx=8, pady=4, cursor="hand2").pack(side="right", padx=(0, 6))

        cols = ("sev", "time", "type", "message")
        self.alert_tree = ttk.Treeview(p, columns=cols, show="headings",
                                       selectmode="browse")
        self.alert_tree.heading("sev",     text="Sev")
        self.alert_tree.heading("time",    text="Time")
        self.alert_tree.heading("type",    text="Type")
        self.alert_tree.heading("message", text="Message")
        self.alert_tree.column("sev",     width=60,  anchor="center")
        self.alert_tree.column("time",    width=140, anchor="w")
        self.alert_tree.column("type",    width=150, anchor="w")
        self.alert_tree.column("message", width=480, anchor="w")

        style = ttk.Style()
        style.configure("Treeview",
                        background=CARD, foreground=TEXT,
                        fieldbackground=CARD, rowheight=26,
                        font=(SANS, 9), borderwidth=0)
        style.configure("Treeview.Heading",
                        background=SURFACE, foreground=MUTED,
                        font=(SANS, 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", BORDER)],
                  foreground=[("selected", TEXT)])

        sb = ttk.Scrollbar(p, orient="vertical", command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.alert_tree.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.alert_tree.bind("<Double-1>", self._show_alert_detail)

        # tag colours for severity
        self.alert_tree.tag_configure("HIGH",   foreground=DANGER)
        self.alert_tree.tag_configure("MEDIUM", foreground=WARN)
        self.alert_tree.tag_configure("LOW",    foreground=ACCENT2)

    def _show_alert_detail(self, event=None):
        sel = self.alert_tree.selection()
        if not sel:
            return
        item = self.alert_tree.item(sel[0])
        vals = item["values"]
        if not vals:
            return
        win = tk.Toplevel(self, bg=CARD)
        win.title("Alert Detail")
        win.geometry("520x300")
        win.resizable(True, True)
        tk.Label(win, text=f"[{vals[0]}]  {vals[2]}", font=(SANS, 10, "bold"),
                 bg=CARD, fg=SEVERITY_COLOR.get(vals[0], TEXT)).pack(anchor="w", padx=16, pady=(12, 4))
        tk.Label(win, text=vals[1], font=(SANS, 8), bg=CARD, fg=MUTED).pack(anchor="w", padx=16)
        tk.Frame(win, height=1, bg=BORDER).pack(fill="x", padx=16, pady=8)
        # find full message from data
        full_msg = vals[3]
        for a in self._data.get("alerts", []):
            if a.get("time") == vals[1] and a.get("type") == vals[2]:
                full_msg = a.get("message", full_msg)
                break
        txt = tk.Text(win, bg=SURFACE, fg=TEXT, font=(MONO, 9),
                      relief="flat", padx=12, pady=8, wrap="word")
        txt.insert("1.0", full_msg)
        txt.config(state="disabled")
        txt.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    # ── Config tab ────────────────────────────────────────────────────────────

    def _build_config_tab(self):
        p = self._tab_config
        canvas = tk.Canvas(p, bg=BG, highlightthickness=0)
        scroll = ttk.Scrollbar(p, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        cfg = self._data.get("config", {})
        self._cfg_vars = {}

        def section(title):
            tk.Label(inner, text=title, font=(SANS, 11, "bold"),
                     bg=BG, fg=TEXT).pack(anchor="w", padx=24, pady=(20, 6))
            tk.Frame(inner, height=1, bg=BORDER).pack(fill="x", padx=24)

        def row(label, key, show=""):
            f = tk.Frame(inner, bg=BG)
            f.pack(fill="x", padx=24, pady=4)
            tk.Label(f, text=label, font=(SANS, 9), bg=BG, fg=MUTED,
                     width=22, anchor="w").pack(side="left")
            var = tk.StringVar(value=cfg.get(key, ""))
            e = tk.Entry(f, textvariable=var, font=(MONO, 9), width=38,
                         bg=CARD, fg=TEXT, insertbackground=ACCENT,
                         relief="flat", bd=4, show=show)
            e.pack(side="left")
            self._cfg_vars[key] = var

        def toggle(label, key):
            f = tk.Frame(inner, bg=BG)
            f.pack(fill="x", padx=24, pady=4)
            var = tk.BooleanVar(value=cfg.get(key, False))
            tk.Checkbutton(f, text=label, variable=var,
                           bg=BG, fg=TEXT, selectcolor=CARD,
                           activebackground=BG, font=(SANS, 9),
                           cursor="hand2").pack(side="left")
            self._cfg_vars[key] = var

        # Email
        section("📧 Email Alerts (Gmail)")
        toggle("Enable email alerts", "email_enabled")
        row("From address",  "email_from")
        row("App password",  "email_password", show="●")
        row("Send alerts to","email_to")
        f = tk.Frame(inner, bg=BG); f.pack(anchor="w", padx=24, pady=4)
        tk.Button(f, text="Test Email", cursor="hand2",
                  bg=BORDER, fg=ACCENT2, relief="flat", font=(SANS, 9), padx=8, pady=4,
                  command=self._test_email).pack(side="left")

        # Telegram
        section("✈️ Telegram Alerts")
        toggle("Enable Telegram alerts", "telegram_enabled")
        row("Bot token",  "telegram_token",  show="●")
        row("Chat ID",    "telegram_chat_id")
        f = tk.Frame(inner, bg=BG); f.pack(anchor="w", padx=24, pady=4)
        tk.Button(f, text="Test Telegram", cursor="hand2",
                  bg=BORDER, fg=ACCENT2, relief="flat", font=(SANS, 9), padx=8, pady=4,
                  command=self._test_telegram).pack(side="left")

        # Discord
        section("💬 Discord Alerts")
        toggle("Enable Discord alerts", "discord_enabled")
        row("Webhook URL", "discord_webhook", show="●")
        f = tk.Frame(inner, bg=BG); f.pack(anchor="w", padx=24, pady=4)
        tk.Button(f, text="Test Discord", cursor="hand2",
                  bg=BORDER, fg=ACCENT2, relief="flat", font=(SANS, 9), padx=8, pady=4,
                  command=self._test_discord).pack(side="left")

        # Misc
        section("🔔 Behaviour")
        toggle("Sound alert on trigger",         "sound_enabled")
        toggle("Auto-arm on startup",            "auto_arm")
        toggle("Show popup on every alert",      "popup_enabled")

        # Process watch list
        section("⚙️ Process Watch List")
        tk.Label(inner, text="Comma-separated names (e.g. taskmgr.exe, regedit.exe)",
                 font=(SANS, 8), bg=BG, fg=MUTED).pack(anchor="w", padx=24)
        f = tk.Frame(inner, bg=BG); f.pack(fill="x", padx=24, pady=4)
        var = tk.StringVar(value=cfg.get("watch_processes", "taskmgr.exe,regedit.exe,cmd.exe"))
        tk.Entry(f, textvariable=var, font=(MONO, 9), width=50,
                 bg=CARD, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=4).pack(side="left")
        self._cfg_vars["watch_processes"] = var

        # Network ports
        section("🌐 Network Watch Ports")
        tk.Label(inner, text="Comma-separated port numbers to watch (e.g. 22,3389,5900)",
                 font=(SANS, 8), bg=BG, fg=MUTED).pack(anchor="w", padx=24)
        f = tk.Frame(inner, bg=BG); f.pack(fill="x", padx=24, pady=4)
        var = tk.StringVar(value=cfg.get("watch_ports", "22,3389,5900,4444"))
        tk.Entry(f, textvariable=var, font=(MONO, 9), width=40,
                 bg=CARD, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=4).pack(side="left")
        self._cfg_vars["watch_ports"] = var

        # Registry paths
        section("🗝️ Registry Watch Paths")
        tk.Label(inner,
                 text="Comma-separated paths (e.g. HKCU\\Software\\Microsoft\\Windows\\Run)",
                 font=(SANS, 8), bg=BG, fg=MUTED).pack(anchor="w", padx=24)
        f = tk.Frame(inner, bg=BG); f.pack(fill="x", padx=24, pady=4)
        default_reg = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        var = tk.StringVar(value=cfg.get("watch_registry", default_reg))
        tk.Entry(f, textvariable=var, font=(MONO, 9), width=60,
                 bg=CARD, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=4).pack(side="left")
        self._cfg_vars["watch_registry"] = var

        # save
        tk.Button(inner, text="Save Configuration",
                  command=self._save_config,
                  bg=ACCENT2, fg="#0d1117", relief="flat",
                  font=(SANS, 10, "bold"), padx=16, pady=8,
                  cursor="hand2").pack(anchor="w", padx=24, pady=20)

    # ── config test buttons ───────────────────────────────────────────────────

    def _test_email(self):
        self._save_config()
        cfg = self._data["config"]
        result = send_email_alert(cfg, "Test", "This is a test alert from CanaryWatch.")
        if result is True:
            messagebox.showinfo("Email Test", "Test email sent successfully!")
        else:
            messagebox.showerror("Email Test Failed", str(result))

    def _test_telegram(self):
        self._save_config()
        cfg = self._data["config"]
        result = send_telegram_alert(cfg, "This is a test alert from CanaryWatch.")
        if result is True:
            messagebox.showinfo("Telegram Test", "Test message sent!")
        else:
            messagebox.showerror("Telegram Test Failed", str(result))

    def _test_discord(self):
        self._save_config()
        cfg = self._data["config"]
        result = send_discord_alert(cfg, "This is a test alert from CanaryWatch.")
        if result is True:
            messagebox.showinfo("Discord Test", "Test message sent!")
        else:
            messagebox.showerror("Discord Test Failed", str(result))

    # ── canary actions ────────────────────────────────────────────────────────

    def _add_file_canary(self):
        path = filedialog.askopenfilename(title="Select file to watch")
        if path:
            self._register_canary({"type": "File Canary", "path": path})

    def _add_folder_canary(self):
        path = filedialog.askdirectory(title="Select folder to watch")
        if path:
            self._register_canary({"type": "Folder Canary", "path": path})

    def _add_usb_canary(self):
        self._register_canary({"type": "USB Canary", "path": "system"})

    def _add_screenshot_canary(self):
        self._register_canary({"type": "Screenshot Canary", "path": "system"})

    def _add_process_canary(self):
        procs = self._data["config"].get("watch_processes", "taskmgr.exe,regedit.exe")
        self._register_canary({"type": "Process Canary", "path": procs})

    def _add_login_canary(self):
        self._register_canary({"type": "Login Canary", "path": "system"})

    def _add_network_canary(self):
        ports = self._data["config"].get("watch_ports", "22,3389,5900,4444")
        self._register_canary({"type": "Network Canary", "path": ports,
                                "label": f"Network: ports {ports}"})

    def _add_registry_canary(self):
        if not IS_WINDOWS:
            messagebox.showinfo("Not supported", "Registry Canary is Windows-only.")
            return
        paths = self._data["config"].get(
            "watch_registry",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
        self._register_canary({"type": "Registry Canary", "path": paths,
                                "label": "Registry Canary"})

    def _add_clipboard_canary(self):
        self._register_canary({"type": "Clipboard Canary", "path": "system"})

    def _deploy_fake_passwords(self):
        path = filedialog.asksaveasfilename(
            title="Save fake passwords file",
            initialfile="passwords.txt", defaultextension=".txt")
        if not path:
            return
        create_fake_passwords_file(path)
        self._register_canary({"type": "File Canary", "path": path,
                                "label": "Fake Passwords"})
        messagebox.showinfo("Deployed", f"Fake passwords file planted at:\n{path}")

    def _deploy_fake_key(self):
        path = filedialog.asksaveasfilename(
            title="Save fake private key", initialfile="id_rsa", defaultextension="")
        if not path:
            return
        create_fake_private_key_file(path)
        self._register_canary({"type": "File Canary", "path": path,
                                "label": "Fake Private Key"})
        messagebox.showinfo("Deployed", f"Fake private key planted at:\n{path}")

    def _deploy_fake_config(self):
        path = filedialog.asksaveasfilename(
            title="Save fake config", initialfile="config.json", defaultextension=".json")
        if not path:
            return
        create_fake_config_file(path)
        self._register_canary({"type": "File Canary", "path": path,
                                "label": "Fake Config"})
        messagebox.showinfo("Deployed", f"Fake config planted at:\n{path}")

    def _deploy_fake_aws(self):
        default = Path.home() / ".aws" / "credentials"
        path = filedialog.asksaveasfilename(
            title="Save fake AWS credentials",
            initialfile=str(default),
            defaultextension="")
        if not path:
            return
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        create_fake_aws_credentials(path)
        self._register_canary({"type": "File Canary", "path": path,
                                "label": "Fake AWS Credentials"})
        messagebox.showinfo("Deployed", f"Fake AWS credentials planted at:\n{path}")

    def _register_canary(self, canary: dict):
        for c in self._data["canaries"]:
            if c["type"] == canary["type"] and c["path"] == canary["path"]:
                messagebox.showinfo("Already exists", "This canary is already in the list.")
                return
        canary["id"]      = ''.join(random.choices(string.hexdigits, k=8))
        canary["enabled"] = True
        self._data["canaries"].append(canary)
        save_data(self._data)
        self._reload_canary_list()

    def _remove_canary(self):
        sel = self.canary_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx < len(self._data["canaries"]):
            self._data["canaries"].pop(idx)
            save_data(self._data)
            self._reload_canary_list()

    def _toggle_canary(self):
        sel = self.canary_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx < len(self._data["canaries"]):
            c = self._data["canaries"][idx]
            c["enabled"] = not c.get("enabled", True)
            save_data(self._data)
            self._reload_canary_list()

    def _reload_canary_list(self):
        self.canary_list.delete(0, "end")
        for c in self._data["canaries"]:
            label   = c.get("label", c["type"])
            path    = c["path"] if c["path"] != "system" else "(system-wide)"
            enabled = c.get("enabled", True)
            prefix  = "✔" if enabled else "✘"
            self.canary_list.insert("end", f"  {prefix}  {label}  |  {path}")
            last = self.canary_list.size() - 1
            self.canary_list.itemconfig(last,
                                        fg=TEXT if enabled else DIM)

    # ── arm / disarm ──────────────────────────────────────────────────────────

    def _toggle_arm(self):
        self._disarm() if self._armed else self._arm()

    def _arm(self):
        active = [c for c in self._data["canaries"] if c.get("enabled", True)]
        if not active:
            messagebox.showwarning("No canaries", "Deploy and enable at least one canary first.")
            return

        cfg       = self._data.get("config", {})
        procs_str = cfg.get("watch_processes", "taskmgr.exe,regedit.exe")
        proc_list = [p.strip() for p in procs_str.split(",") if p.strip()]
        ports_str = cfg.get("watch_ports", "22,3389,5900")
        port_list = [p.strip() for p in ports_str.split(",") if p.strip()]
        reg_str   = cfg.get("watch_registry", "")
        reg_list  = [r.strip() for r in reg_str.split(",") if r.strip()]

        for canary in active:
            ctype = canary["type"]
            path  = canary["path"]

            if ctype == "File Canary" and _HAS_WATCHDOG:
                try:
                    folder   = str(Path(path).parent)
                    handler  = FileCanaryHandler(canary, self._data, self._on_alert)
                    observer = wd_observers.Observer()
                    observer.schedule(handler, folder, recursive=False)
                    observer.start()
                    self._observers.append(observer)
                except Exception as e:
                    self._log_ui(f"Failed to watch {path}: {e}")

            elif ctype == "Folder Canary" and _HAS_WATCHDOG:
                try:
                    handler  = FolderCanaryHandler(canary, self._data, self._on_alert)
                    observer = wd_observers.Observer()
                    observer.schedule(handler, path, recursive=True)
                    observer.start()
                    self._observers.append(observer)
                except Exception as e:
                    self._log_ui(f"Failed to watch {path}: {e}")

            elif ctype == "USB Canary":
                m = USBMonitor(self._data, self._on_alert)
                m.start(); self._monitors.append(m)

            elif ctype == "Screenshot Canary":
                m = ScreenshotMonitor(self._data, self._on_alert)
                m.start(); self._monitors.append(m)

            elif ctype == "Process Canary":
                m = ProcessMonitor(proc_list, self._data, self._on_alert)
                m.start(); self._monitors.append(m)

            elif ctype == "Login Canary":
                m = LoginMonitor(self._data, self._on_alert)
                m.start(); self._monitors.append(m)

            elif ctype == "Network Canary":
                m = NetworkMonitor(port_list, self._data, self._on_alert)
                m.start(); self._monitors.append(m)

            elif ctype == "Registry Canary":
                m = RegistryMonitor(reg_list, self._data, self._on_alert)
                m.start(); self._monitors.append(m)

            elif ctype == "Clipboard Canary":
                m = ClipboardMonitor(self._data, self._on_alert, self)
                m.start(); self._monitors.append(m)

        self._armed      = True
        self._start_time = datetime.now()
        self.arm_btn.config(text="■  Disarm", bg=DANGER, activebackground="#ff7b72")
        self.status_lbl.config(text="● ARMED", fg=SUCCESS)

    def _disarm(self):
        for obs in self._observers:
            try: obs.stop(); obs.join(timeout=2)
            except Exception: pass
        for mon in self._monitors:
            try: mon.stop()
            except Exception: pass
        self._observers.clear()
        self._monitors.clear()
        self._armed      = False
        self._start_time = None
        self.arm_btn.config(text="▶  Arm All Canaries", bg=SUCCESS,
                            activebackground="#56d364")
        self.status_lbl.config(text="● DISARMED", fg=DANGER)

    # ── alert handling ────────────────────────────────────────────────────────

    def _on_alert(self, alert: dict):
        self.after(0, self._show_alert, alert)

    def _show_alert(self, alert: dict):
        self.title(f"🚨 ALERT — {alert['type']}  |  CanaryWatch")
        self.after(4000, lambda: self.title("CanaryWatch  —  Personal IDS"))

        sev = alert.get("severity", "MEDIUM")
        self.alert_tree.insert("", 0,
                               values=(sev, alert["time"], alert["type"],
                                       alert["message"].split("\n")[0]),
                               tags=(sev,))

        if self._data.get("config", {}).get("popup_enabled", True):
            messagebox.showwarning(
                "🚨 CanaryWatch Alert",
                f"[{sev}]  {alert['type']}\n\n{alert['message']}")

    def _reload_alert_log(self):
        self.alert_tree.delete(*self.alert_tree.get_children())
        for a in self._data.get("alerts", []):
            sev = a.get("severity", "MEDIUM")
            self.alert_tree.insert("", "end",
                                   values=(sev, a["time"], a["type"],
                                           a["message"].split("\n")[0]),
                                   tags=(sev,))

    def _apply_filter(self):
        query = self._filter_var.get().lower()
        self.alert_tree.delete(*self.alert_tree.get_children())
        for a in self._data.get("alerts", []):
            if (query in a.get("type", "").lower() or
                    query in a.get("message", "").lower() or
                    query in a.get("severity", "").lower()):
                sev = a.get("severity", "MEDIUM")
                self.alert_tree.insert("", "end",
                                       values=(sev, a["time"], a["type"],
                                               a["message"].split("\n")[0]),
                                       tags=(sev,))

    def _clear_alerts(self):
        if messagebox.askyesno("Clear log", "Clear all alerts from log?"):
            self._data["alerts"] = []
            save_data(self._data)
            self.alert_tree.delete(*self.alert_tree.get_children())

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            title="Export alert log",
            initialfile="canarywatch_alerts.txt",
            defaultextension=".txt")
        if path and LOG_FILE.exists():
            shutil.copy(LOG_FILE, path)
            messagebox.showinfo("Exported", f"Log saved to:\n{path}")

    def _log_ui(self, msg):
        print(msg)

    # ── config ────────────────────────────────────────────────────────────────

    def _save_config(self):
        cfg = {}
        for key, var in self._cfg_vars.items():
            cfg[key] = var.get()
        self._data["config"] = cfg
        save_data(self._data)
        messagebox.showinfo("Saved", "Configuration saved.")

    # ── system tray ──────────────────────────────────────────────────────────

    def _to_tray(self):
        try:
            import pystray
            from PIL import Image, ImageDraw
        except ImportError:
            messagebox.showinfo(
                "System Tray",
                "Install pystray and Pillow to use this feature:\n"
                "  pip install pystray Pillow")
            return

        self.withdraw()

        def make_icon():
            img  = Image.new("RGB", (64, 64), color="#090c10")
            draw = ImageDraw.Draw(img)
            draw.ellipse([8, 8, 56, 56], fill="#f78166")
            draw.ellipse([20, 20, 44, 44], fill="#090c10")
            return img

        def restore(icon, item):
            icon.stop()
            self.after(0, self.deiconify)

        def quit_app(icon, item):
            icon.stop()
            self.after(0, self._on_close)

        status_text = "Armed" if self._armed else "Disarmed"
        menu = pystray.Menu(
            pystray.MenuItem(f"CanaryWatch ({status_text})", None, enabled=False),
            pystray.MenuItem("Open", restore, default=True),
            pystray.MenuItem("Quit", quit_app),
        )
        icon = pystray.Icon("CanaryWatch", make_icon(), "CanaryWatch", menu)
        threading.Thread(target=icon.run, daemon=True).start()

    # ── close ─────────────────────────────────────────────────────────────────

    def _on_close(self):
        self._disarm()
        self.destroy()


# ── entry point ───────────────────────────────────────────────────────────────

def _ensure_deps():
    needed = []
    try: import watchdog
    except ImportError: needed.append("watchdog")
    try: import requests
    except ImportError: needed.append("requests")
    if needed:
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               *needed, "--break-system-packages", "-q"])

if __name__ == "__main__":
    _ensure_deps()
    app = CanaryWatchApp()
    app.mainloop()
