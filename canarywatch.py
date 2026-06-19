#!/usr/bin/python3
# CanaryWatch — Personal Intrusion Detection System
# Disclaimer: For defensive/educational use on your own systems only.

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
import requests
import winreg
import ctypes
import random
import string
import subprocess
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import watchdog.observers as wd_observers
import watchdog.events as wd_events

# ── palette ───────────────────────────────────────────────────────────────────
BG       = "#090c10"
SURFACE  = "#0d1117"
CARD     = "#161b22"
BORDER   = "#21262d"
ACCENT   = "#f78166"   # warm coral — threat/alert energy
ACCENT2  = "#58a6ff"   # blue — info/status
SUCCESS  = "#3fb950"
DANGER   = "#f85149"
WARN     = "#e3b341"
TEXT     = "#e6edf3"
MUTED    = "#8b949e"
DIM      = "#484f58"
MONO     = "Courier New"
SANS     = "Segoe UI"

DATA_FILE = Path.home() / ".canarywatch" / "data.json"
LOG_FILE  = Path.home() / ".canarywatch" / "alerts.log"

# ── persistence helpers ────────────────────────────────────────────────────────

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
    data["alerts"] = data["alerts"][:500]   # keep last 500
    save_data(data)
    # also write to log file
    ensure_data_dir()
    with open(LOG_FILE, "a") as f:
        f.write(f"[{alert['time']}] [{alert['type']}] {alert['message']}\n")

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
        return False

def send_telegram_alert(config: dict, message: str):
    try:
        token   = config["telegram_token"]
        chat_id = config["telegram_chat_id"]
        url     = f"https://api.telegram.org/bot{token}/sendMessage"
        requests.post(url, json={"chat_id": chat_id,
                                 "text": f"🚨 CanaryWatch\n\n{message}"},
                      timeout=5)
        return True
    except Exception:
        return False

def send_discord_alert(config: dict, message: str):
    try:
        requests.post(config["discord_webhook"],
                      json={"content": f"🚨 **CanaryWatch Alert**\n```\n{message}\n```"},
                      timeout=5)
        return True
    except Exception:
        return False

def dispatch_alert(data: dict, alert_type: str, message: str):
    """Log + send all configured alerts."""
    alert = {
        "time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type":    alert_type,
        "message": message,
        "id":      ''.join(random.choices(string.hexdigits, k=8))
    }
    append_alert(data, alert)
    cfg = data.get("config", {})

    body = f"Time: {alert['time']}\nType: {alert_type}\n\n{message}"

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

class FileCanaryHandler(wd_events.FileSystemEventHandler):
    def __init__(self, canary: dict, data: dict, callback):
        super().__init__()
        self.canary   = canary
        self.data     = data
        self.callback = callback

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
        alert = dispatch_alert(self.data, self.canary["type"], msg)
        self.callback(alert)

class FolderCanaryHandler(wd_events.FileSystemEventHandler):
    def __init__(self, canary: dict, data: dict, callback):
        super().__init__()
        self.canary   = canary
        self.data     = data
        self.callback = callback
        self._last    = 0

    def on_any_event(self, event):
        now = time.time()
        if now - self._last < 2:   # debounce 2s
            return
        self._last = now
        alert = dispatch_alert(
            self.data, "Folder Canary",
            f"Activity detected in watched folder: {self.canary['path']}\n"
            f"Event: {event.event_type}  |  Path: {event.src_path}"
        )
        self.callback(alert)

# ── USB monitor ───────────────────────────────────────────────────────────────

class USBMonitor(threading.Thread):
    def __init__(self, data: dict, callback):
        super().__init__(daemon=True)
        self.data     = data
        self.callback = callback
        self._stop    = threading.Event()
        self._known   = self._get_drives()

    def _get_drives(self) -> set:
        try:
            out = subprocess.check_output(
                ["wmic", "logicaldisk", "get", "DeviceID,DriveType"],
                stderr=subprocess.DEVNULL).decode(errors="replace")
            drives = set()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == "2":   # type 2 = removable
                    drives.add(parts[0])
            return drives
        except Exception:
            return set()

    def run(self):
        while not self._stop.wait(3):
            current = self._get_drives()
            new = current - self._known
            for drive in new:
                alert = dispatch_alert(
                    self.data, "USB Canary",
                    f"New removable drive detected: {drive}\n"
                    f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                self.callback(alert)
            self._known = current

    def stop(self):
        self._stop.set()

# ── Screenshot monitor ────────────────────────────────────────────────────────

class ScreenshotMonitor(threading.Thread):
    """Detect Print Screen key presses via Windows API polling."""
    def __init__(self, data: dict, callback):
        super().__init__(daemon=True)
        self.data     = data
        self.callback = callback
        self._stop    = threading.Event()

    def run(self):
        VK_SNAPSHOT = 0x2C
        last_state = 0
        while not self._stop.wait(0.1):
            state = ctypes.windll.user32.GetAsyncKeyState(VK_SNAPSHOT)
            if state != 0 and state != last_state:
                alert = dispatch_alert(
                    self.data, "Screenshot Canary",
                    "Print Screen key detected!\n"
                    f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                self.callback(alert)
            last_state = state

    def stop(self):
        self._stop.set()

# ── Process monitor ───────────────────────────────────────────────────────────

class ProcessMonitor(threading.Thread):
    """Alert when a watched process name appears."""
    def __init__(self, process_names: list, data: dict, callback):
        super().__init__(daemon=True)
        self.targets  = [p.lower() for p in process_names]
        self.data     = data
        self.callback = callback
        self._stop    = threading.Event()
        self._seen    = set()

    def _running(self) -> set:
        try:
            out = subprocess.check_output(
                ["tasklist", "/fo", "csv", "/nh"],
                stderr=subprocess.DEVNULL).decode(errors="replace")
            procs = set()
            for line in out.splitlines():
                parts = line.strip('"').split('","')
                if parts:
                    procs.add(parts[0].lower())
            return procs
        except Exception:
            return set()

    def run(self):
        while not self._stop.wait(3):
            running = self._running()
            for target in self.targets:
                if target in running and target not in self._seen:
                    self._seen.add(target)
                    alert = dispatch_alert(
                        self.data, "Process Canary",
                        f"Watched process launched: {target}\n"
                        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    self.callback(alert)
                elif target not in running:
                    self._seen.discard(target)

    def stop(self):
        self._stop.set()

# ── Login monitor ─────────────────────────────────────────────────────────────

class LoginMonitor(threading.Thread):
    """Poll Windows Security event log for new login events (Event ID 4624)."""
    def __init__(self, data: dict, callback):
        super().__init__(daemon=True)
        self.data     = data
        self.callback = callback
        self._stop    = threading.Event()
        self._last    = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    def run(self):
        while not self._stop.wait(10):
            try:
                cmd = (
                    f'Get-WinEvent -FilterHashtable @{{LogName="Security";Id=4624;'
                    f'StartTime="{self._last}"}} -MaxEvents 5 -ErrorAction SilentlyContinue'
                    f' | Select-Object TimeCreated,Message | ConvertTo-Json'
                )
                out = subprocess.check_output(
                    ["powershell", "-Command", cmd],
                    stderr=subprocess.DEVNULL, timeout=8
                ).decode(errors="replace").strip()
                if out and out != "null":
                    self._last = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
                    alert = dispatch_alert(
                        self.data, "Login Canary",
                        f"New Windows login event detected!\n"
                        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"Check Event Viewer → Security → Event 4624 for details."
                    )
                    self.callback(alert)
            except Exception:
                pass

    def stop(self):
        self._stop.set()

# ── Canary file generators ─────────────────────────────────────────────────────

def create_fake_passwords_file(path: str):
    content = """# My Passwords - DO NOT SHARE
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
"""
    Path(path).write_text(content)

def create_fake_private_key_file(path: str):
    content = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29P2rFj7rS
pMHmMBT1FAKE3YcFAKEKEYDATAHEREXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx
FakePrivateKeyForCanaryPurposesOnlyDoNotUseThisForAnythingReal1234
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx
-----END RSA PRIVATE KEY-----
"""
    Path(path).write_text(content)

def create_fake_config_file(path: str):
    content = """{
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
"""
    Path(path).write_text(content)


# ══════════════════════════════════════════════════════════════════════════════
# GUI
# ══════════════════════════════════════════════════════════════════════════════

class CanaryWatchApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CanaryWatch  —  Personal IDS")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(860, 620)

        self._data      = load_data()
        self._observers = []   # watchdog observers
        self._monitors  = []   # USB / screenshot / process / login threads
        self._armed     = False

        self._build_ui()
        self._reload_alert_log()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── top bar ──
        bar = tk.Frame(self, bg=BG, pady=12)
        bar.pack(fill="x", padx=24)

        tk.Label(bar, text="◈ CanaryWatch", font=(SANS, 18, "bold"),
                 bg=BG, fg=ACCENT).pack(side="left")

        self.status_lbl = tk.Label(bar, text="● DISARMED", font=(SANS, 9, "bold"),
                                   bg=BG, fg=DANGER)
        self.status_lbl.pack(side="left", padx=(16, 0))

        self.arm_btn = tk.Button(bar, text="▶  Arm All Canaries",
                                 command=self._toggle_arm,
                                 bg=SUCCESS, fg="#0d1117", relief="flat",
                                 font=(SANS, 9, "bold"), padx=12, pady=6,
                                 activebackground="#56d364", cursor="hand2")
        self.arm_btn.pack(side="right")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # ── notebook tabs ──
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
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        self._tab_deploy  = tk.Frame(nb, bg=BG)
        self._tab_alerts  = tk.Frame(nb, bg=BG)
        self._tab_config  = tk.Frame(nb, bg=BG)

        nb.add(self._tab_deploy, text="  Deploy  ")
        nb.add(self._tab_alerts, text="  Alert Log  ")
        nb.add(self._tab_config, text="  Alert Config  ")

        self._build_deploy_tab()
        self._build_alerts_tab()
        self._build_config_tab()

    # ── Deploy tab ────────────────────────────────────────────────────────────

    def _build_deploy_tab(self):
        p = self._tab_deploy

        # left: canary list
        left = tk.Frame(p, bg=BG, width=340)
        left.pack(side="left", fill="both", padx=(16, 0), pady=16)
        left.pack_propagate(False)

        tk.Label(left, text="Active Canaries", font=(SANS, 10, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", pady=(0, 8))

        list_frame = tk.Frame(left, bg=CARD, bd=0)
        list_frame.pack(fill="both", expand=True)

        self.canary_list = tk.Listbox(
            list_frame, bg=CARD, fg=TEXT, font=(SANS, 9),
            selectbackground=ACCENT, selectforeground="#0d1117",
            relief="flat", bd=0, activestyle="none",
            highlightthickness=0)
        self.canary_list.pack(fill="both", expand=True, padx=2, pady=2)

        btn_row = tk.Frame(left, bg=BG)
        btn_row.pack(fill="x", pady=(8, 0))
        tk.Button(btn_row, text="Remove Selected",
                  command=self._remove_canary,
                  bg=BORDER, fg=DANGER, relief="flat",
                  font=(SANS, 9), padx=8, pady=5,
                  cursor="hand2").pack(side="left")

        # right: add canary panel
        right = tk.Frame(p, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=16, pady=16)

        tk.Label(right, text="Add New Canary", font=(SANS, 10, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", pady=(0, 12))

        # cards grid
        cards = [
            ("📄 File Canary",       "Alert when a specific file is opened/modified",    self._add_file_canary),
            ("📁 Folder Canary",     "Alert when any activity occurs in a folder",        self._add_folder_canary),
            ("🔌 USB Canary",        "Alert when a USB drive is plugged in",              self._add_usb_canary),
            ("📸 Screenshot Canary", "Alert when Print Screen is pressed",                self._add_screenshot_canary),
            ("⚙️ Process Canary",    "Alert when a watched process launches",             self._add_process_canary),
            ("🔐 Login Canary",      "Alert on any new Windows login event",              self._add_login_canary),
            ("🎣 Fake Passwords",    "Plant a fake passwords.txt as a tripwire",          self._deploy_fake_passwords),
            ("🔑 Fake Private Key",  "Plant a fake id_rsa as a tripwire",                 self._deploy_fake_key),
            ("🗄️ Fake Config",      "Plant a fake config.json as a tripwire",            self._deploy_fake_config),
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

        self._reload_canary_list()

    # ── Alerts tab ────────────────────────────────────────────────────────────

    def _build_alerts_tab(self):
        p = self._tab_alerts

        top = tk.Frame(p, bg=BG)
        top.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(top, text="Alert Log", font=(SANS, 10, "bold"),
                 bg=BG, fg=TEXT).pack(side="left")
        tk.Button(top, text="Clear Log", command=self._clear_alerts,
                  bg=BORDER, fg=DANGER, relief="flat",
                  font=(SANS, 9), padx=8, pady=4,
                  cursor="hand2").pack(side="right")
        tk.Button(top, text="Export Log", command=self._export_log,
                  bg=BORDER, fg=ACCENT2, relief="flat",
                  font=(SANS, 9), padx=8, pady=4,
                  cursor="hand2").pack(side="right", padx=(0, 6))

        cols = ("time", "type", "message")
        self.alert_tree = ttk.Treeview(p, columns=cols, show="headings",
                                       selectmode="browse")
        self.alert_tree.heading("time",    text="Time")
        self.alert_tree.heading("type",    text="Type")
        self.alert_tree.heading("message", text="Message")
        self.alert_tree.column("time",    width=150, anchor="w")
        self.alert_tree.column("type",    width=160, anchor="w")
        self.alert_tree.column("message", width=500, anchor="w")

        style = ttk.Style()
        style.configure("Treeview",
                        background=CARD, foreground=TEXT,
                        fieldbackground=CARD, rowheight=26,
                        font=(SANS, 9), borderwidth=0)
        style.configure("Treeview.Heading",
                        background=SURFACE, foreground=MUTED,
                        font=(SANS, 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", ACCENT)],
                  foreground=[("selected", "#0d1117")])

        sb = ttk.Scrollbar(p, orient="vertical", command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=sb.set)
        self.alert_tree.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        sb.pack(side="right", fill="y")

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

        self._cfg_vars = {}

        # Email
        section("📧 Email Alerts (Gmail)")
        toggle("Enable email alerts", "email_enabled")
        row("From address",  "email_from")
        row("App password",  "email_password", show="●")
        row("Send alerts to","email_to")

        # Telegram
        section("✈️ Telegram Alerts")
        toggle("Enable Telegram alerts", "telegram_enabled")
        row("Bot token",  "telegram_token",  show="●")
        row("Chat ID",    "telegram_chat_id")

        # Discord
        section("💬 Discord Alerts")
        toggle("Enable Discord alerts", "discord_enabled")
        row("Webhook URL", "discord_webhook", show="●")

        # Process watch list
        section("⚙️ Process Watch List")
        tk.Label(inner, text="Comma-separated process names to watch (e.g. taskmgr.exe, regedit.exe)",
                 font=(SANS, 8), bg=BG, fg=MUTED).pack(anchor="w", padx=24)
        f = tk.Frame(inner, bg=BG)
        f.pack(fill="x", padx=24, pady=4)
        var = tk.StringVar(value=cfg.get("watch_processes", "taskmgr.exe,regedit.exe,cmd.exe"))
        tk.Entry(f, textvariable=var, font=(MONO, 9), width=50,
                 bg=CARD, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=4).pack(side="left")
        self._cfg_vars["watch_processes"] = var

        # save button
        tk.Button(inner, text="Save Configuration",
                  command=self._save_config,
                  bg=ACCENT2, fg="#0d1117", relief="flat",
                  font=(SANS, 10, "bold"), padx=16, pady=8,
                  cursor="hand2").pack(anchor="w", padx=24, pady=20)

    # ── canary actions ────────────────────────────────────────────────────────

    def _add_file_canary(self):
        path = filedialog.askopenfilename(title="Select file to watch")
        if not path:
            return
        self._register_canary({"type": "File Canary", "path": path})

    def _add_folder_canary(self):
        path = filedialog.askdirectory(title="Select folder to watch")
        if not path:
            return
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

    def _deploy_fake_passwords(self):
        path = filedialog.asksaveasfilename(
            title="Save fake passwords file",
            initialfile="passwords.txt",
            defaultextension=".txt")
        if not path:
            return
        create_fake_passwords_file(path)
        self._register_canary({"type": "File Canary", "path": path,
                                "label": "Fake Passwords"})
        messagebox.showinfo("Deployed", f"Fake passwords file planted at:\n{path}")

    def _deploy_fake_key(self):
        path = filedialog.asksaveasfilename(
            title="Save fake private key",
            initialfile="id_rsa",
            defaultextension="")
        if not path:
            return
        create_fake_private_key_file(path)
        self._register_canary({"type": "File Canary", "path": path,
                                "label": "Fake Private Key"})
        messagebox.showinfo("Deployed", f"Fake private key planted at:\n{path}")

    def _deploy_fake_config(self):
        path = filedialog.asksaveasfilename(
            title="Save fake config file",
            initialfile="config.json",
            defaultextension=".json")
        if not path:
            return
        create_fake_config_file(path)
        self._register_canary({"type": "File Canary", "path": path,
                                "label": "Fake Config"})
        messagebox.showinfo("Deployed", f"Fake config file planted at:\n{path}")

    def _register_canary(self, canary: dict):
        # avoid duplicates
        for c in self._data["canaries"]:
            if c["type"] == canary["type"] and c["path"] == canary["path"]:
                messagebox.showinfo("Already exists",
                                    "This canary is already in the list.")
                return
        canary["id"] = ''.join(random.choices(string.hexdigits, k=8))
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

    def _reload_canary_list(self):
        self.canary_list.delete(0, "end")
        for c in self._data["canaries"]:
            label = c.get("label", c["type"])
            path  = c["path"] if c["path"] != "system" else "(system-wide)"
            self.canary_list.insert("end", f"  {label}  |  {path}")

    # ── arm / disarm ──────────────────────────────────────────────────────────

    def _toggle_arm(self):
        if self._armed:
            self._disarm()
        else:
            self._arm()

    def _arm(self):
        if not self._data["canaries"]:
            messagebox.showwarning("No canaries", "Deploy at least one canary first.")
            return

        cfg = self._data.get("config", {})
        procs_str = cfg.get("watch_processes", "taskmgr.exe,regedit.exe")
        proc_list = [p.strip() for p in procs_str.split(",") if p.strip()]

        for canary in self._data["canaries"]:
            ctype = canary["type"]
            path  = canary["path"]

            if ctype == "File Canary":
                try:
                    folder = str(Path(path).parent)
                    handler  = FileCanaryHandler(canary, self._data,
                                                 self._on_alert)
                    observer = wd_observers.Observer()
                    observer.schedule(handler, folder, recursive=False)
                    observer.start()
                    self._observers.append(observer)
                except Exception as e:
                    self._log_ui(f"Failed to watch {path}: {e}")

            elif ctype == "Folder Canary":
                try:
                    handler  = FolderCanaryHandler(canary, self._data,
                                                   self._on_alert)
                    observer = wd_observers.Observer()
                    observer.schedule(handler, path, recursive=True)
                    observer.start()
                    self._observers.append(observer)
                except Exception as e:
                    self._log_ui(f"Failed to watch {path}: {e}")

            elif ctype == "USB Canary":
                m = USBMonitor(self._data, self._on_alert)
                m.start()
                self._monitors.append(m)

            elif ctype == "Screenshot Canary":
                m = ScreenshotMonitor(self._data, self._on_alert)
                m.start()
                self._monitors.append(m)

            elif ctype == "Process Canary":
                m = ProcessMonitor(proc_list, self._data, self._on_alert)
                m.start()
                self._monitors.append(m)

            elif ctype == "Login Canary":
                m = LoginMonitor(self._data, self._on_alert)
                m.start()
                self._monitors.append(m)

        self._armed = True
        self.arm_btn.config(text="■  Disarm", bg=DANGER,
                            activebackground="#ff7b72")
        self.status_lbl.config(text="● ARMED", fg=SUCCESS)

    def _disarm(self):
        for obs in self._observers:
            try:
                obs.stop(); obs.join(timeout=2)
            except Exception:
                pass
        for mon in self._monitors:
            try:
                mon.stop()
            except Exception:
                pass
        self._observers.clear()
        self._monitors.clear()
        self._armed = False
        self.arm_btn.config(text="▶  Arm All Canaries", bg=SUCCESS,
                            activebackground="#56d364")
        self.status_lbl.config(text="● DISARMED", fg=DANGER)

    # ── alert handling ────────────────────────────────────────────────────────

    def _on_alert(self, alert: dict):
        """Called from background threads — schedule UI update on main thread."""
        self.after(0, self._show_alert, alert)

    def _show_alert(self, alert: dict):
        # flash title
        self.title(f"🚨 ALERT — {alert['type']}  |  CanaryWatch")
        self.after(3000, lambda: self.title("CanaryWatch  —  Personal IDS"))

        # insert into treeview
        self.alert_tree.insert("", 0,
                               values=(alert["time"], alert["type"],
                                       alert["message"].split("\n")[0]))

        # desktop popup
        messagebox.showwarning(
            f"🚨 CanaryWatch Alert",
            f"Type:  {alert['type']}\n\n{alert['message']}"
        )

    def _reload_alert_log(self):
        self.alert_tree.delete(*self.alert_tree.get_children())
        for a in self._data.get("alerts", []):
            self.alert_tree.insert("", "end",
                                   values=(a["time"], a["type"],
                                           a["message"].split("\n")[0]))

    def _clear_alerts(self):
        if messagebox.askyesno("Clear log", "Clear all alerts?"):
            self._data["alerts"] = []
            save_data(self._data)
            self.alert_tree.delete(*self.alert_tree.get_children())

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            title="Export alert log",
            initialfile="canarywatch_alerts.txt",
            defaultextension=".txt")
        if path:
            shutil.copy(LOG_FILE, path)
            messagebox.showinfo("Exported", f"Log saved to:\n{path}")

    def _log_ui(self, msg):
        print(msg)  # fallback

    # ── config ────────────────────────────────────────────────────────────────

    def _save_config(self):
        cfg = {}
        for key, var in self._cfg_vars.items():
            cfg[key] = var.get()
        self._data["config"] = cfg
        save_data(self._data)
        messagebox.showinfo("Saved", "Configuration saved.")

    # ── close ─────────────────────────────────────────────────────────────────

    def _on_close(self):
        self._disarm()
        self.destroy()


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # check watchdog installed
    try:
        import watchdog
    except ImportError:
        import subprocess, sys
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "watchdog", "--break-system-packages", "-q"])
    try:
        import requests
    except ImportError:
        import subprocess, sys
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "requests", "--break-system-packages", "-q"])

    app = CanaryWatchApp()
    app.mainloop()
