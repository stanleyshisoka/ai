
# AI Assistant (Enhanced + Secure Vault & Login) — Cleaned & Upgraded
# -------------------------------------------------------------------
# What's new in this build:
# - Cleanup: removed duplicate talk(), unreachable code, repeated imports, and
#   incomplete reminder snippets. Fixed "generate password" double prompt.
# - Settings: persistent settings.json (theme, voice, safe_mode).
# - Theme: light/dark theme toggle for all Tk windows.
# - Weather: "weather in Nairobi" (OpenWeather, needs API key; graceful fallback).
# - News: "news today" (NewsAPI, needs API key; graceful fallback).
# - Translate: "translate <text> to <lang>" (MyMemory free API; graceful fallback).
# - System Monitor: quick popup with CPU (best-effort), RAM, Disk.
# - Clipboard History: background watcher, "clipboard history" shows recent items.
# - Offline Queue: if offline, "search for", "open <query>", "news today", "weather in ..."
#   get queued; processed automatically once back online.
#
# SECURITY NOTES (unchanged core):
# - Session login with master password (default "stano", resets each run).
# - XOR "toy" encryption for vault. For production, use a vetted crypto library.
# - Heuristic spyware scan tools remain; may produce false positives.
#
# API Keys (optional; set yours below):
WEATHER_API_KEY = "be115e6b6f5f51b5b399acd9278f5211"  # OpenWeather key (https://openweathermap.org/)
NEWS_API_KEY = "a5ff14548d80444290a0db0b65516cae"     # NewsAPI key (https://newsapi.org/)

import os
import sys
import re
import json
import time
import math
import shutil
import socket
import random
import hashlib
import secrets
import platform
import datetime
import subprocess
import threading
import urllib.parse
import urllib.request
from pathlib import Path
from tkinter import messagebox
import tkinter as tk

# Optional speech (skip failures gracefully)
try:
    import pyttsx3
except Exception:
    pyttsx3 = None

# Optional GUI automation (used for typing/hotkeys/screenshot)
try:
    import pyautogui
except Exception:
    pyautogui = None

# Optional Windows registry (startup list)
try:
    import winreg  # type: ignore
except Exception:
    winreg = None

# ------------------------
# Globals & Paths
# ------------------------
BASE_DIR = Path(__file__).parent
learned_responses_file = str(BASE_DIR / 'learned_commands.json')
notes_file = str(BASE_DIR / 'notes.txt')
screenshots_dir = Path(BASE_DIR / 'screenshots')
screenshots_dir.mkdir(exist_ok=True)

# Secure vault paths
vault_file = Path(BASE_DIR / "password_vault.bin")
key_file = Path(BASE_DIR / "vault.key")

# Persistent settings
settings_file = Path(BASE_DIR / "settings.json")
default_settings = {
    "voice_enabled": True,
    "theme": "light",          # "light" or "dark"
    "safe_mode": False,
}
_settings = dict(default_settings)

# Offline queue
offline_queue_file = Path(BASE_DIR / "offline_queue.json")

# Session master password
SESSION_MASTER_PASSWORD = "stano"
_failed_attempts = 0

# Runtime flags
offline_mode = False
keep_listening = True
use_typing_input = True

# Clipboard history
_clipboard_history = []
_MAX_CLIPBOARD = 10
_clipboard_thread_started = False

# Human responses / content
human_responses = [
    "Sure thing! Let me take care of that.",
    "Absolutely, working on it now.",
    "Got it.",
    "On it!",
    "Alright, doing that for you now.",
    "One moment, please!"
]

fun_facts = [
    "Did you know? The first computer virus was created in 1986.",
    "Fun fact: The original name for Windows was Interface Manager.",
    "Did you know? Python is named after Monty Python, not the snake!",
    "Fact: The first website is still online. It's info.cern.ch."
]

jokes = [
    "Why do programmers prefer dark mode? Because light attracts bugs.",
    "I told my computer I needed a break, and it said no problem — it went to sleep.",
    "There are only 10 kinds of people in the world: those who understand binary and those who don't.",
    "I would tell you a UDP joke, but you might not get it."
]

context_memory = []  # recent commands (simple memory)

# Safe Mode (Whitelist Only)
WHITELISTED_COMMANDS = [
    "help", "show notes", "clear notes", "my ip",
    "generate password", "show passwords"
]

def enforce_safe_mode(cmd: str) -> bool:
    if _settings.get("safe_mode", False) and cmd.lower().strip() not in WHITELISTED_COMMANDS:
        talk("Restricted command in safe mode.")
        return True
    return False

def enable_safe_mode():
    _settings["safe_mode"] = True
    save_settings()
    talk("Safe mode activated.")

# ------------------------
# Settings
# ------------------------
def load_settings():
    global _settings
    if settings_file.exists():
        try:
            with open(settings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                _settings.update(data)
        except Exception:
            pass
    # Ensure keys
    for k, v in default_settings.items():
        _settings.setdefault(k, v)

def save_settings():
    try:
        with open(settings_file, "w", encoding="utf-8") as f:
            json.dump(_settings, f, indent=2)
    except Exception:
        pass

# ------------------------
# Voice/TTS
# ------------------------
engine = None
def _init_tts():
    global engine
    if pyttsx3 is None:
        return
    try:
        engine = pyttsx3.init()
        engine.setProperty('rate', 160)
    except Exception:
        engine = None

def toggle_voice(enabled: bool):
    _settings["voice_enabled"] = bool(enabled)
    save_settings()

def talk(text: str):
    if not _settings.get("voice_enabled", True) or engine is None:
        print(text)
        return
    try:
        engine.say(text)
        engine.runAndWait()
    except Exception:
        print("[TTS]", text)

# ------------------------
# Connectivity & Offline Queue
# ------------------------
def is_connected() -> bool:
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def initialize_mode():
    global offline_mode
    offline_mode = not is_connected()

def load_offline_queue():
    if offline_queue_file.exists():
        try:
            with open(offline_queue_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_offline_queue(queue):
    try:
        with open(offline_queue_file, "w", encoding="utf-8") as f:
            json.dump(queue, f, indent=2)
    except Exception:
        pass

def queue_online_command(cmd: str):
    queue = load_offline_queue()
    queue.append({"cmd": cmd, "ts": datetime.datetime.now().isoformat()})
    save_offline_queue(queue)
    talk("You're offline. I've queued this command to run when back online.")

def process_offline_queue():
    if offline_mode:
        return
    queue = load_offline_queue()
    if not queue:
        return
    # Ask user if they want to run queued commands
    if confirm_dialog("Run Queued Commands", f"{len(queue)} queued online command(s) found. Run them now?"):
        for item in queue:
            handle_command(item["cmd"], from_queue=True)
        save_offline_queue([])

# ------------------------
# Simple encryption helpers (XOR stream based on SHA-256)
# ------------------------
def _load_or_create_key():
    if key_file.exists():
        try:
            with open(key_file, "rb") as f:
                data = f.read().strip()
            if len(data) == 32:
                return data
            return bytes.fromhex(data.decode("utf-8"))
        except Exception:
            pass
    key = secrets.token_bytes(32)
    _save_key(key)
    return key

def _save_key(key_bytes: bytes):
    with open(key_file, "wb") as f:
        f.write(key_bytes)

def _keystream(key: bytes, length: int):
    output = bytearray()
    counter = 0
    while len(output) < length:
        counter += 1
        block = hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        output.extend(block)
    return bytes(output[:length])

def _xor_crypt(data: bytes, key: bytes) -> bytes:
    ks = _keystream(key, len(data))
    return bytes(d ^ k for d, k in zip(data, ks))

def _read_vault_plaintext(key: bytes):
    if not vault_file.exists():
        return []
    try:
        with open(vault_file, "rb") as f:
            enc = f.read()
        plain = _xor_crypt(enc, key)
        return json.loads(plain.decode("utf-8"))
    except Exception:
        return []

def _write_vault_plaintext(entries, key: bytes):
    data = json.dumps(entries, indent=2).encode("utf-8")
    enc = _xor_crypt(data, key)
    with open(vault_file, "wb") as f:
        f.write(enc)

def rotate_encryption_key():
    old_key = _load_or_create_key()
    entries = _read_vault_plaintext(old_key)
    new_key = secrets.token_bytes(32)
    _save_key(new_key)
    _write_vault_plaintext(entries, new_key)

def add_password_to_vault(pwd: str, meta: dict | None = None):
    key = _load_or_create_key()
    entries = _read_vault_plaintext(key)
    entry = {
        "password": pwd,
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    if meta:
        entry.update(meta)
    entries.append(entry)
    _write_vault_plaintext(entries, key)

def show_saved_passwords():
    key = _load_or_create_key()
    entries = _read_vault_plaintext(key)
    if not entries:
        return "No saved passwords yet."
    lines = []
    for i, e in enumerate(entries, 1):
        parts = []
        if e.get("definition"):
            parts.append(f"for: {e['definition']}")
        if e.get("length"):
            parts.append(f"len: {e['length']}")
        extra = (" — " + ", ".join(parts)) if parts else ""
        lines.append(f"{i}. {e['password']}  (saved: {e['created_at']}){extra}")
    return "\n".join(lines)

def clear_password_vault():
    key = _load_or_create_key()
    _write_vault_plaintext([], key)

# ------------------------

# ------------------------
# Productivity & Knowledge Enhancements (Tasks, Reminders, Wiki, Converters, QR)
# ------------------------
tasks_file = Path(BASE_DIR / "tasks.json")
reminders_file = Path(BASE_DIR / "reminders.json")
qr_codes_dir = Path(BASE_DIR / "qr_codes")
qr_codes_dir.mkdir(exist_ok=True)

# Optional QR code
try:
    import qrcode  # pip install qrcode[pil]
except Exception:
    qrcode = None

# ---- Tasks (To-Do) ----
def _load_tasks():
    if tasks_file.exists():
        try:
            with open(tasks_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def _save_tasks(tasks):
    try:
        with open(tasks_file, "w", encoding="utf-8") as f:
            json.dump(tasks, f, indent=2)
    except Exception:
        pass

def add_task(text):
    tasks = _load_tasks()
    tasks.append({"text": text.strip(), "done": False, "ts": datetime.datetime.now().isoformat()})
    _save_tasks(tasks)
    return True

def format_tasks():
    tasks = _load_tasks()
    if not tasks:
        return "No tasks yet."
    lines = []
    for i, tsk in enumerate(tasks, 1):
        lines.append(f"{i}. [{'x' if tsk.get('done') else ' '}] {tsk.get('text')}")
    return "\n".join(lines)

def mark_task_done(index):
    tasks = _load_tasks()
    if 1 <= index <= len(tasks):
        tasks[index-1]["done"] = True
        _save_tasks(tasks)
        return True
    return False

def clear_all_tasks():
    _save_tasks([])
    return True

# ---- Reminders ----
_reminders = []  # in-memory cache
def _load_reminders():
    global _reminders
    if reminders_file.exists():
        try:
            with open(reminders_file, "r", encoding="utf-8") as f:
                _reminders = json.load(f)
        except Exception:
            _reminders = []
    else:
        _reminders = []
    return _reminders

def _save_reminders():
    try:
        with open(reminders_file, "w", encoding="utf-8") as f:
            json.dump(_reminders, f, indent=2)
    except Exception:
        pass

def _parse_when_datetime(s: str):
    # Accept "HH:MM" or "HH:MM am/pm"; today or tomorrow if time already passed
    t = parse_time_string(s)
    if not t:
        return None
    now = datetime.datetime.now()
    dt = now.replace(hour=t.hour, minute=t.minute, second=0, microsecond=0)
    if dt <= now:
        dt += datetime.timedelta(days=1)
    return dt

def add_reminder(text, when_str):
    global _reminders
    dt = _parse_when_datetime(when_str)
    if not dt:
        return False, "Sorry, I couldn't understand the time."
    rid = hashlib.sha1(f"{text}{dt.isoformat()}".encode("utf-8")).hexdigest()[:8]
    _load_reminders()
    _reminders.append({"id": rid, "text": text.strip(), "when": dt.isoformat(), "fired": False})
    _save_reminders()
    return True, dt

def format_reminders():
    _load_reminders()
    if not _reminders:
        return "No reminders yet."
    lines = []
    for r in _reminders:
        mark = "x" if r.get("fired") else " "
        lines.append(f"[{mark}] {r.get('when')} — {r.get('text')} (id: {r.get('id')})")
    return "\n".join(lines)

def clear_reminders():
    global _reminders
    _reminders = []
    _save_reminders()
    return True

def _reminder_scheduler_loop():
    # Check every 30s for due reminders
    while keep_listening:
        try:
            _load_reminders()
            now = datetime.datetime.now()
            changed = False
            for r in _reminders:
                if not r.get("fired"):
                    try:
                        when = datetime.datetime.fromisoformat(r.get("when"))
                    except Exception:
                        continue
                    if when <= now:
                        try:
                            talk(f"Reminder: {r.get('text')}")
                            messagebox.showinfo("Reminder", r.get("text"))
                        except Exception:
                            pass
                        r["fired"] = True
                        changed = True
            if changed:
                _save_reminders()
        except Exception:
            pass
        time.sleep(30)

def start_reminder_scheduler():
    th = threading.Thread(target=_reminder_scheduler_loop, daemon=True)
    th.start()

# ---- Wikipedia Summaries ----
def wiki_summary(topic):
    if offline_mode:
        return "Wikipedia unavailable offline."
    title = urllib.parse.quote(topic.strip())
    url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{title}"
    data = http_get_json(url, headers={"accept": "application/json"})
    if not data:
        return "Couldn't fetch summary."
    if data.get("extract"):
        return data["extract"]
    if data.get("description"):
        return data["description"]
    return "No summary found."

# ---- Unit Converter ----
def convert_units(expr: str):
    expr = expr.strip().lower()
    # Patterns like "5 km to miles" or "32 c to f"
    m = re.match(r'^(-?\d+(\.\d+)?)\s*([a-z°]+)\s+to\s+([a-z°]+)$', expr)
    if not m:
        return None
    val = float(m.group(1))
    src = m.group(3)
    dst = m.group(4)

    # Temperature
    temp_alias = {"c":"c", "°c":"c", "celsius":"c", "f":"f", "°f":"f", "fahrenheit":"f", "k":"k", "kelvin":"k"}
    if src in temp_alias and dst in temp_alias:
        s = temp_alias[src]; d = temp_alias[dst]
        if s == d:
            return f"{val} {src} = {val} {dst}"
        if s == "c" and d == "f":
            out = val * 9/5 + 32
        elif s == "f" and d == "c":
            out = (val - 32) * 5/9
        elif s == "c" and d == "k":
            out = val + 273.15
        elif s == "k" and d == "c":
            out = val - 273.15
        elif s == "f" and d == "k":
            out = (val - 32) * 5/9 + 273.15
        elif s == "k" and d == "f":
            out = (val - 273.15) * 9/5 + 32
        else:
            return "Unsupported temperature conversion."
        return f"{val} {src} = {round(out, 4)} {dst}"

    # Distance and mass simple map (SI <-> Imperial)
    factors = {
        ("km","miles"): 0.621371, ("miles","km"): 1/0.621371,
        ("m","ft"): 3.28084, ("ft","m"): 1/3.28084,
        ("cm","inch"): 0.393701, ("inch","cm"): 1/0.393701,
        ("kg","lb"): 2.20462, ("lb","kg"): 1/2.20462,
        ("l","gallon"): 0.264172, ("gallon","l"): 1/0.264172,
        ("km","mi"): 0.621371, ("mi","km"): 1/0.621371,
        ("meter","ft"): 3.28084, ("meters","ft"): 3.28084,
        ("foot","m"): 1/3.28084, ("feet","m"): 1/3.28084,
        ("liters","gallons"): 0.264172, ("gallons","liters"): 1/0.264172,
    }
    # Normalize some aliases
    alias = {
        "kilometer":"km", "kilometers":"km",
        "mile":"miles", "mi":"miles",
        "meter":"m", "meters":"m",
        "centimeter":"cm", "centimeters":"cm",
        "foot":"ft", "feet":"ft",
        "liter":"l", "liters":"l",
        "gallons":"gallon", "ounces":"oz", "ounce":"oz",
        "pound":"lb", "pounds":"lb",
        "inches":"inch"
    }
    src = alias.get(src, src)
    dst = alias.get(dst, dst)
    key = (src, dst)
    if key in factors:
        out = val * factors[key]
        return f"{val} {src} = {round(out, 4)} {dst}"
    return "Unsupported unit conversion. Try temperature, km/miles, m/ft, cm/inch, kg/lb, l/gallon."

# ---- Currency Converter (exchangerate.host) ----
def convert_currency(expr: str):
    # "100 usd to kes"
    m = re.match(r'^(-?\d+(\.\d+)?)\s*([a-z]{3})\s+to\s+([a-z]{3})$', expr.strip().lower())
    if not m:
        return None
    amt = float(m.group(1)); src = m.group(3).upper(); dst = m.group(4).upper()
    if offline_mode:
        return "Currency conversion unavailable offline."
    url = f"https://api.exchangerate.host/convert?from={urllib.parse.quote(src)}&to={urllib.parse.quote(dst)}&amount={amt}"
    data = http_get_json(url)
    if not data or data.get("result") is None:
        return "Couldn't fetch exchange rate."
    result = data["result"]
    return f"{amt} {src} = {round(result, 4)} {dst}"

# ---- QR Code ----
def make_qr_code(text: str):
    if qrcode is None:
        return False, "QR code feature requires 'qrcode' package. Install with: pip install qrcode[pil]"
    try:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = qr_codes_dir / f"qr_{ts}.png"
        img = qrcode.make(text)
        img.save(path)
        return True, str(path)
    except Exception as e:
        return False, f"Failed to generate QR: {e}"
# Utilities
# ------------------------
def human_like_response():
    return random.choice(human_responses)

def random_fact():
    return random.choice(fun_facts)

def random_joke():
    return random.choice(jokes)

def save_note(text):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(notes_file, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {text}\n")

def read_notes():
    if not os.path.exists(notes_file):
        return "No notes yet."
    with open(notes_file, "r", encoding="utf-8") as f:
        return f.read().strip() or "No notes yet."

def clear_notes():
    if os.path.exists(notes_file):
        os.remove(notes_file)

def take_screenshot():
    if pyautogui is None:
        return "Screenshot not available (pyautogui missing)."
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = str(screenshots_dir / f"screenshot_{ts}.png")
    image = pyautogui.screenshot()
    image.save(path)
    return path

def coin_flip():
    return random.choice(["Heads", "Tails"])

def roll_dice():
    return random.randint(1, 6)

def generate_password(length=12):
    length = max(6, min(64, int(length or 12)))
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?"
    return ''.join(random.choice(chars) for _ in range(length))

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"

# ------------------------
# Learned Commands (Persistence)
# ------------------------
learned_commands = {}

def load_learned_commands():
    global learned_commands
    if os.path.exists(learned_responses_file):
        try:
            with open(learned_responses_file, "r", encoding="utf-8") as f:
                learned_commands = json.load(f)
        except Exception:
            learned_commands = {}
    else:
        learned_commands = {}

def save_learned_commands():
    try:
        with open(learned_responses_file, "w", encoding="utf-8") as f:
            json.dump(learned_commands, f, indent=2)
    except Exception as e:
        messagebox.showerror("Save Error", f"Could not save learned commands: {e}")

def learn_custom_command(trigger, action_type, value):
    learned_commands[trigger.strip().lower()] = {"type": action_type, "value": value}
    save_learned_commands()

# ------------------------
# Theme (Tk)
# ------------------------
def get_theme():
    theme = _settings.get("theme", "light")
    if theme not in ("light", "dark"):
        theme = "light"
    if theme == "dark":
        return {
            "bg": "#121212",
            "fg": "#F1F1F1",
            "accent": "#0ea5e9",
            "muted": "#2A2A2A",
        }
    return {
        "bg": "white",
        "fg": "black",
        "accent": "#0078D7",
        "muted": "#f0f0f0",
    }

def toggle_theme():
    _settings["theme"] = "dark" if _settings.get("theme", "light") == "light" else "light"
    save_settings()
    talk(f"Theme set to {_settings['theme']}.")

# ------------------------
# UI (Message/Prompt) + Login
# ------------------------
class AIMessageBox:
    def __init__(self, text, password_mode=False):
        t = get_theme()
        self.user_input = None
        self.root = tk.Tk()
        self.root.title(self.get_window_title())
        self.root.geometry("640x280")
        self.root.resizable(False, False)
        self.root.configure(bg=t["bg"])

        label = tk.Label(
            self.root, text=text, wraplength=600,
            bg=t["bg"], fg=t["fg"], font=("Segoe UI", 12)
        )
        label.pack(pady=20, padx=10)

        self.entry = tk.Entry(self.root, font=("Segoe UI", 11), width=78, bg="white" if t["bg"]=="white" else "#1e1e1e", fg=t["fg"], insertbackground=t["fg"])
        if password_mode:
            self.entry.config(show="*")
        self.entry.pack(pady=10)

        button_frame = tk.Frame(self.root, bg=t["bg"])
        button_frame.pack()

        submit_btn = tk.Button(
            button_frame, text="Submit", command=self.on_submit,
            font=("Segoe UI", 10), bg=t["accent"], fg="white", activebackground=t["accent"]
        )
        submit_btn.grid(row=0, column=0, padx=5)

        cancel_btn = tk.Button(
            button_frame, text="Cancel", command=self.on_cancel,
            font=("Segoe UI", 10), bg="#6c757d", fg="white"
        )
        cancel_btn.grid(row=0, column=1, padx=5)

        # Enter key to submit
        self.entry.bind("<Return>", lambda e: self.on_submit())

        self.root.attributes('-topmost', True)
        self.entry.focus_set()
        self.root.mainloop()

    def on_submit(self):
        self.user_input = self.entry.get()
        self.root.destroy()

    def on_cancel(self):
        self.user_input = None
        self.root.destroy()

    def get_input(self):
        return self.user_input

    def get_window_title(self):
        return "AI Assistant (OFFLINE)" if offline_mode else "AI Assistant"

def confirm_dialog(title, text):
    t = get_theme()
    root = tk.Tk()
    root.withdraw()
    # messagebox does not theme; acceptable
    result = messagebox.askyesno(title, text)
    root.destroy()
    return result

def login_gate():
    global _failed_attempts
    while True:
        prompt = "Enter master password to access the AI:"
        pwd = AIMessageBox(prompt, password_mode=True).get_input()
        if pwd is None:
            return False
        if pwd == SESSION_MASTER_PASSWORD:
            messagebox.showinfo("Access Granted", "Welcome.")
            return True
        _failed_attempts += 1
        remaining = max(0, 5 - _failed_attempts)
        if _failed_attempts >= 5:
            try:
                rotate_encryption_key()
                messagebox.showwarning(
                    "Security",
                    "Too many failed attempts. The encryption key for the vault has been rotated."
                )
            except Exception as e:
                messagebox.showwarning(
                    "Security",
                    f"Key rotation attempted after failed logins, but an error occurred: {e}"
                )
        else:
            messagebox.showerror("Access Denied", f"Incorrect password. Attempts before key rotation: {remaining}")

# ------------------------
# Input
# ------------------------
def listen_command():
    typed_input = AIMessageBox("Type your command below.").get_input()
    return typed_input.lower().strip() if typed_input else ""

# ------------------------
# Actions
# ------------------------
def open_website_or_search(query):
    if not query:
        return
    # Heuristic: if it contains a dot and no spaces, treat as domain
    if "." in query and " " not in query:
        url = query if query.startswith("http") else f"https://{query}"
    else:
        url = f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass


def open_application(app_name):
    app_name = app_name.strip()
    if os.name == "nt":  # Windows
        mapping = {
            "notepad": "notepad.exe",
            "calculator": "calc.exe",
            "paint": "mspaint.exe",
            "cmd": "cmd.exe"
        }
        exe = mapping.get(app_name.lower(), app_name)
        try:
            subprocess.Popen(exe, shell=True)
            return True
        except Exception:
            return False
    elif sys.platform == "darwin":  # macOS
        try:
            subprocess.Popen(["open", "-a", app_name])
            return True
        except Exception:
            return False
    else:  # Linux / others
        try:
            subprocess.Popen([app_name])
            return True
        except Exception:
            try:
                subprocess.Popen(["xdg-open", app_name])
                return True
            except Exception:
                return False

def type_text(text):
    if pyautogui is None:
        talk("Typing not available (pyautogui missing).")
        return
    pyautogui.typewrite(text, interval=0.02)

def press_hotkey(*keys):
    if pyautogui is None:
        talk("Hotkeys not available (pyautogui missing).")
        return
    pyautogui.hotkey(*keys)

# ------------------------
# System Monitor
# ------------------------
def get_system_stats():
    # Disk
    try:
        total, used, free = shutil.disk_usage(str(Path.home()))
        disk_info = {
            "total_gb": round(total / (1024**3), 2),
            "used_gb": round(used / (1024**3), 2),
            "free_gb": round(free / (1024**3), 2),
        }
    except Exception:
        disk_info = {"total_gb": "?", "used_gb": "?", "free_gb": "?"}

    # RAM (best-effort, platform-dependent without psutil)
    ram_info = {"total_gb": "?", "available_gb": "?"}
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/meminfo", "r") as f:
                mem = f.read()
            m_total = re.search(r"MemTotal:\s+(\d+)\s+kB", mem)
            m_free = re.search(r"MemAvailable:\s+(\d+)\s+kB", mem)
            if m_total and m_free:
                total_kb = int(m_total.group(1))
                free_kb = int(m_free.group(1))
                ram_info = {
                    "total_gb": round(total_kb/1024/1024, 2),
                    "available_gb": round(free_kb/1024/1024, 2)
                }
        elif sys.platform == "darwin":
            # macOS: use vm_stat
            out = subprocess.check_output(["vm_stat"], text=True)
            page_size = 4096
            m = re.search(r"page size of (\d+) bytes", out)
            if m:
                page_size = int(m.group(1))
            def _pages(tag):
                mm = re.search(rf"{tag}:\s+(\d+)\.", out)
                return int(mm.group(1)) if mm else 0
            free = _pages("Pages free")
            inactive = _pages("Pages inactive")
            speculative = _pages("Pages speculative")
            wired = _pages("Pages wired down")
            active = _pages("Pages active")
            total_pages = free + inactive + speculative + wired + active
            total = total_pages * page_size
            avail = (free + inactive + speculative) * page_size
            ram_info = {"total_gb": round(total/1024/1024/1024, 2), "available_gb": round(avail/1024/1024/1024, 2)}
        elif os.name == "nt":
            # Windows: wmic (deprecated but still present on many systems)
            try:
                out = subprocess.check_output("wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /Value", text=True)
                tv = re.search(r"TotalVisibleMemorySize=(\d+)", out)
                fr = re.search(r"FreePhysicalMemory=(\d+)", out)
                if tv and fr:
                    total_kb = int(tv.group(1))
                    free_kb = int(fr.group(1))
                    ram_info = {"total_gb": round(total_kb/1024/1024, 2), "available_gb": round(free_kb/1024/1024, 2)}
            except Exception:
                pass
    except Exception:
        pass

    # CPU (best-effort)
    cpu_info = {"load": "?"}
    try:
        if hasattr(os, "getloadavg"):
            la = os.getloadavg()  # 1,5,15 averages
            cpu_info = {"load": f"{la[0]:.2f} (1m avg)"}
        elif os.name == "nt":
            # Try wmic
            try:
                out = subprocess.check_output("wmic cpu get LoadPercentage /Value", text=True)
                m = re.search(r"LoadPercentage=(\d+)", out)
                if m:
                    cpu_info = {"load": f"{m.group(1)}%"}
            except Exception:
                pass
    except Exception:
        pass

    return {"cpu": cpu_info, "ram": ram_info, "disk": disk_info}

def show_system_monitor():
    stats = get_system_stats()
    t = get_theme()
    win = tk.Tk()
    win.title("System Monitor")
    win.geometry("420x240")
    win.configure(bg=t["bg"])
    def row(lbl, val, r):
        tk.Label(win, text=lbl, bg=t["bg"], fg=t["fg"], font=("Segoe UI", 11)).grid(row=r, column=0, sticky="w", padx=12, pady=6)
        tk.Label(win, text=val, bg=t["bg"], fg=t["fg"], font=("Segoe UI", 11, "bold")).grid(row=r, column=1, sticky="w", padx=6, pady=6)
    row("CPU Load:", stats["cpu"]["load"], 0)
    row("RAM Total:", f'{stats["ram"]["total_gb"]} GB', 1)
    row("RAM Available:", f'{stats["ram"]["available_gb"]} GB', 2)
    row("Disk Total:", f'{stats["disk"]["total_gb"]} GB', 3)
    row("Disk Used:", f'{stats["disk"]["used_gb"]} GB', 4)
    row("Disk Free:", f'{stats["disk"]["free_gb"]} GB', 5)
    tk.Button(win, text="Close", command=win.destroy, bg=t["accent"], fg="white").grid(row=6, column=0, columnspan=2, pady=12)
    win.attributes("-topmost", True)
    win.mainloop()

# ------------------------
# Clipboard Watcher
# ------------------------
def _clipboard_loop():
    global _clipboard_history
    last = ""
    while keep_listening:
        try:
            r = tk.Tk()
            r.withdraw()
            r.update()
            content = ""
            try:
                content = r.clipboard_get()
            except Exception:
                content = ""
            r.destroy()
            if content and content != last:
                last = content
                _clipboard_history.append(content)
                _clipboard_history = _clipboard_history[-_MAX_CLIPBOARD:]
        except Exception:
            pass
        time.sleep(2.0)

def start_clipboard_watcher():
    global _clipboard_thread_started
    if _clipboard_thread_started:
        return
    _clipboard_thread_started = True
    th = threading.Thread(target=_clipboard_loop, daemon=True)
    th.start()

def show_clipboard_history():
    if not _clipboard_history:
        messagebox.showinfo("Clipboard History", "No clipboard items captured yet.")
        return
    content = "\n\n".join(f"{i+1}. {c[:500]}" for i, c in enumerate(reversed(_clipboard_history)))
    messagebox.showinfo("Clipboard History", content)

# ------------------------
# Timers & Alarms
# ------------------------
def set_timer(seconds, message="Time's up!"):
    def notify():
        talk(message)
        messagebox.showinfo("Timer", message)
    t = threading.Timer(seconds, notify)
    t.daemon = True
    t.start()

def parse_time_string(s):
    s = s.strip().lower()
    m = re.match(r'^(\d{1,2}):(\d{2})$', s)
    if m:
        h, mi = int(m.group(1)), int(m.group(2))
        if 0 <= h < 24 and 0 <= mi < 60:
            return datetime.time(hour=h, minute=mi)
    m = re.match(r'^(\d{1,2}):(\d{2})\s*(am|pm)$', s)
    if m:
        h, mi, ap = int(m.group(1)), int(m.group(2)), m.group(3)
        if ap == "pm" and h != 12:
            h += 12
        if ap == "am" and h == 12:
            h = 0
        if 0 <= h < 24 and 0 <= mi < 60:
            return datetime.time(hour=h, minute=mi)
    return None

def set_alarm(target_time_str):
    target = parse_time_string(target_time_str)
    if not target:
        talk("Sorry, I couldn't understand the time.")
        return False
    now = datetime.datetime.now()
    alarm_dt = now.replace(hour=target.hour, minute=target.minute, second=0, microsecond=0)
    if alarm_dt <= now:
        alarm_dt += datetime.timedelta(days=1)
    seconds = (alarm_dt - now).total_seconds()
    def notify():
        talk("Alarm! It's time.")
        messagebox.showinfo("Alarm", f"Alarm for {target.strftime('%H:%M')}")
    t = threading.Timer(seconds, notify)
    t.daemon = True
    t.start()
    talk(f"Alarm set for {alarm_dt.strftime('%Y-%m-%d %H:%M')}")
    return True

# ------------------------
# Calculator (safe eval)
# ------------------------
def safe_calculate(expr):
    if not re.match(r'^[\d\.\+\-\*\/\%\(\)\s]+$', expr):
        return "Sorry, I can only calculate basic arithmetic."
    try:
        result = eval(expr, {"__builtins__": None}, {})
        return result
    except Exception as e:
        return f"Error: {e}"

# ------------------------
# Security Utilities (Heuristic Spyware Scan & Tools)
# ------------------------
QUARANTINE_DIR = Path(BASE_DIR / "quarantine")
QUARANTINE_DIR.mkdir(exist_ok=True)

SUSPICIOUS_PROCESS_NAMES = {
    "svch0st.exe", "svhost.exe", "lsaas.exe", "expl0rer.exe", "explorer32.exe",
    "taskmger.exe", "winlogin.exe", "winlogon32.exe", "msconfig32.exe",
    "update.exe", "chromeupdater.exe", "adservice.exe", "spoolsv32.exe",
    "reader_sl.exe", "rundIl32.exe", "conhost32.exe"
}

SUSPICIOUS_PORTS = {1337, 4444, 5555, 6666, 6969, 8081, 8222, 13337, 27042}

SUSPICIOUS_DOMAINS = {"microsoft.com", "google.com", "facebook.com",
                      "antivirus.com", "malwarebytes.com", "kaspersky.com",
                      "eset.com", "bitdefender.com"}

def _run_cmd(args):
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True, shell=os.name=="nt")
    except Exception as e:
        return f"ERROR running {args}: {e}"

def _shorten(text, max_chars=8000):
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... (truncated) ..."

def list_processes_text():
    sysname = platform.system()
    if sysname == "Windows":
        return _run_cmd("tasklist /fo table")
    else:
        return _run_cmd(["ps", "aux"])

def list_connections_text():
    sysname = platform.system()
    if sysname == "Windows":
        return _run_cmd("netstat -ano")
    elif sysname == "Darwin":
        return _run_cmd(["lsof", "-i", "-P", "-n"])
    else:
        out = _run_cmd(["ss", "-tulpn"])
        if "ERROR" in out or not out.strip():
            out = _run_cmd(["netstat", "-tunap"])
        return out

def list_startup_items_text():
    sysname = platform.system()
    lines = []
    try:
        if sysname == "Windows":
            if winreg:
                for hive, path in [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                ]:
                    try:
                        key = winreg.OpenKey(hive, path)
                        lines.append(f"[Registry] {path}")
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                lines.append(f"  {name} -> {value}")
                                i += 1
                            except OSError:
                                break
                    except Exception:
                        pass
            startup_dirs = [
                os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
            ]
            for d in startup_dirs:
                if os.path.isdir(d):
                    lines.append(f"[Startup Folder] {d}")
                    for f in os.listdir(d):
                        lines.append(f"  {f}")
            lines.append("[Scheduled Tasks]")
            lines.append(_run_cmd("schtasks /query /fo LIST /v"))
        elif sysname == "Darwin":
            lines.append("[launchctl list]")
            lines.append(_run_cmd(["launchctl", "list"]))
            lines.append("[User crontab]")
            lines.append(_run_cmd(["crontab", "-l"]))
            lines.append("[Hint] Check Login Items in System Settings.")
        else:
            lines.append("[systemd user services]")
            lines.append(_run_cmd(["systemctl", "--user", "list-unit-files", "--type=service"]))
            lines.append("[crontab -l]")
            lines.append(_run_cmd(["crontab", "-l"]))
            autostart = os.path.expanduser("~/.config/autostart")
            if os.path.isdir(autostart):
                lines.append(f"[~/.config/autostart] {autostart}")
                for f in os.listdir(autostart):
                    lines.append(f"  {f}")
    except Exception as e:
        lines.append(f"ERROR listing startup items: {e}")
    return "\n".join(lines)

def check_hosts_file():
    hosts_paths = {
        "Windows": r"C:\Windows\System32\drivers\etc\hosts",
        "Darwin": "/etc/hosts",
        "Linux": "/etc/hosts"
    }
    sysname = platform.system()
    path = hosts_paths.get(sysname, "/etc/hosts")
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for dom in SUSPICIOUS_DOMAINS:
                    if dom in line and not line.startswith("0.0.0.0") and not line.startswith("127."):
                        findings.append(f"Hosts entry might hijack: {line}")
    except Exception as e:
        findings.append(f"Could not read hosts file: {e}")
    return findings

def scan_files_quick(max_files=600):
    findings = []
    sysname = platform.system()
    home = Path.home()
    temps = [Path(os.getenv("TEMP") or os.getenv("TMP") or "/tmp")]
    targets = [home, *temps]
    checked = 0

    suspicious_exts = {".exe", ".dll", ".scr", ".bat", ".vbs", ".js", ".jar", ".ps1", ".sys"}
    try:
        for root in targets:
            if not root.exists():
                continue
            for p in root.rglob("*"):
                if checked >= max_files:
                    break
                if p.is_file():
                    checked += 1
                    name = p.name.lower()
                    ext = p.suffix.lower()
                    try:
                        with open(p, "rb") as f:
                            head = f.read(4)
                        is_exec = (
                            head.startswith(b"MZ") or
                            head.startswith(b"\x7fELF") or
                            head in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")
                        )
                        if is_exec or ext in suspicious_exts:
                            if any(k in name for k in ["update", "service", "svchost", "driver", "chrome", "win"]):
                                findings.append(f"Suspicious file: {p}")
                    except Exception:
                        continue
    except Exception as e:
        findings.append(f"Error during file scan: {e}")
    return findings

def analyze_process_list(proc_text):
    findings = []
    lower = proc_text.lower()
    for bad in SUSPICIOUS_PROCESS_NAMES:
        if bad.lower() in lower:
            findings.append(f"Suspicious process name seen: {bad}")
    return findings

def analyze_connections(conn_text):
    findings = []
    for port in SUSPICIOUS_PORTS:
        if f":{port} " in conn_text or f".{port} " in conn_text:
            findings.append(f"Connection on suspicious port {port} detected.")
    return findings

def build_security_report(full=False):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"Security Scan Report - {ts}", "="*60]
    try:
        proc = list_processes_text()
        lines.append("\n[Processes]\n" + _shorten(proc, 6000))
        lines.extend(analyze_process_list(proc))
    except Exception as e:
        lines.append(f"Error listing processes: {e}")

    try:
        conns = list_connections_text()
        lines.append("\n[Network Connections]\n" + _shorten(conns, 6000))
        lines.extend(analyze_connections(conns))
    except Exception as e:
        lines.append(f"Error listing connections: {e}")

    try:
        startups = list_startup_items_text()
        lines.append("\n[Startup & Persistence]\n" + _shorten(startups, 6000))
    except Exception as e:
        lines.append(f"Error listing startup: {e}")

    hosts_findings = check_hosts_file()
    if hosts_findings:
        lines.append("\n[Hosts File Checks]")
        lines.extend(hosts_findings)

    file_findings = scan_files_quick(max_files=3000 if full else 600)
    if file_findings:
        lines.append("\n[File Scan Findings]")
        lines.extend(file_findings)

    lines.append("\nNotes: This is a heuristic scan and may produce false positives. For a thorough scan, use reputable anti-malware tools.")
    report = "\n".join(lines)
    ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = BASE_DIR / f"security_report_{ts_file}.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    return report, str(out_path)

def quarantine_file(path_str):
    try:
        p = Path(path_str).expanduser()
        if not p.exists() or not p.is_file():
            return False, "File not found."
        dest = QUARANTINE_DIR / (p.name + ".quarantined")
        shutil.move(str(p), str(dest))
        return True, f"Moved to quarantine: {dest}"
    except Exception as e:
        return False, f"Quarantine failed: {e}"

# ------------------------
# Downloads Organizer & File Search
# ------------------------
def search_files(keyword, base_path=None):
    base_path = base_path or str(Path.home())
    matches = []
    for root, _, files in os.walk(base_path):
        for file in files:
            if keyword.lower() in file.lower():
                matches.append(os.path.join(root, file))
    return matches[:20]

def organize_downloads():
    download_dir = Path.home() / "Downloads"
    if not download_dir.exists():
        return "Downloads folder not found."
    for file in download_dir.iterdir():
        if file.is_file():
            ext = file.suffix[1:] if file.suffix else "no_extension"
            dest = download_dir / ext
            dest.mkdir(exist_ok=True)
            try:
                file.rename(dest / file.name)
            except Exception:
                continue
    return "Downloads organized by file type."

# ------------------------
# Online Helpers (Weather/News/Translate)
# ------------------------
def http_get_json(url, headers=None, timeout=8):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None

def get_weather(city: str):
    if not WEATHER_API_KEY:
        return "Weather API key not set."
    if offline_mode:
        return "Weather unavailable offline."
    url = f"https://api.openweathermap.org/data/2.5/weather?q={urllib.parse.quote(city)}&appid={WEATHER_API_KEY}&units=metric"
    data = http_get_json(url)
    if not data or data.get("cod") != 200:
        return "Couldn't fetch weather."
    main = data["main"]
    weather = data["weather"][0]
    temp = main.get("temp")
    feels = main.get("feels_like")
    desc = weather.get("description", "").title()
    name = data.get("name", city.title())
    return f"{name}: {temp}°C (feels {feels}°C), {desc}."

def get_news_headlines(country="us", limit=5):
    if not NEWS_API_KEY:
        return "News API key not set."
    if offline_mode:
        return "News unavailable offline."
    url = f"https://newsapi.org/v2/top-headlines?country={urllib.parse.quote(country)}&pageSize={limit}"
    headers = {"X-Api-Key": NEWS_API_KEY}
    data = http_get_json(url, headers=headers)
    if not data or data.get("status") != "ok":
        return "Couldn't fetch news."
    arts = data.get("articles", [])[:limit]
    out = []
    for i, a in enumerate(arts, 1):
        title = a.get("title") or "Untitled"
        src = (a.get("source") or {}).get("name") or "Unknown"
        out.append(f"{i}. {title} — {src}")
    return "\n".join(out) if out else "No headlines."

def translate_text(text, target_lang):
    if offline_mode:
        return "Translation unavailable offline."
    # MyMemory free API (rate-limited, no key required)
    # target_lang can be language name or code; try to convert common names
    lang_map = {
        "french": "fr", "spanish": "es", "german": "de", "swahili": "sw",
        "kiswahili": "sw", "italian": "it", "portuguese": "pt", "arabic": "ar",
        "japanese": "ja", "chinese": "zh", "english": "en"
    }
    code = target_lang.lower().strip()
    code = lang_map.get(code, code[:2])
    q = urllib.parse.quote_plus(text)
    url = f"https://api.mymemory.translated.net/get?q={q}&langpair=en|{code}"
    data = http_get_json(url)
    if not data:
        return "Couldn't translate."
    return (data.get("responseData") or {}).get("translatedText", "Couldn't translate.")

# ------------------------
# Help text
# ------------------------
def get_help_text():
    lines = [
        "Try these commands:",
        "- help / what can you do",
        "- theme toggle",
        "- voice on / voice off",
        "- open <website or app>  e.g., 'open youtube.com' or 'open notepad'",
        "- search for <query>",
        "- type <your text>",
        "- press <ctrl+c>  (use plus between keys)",
        "- timer <seconds> [message]",
        "- set alarm <HH:MM> or <HH:MM am/pm>",
        "- note <text>, show notes, clear notes",
        "- screenshot",
        "- tell me a joke / fun fact",
        "- calculate <expression>",
        "- flip a coin / roll a dice",
        "- generate password [length]  (auto-saves to encrypted vault; you can label it)",
        "- show passwords / clear passwords",
        "- my ip",
        "- learn command  (guided)",
        "- shutdown / restart (asks for confirmation)",
        "- security scan / security full scan / security report",
        "- quarantine <file_path>",
        "- list connections / list startup",
        "- organize downloads / search file <keyword>",
        "- system monitor",
        "- clipboard history",
        "- weather in <city>",
        "- news today",
        "- translate <text> to <language>",
        "- exit / quit / stop",
    ]
    return "\n".join(lines)

# ------------------------
# Command Handling
# ------------------------
def handle_command(cmd, from_queue=False):
    global offline_mode, use_typing_input, keep_listening

    if not cmd:
        return

    # Safe mode enforcement
    if enforce_safe_mode(cmd):
        return

    # Context memory
    context_memory.append(cmd)
    if len(context_memory) > 50:
        context_memory.pop(0)

    # Learned commands first
    if cmd in learned_commands:
        entry = learned_commands[cmd]
        if entry["type"] == "url":
            open_website_or_search(entry["value"])
            talk(human_like_response())
            return
        elif entry["type"] == "app":
            ok = open_application(entry["value"])
            talk(human_like_response() if ok else "I couldn't open that application.")
            return

    cmd_clean = cmd.strip().lower()

    # Help
    if cmd_clean in ["help", "what can you do", "commands", "menu"]:
        messagebox.showinfo("Capabilities", get_help_text())
        talk("I've shown you what I can do.")
        return

    # Theme / Voice
    if cmd_clean in ["theme toggle", "toggle theme", "switch theme"]:
        toggle_theme()
        return
    if cmd_clean in ["voice on", "enable voice"]:
        toggle_voice(True)
        talk("Voice enabled.")
        return
    if cmd_clean in ["voice off", "mute assistant", "disable voice"]:
        toggle_voice(False)
        talk("Voice muted.")
        return

    # Time & date
    if "time" in cmd_clean and ("what" in cmd_clean or "now" in cmd_clean or "current" in cmd_clean):
        now = datetime.datetime.now().strftime("%H:%M")
        talk(f"The time is {now}.")
        return

    if "date" in cmd_clean:
        today = datetime.datetime.now().strftime("%A, %B %d, %Y")
        talk(f"Today is {today}.")
        return

    # Open / Search (queue if offline)
    if cmd_clean.startswith("open "):
        target = cmd[len("open "):].strip()
        if offline_mode and (("." in target and " " not in target) or True):
            # Opening an app is okay offline; browsing is not. Use heuristic:
            if "." in target and " " not in target:
                queue_online_command(cmd)
                return
        if "." in target and " " not in target:
            open_website_or_search(target)
            talk(human_like_response())
        else:
            ok = open_application(target)
            talk(human_like_response() if ok else "I couldn't open that application.")
        return

    if cmd_clean.startswith("search for "):
        if offline_mode:
            queue_online_command(cmd)
            return
        query = cmd[len("search for "):].strip()
        open_website_or_search(query)
        talk(human_like_response())
        return

    # Typing / Hotkeys
    if cmd_clean.startswith("type "):
        text = cmd[5:]
        type_text(text)
        talk("Typed.")
        return

    if cmd_clean.startswith("press "):
        keys_part = cmd[len("press "):].strip()
        keys = [k.strip() for k in keys_part.split("+") if k.strip()]
        if keys:
            press_hotkey(*keys)
            talk("Hotkey pressed.")
        else:
            talk("Please specify keys like ctrl+c.")
        return

    # Timer
    if cmd_clean.startswith("timer "):
        parts = cmd.split()
        try:
            seconds = int(parts[1])
            message = " ".join(parts[2:]).strip() or "Time's up!"
            set_timer(seconds, message)
            talk(f"Timer set for {seconds} seconds.")
        except Exception:
            talk("Please say: timer <seconds> [message].")
        return

    # Alarm
    if cmd_clean.startswith("set alarm"):
        time_str = cmd.replace("set alarm", "", 1).strip()
        if not time_str:
            time_str = AIMessageBox("Enter alarm time (e.g., 14:30 or 2:30 pm):").get_input()
        if time_str:
            set_alarm(time_str.strip())
        return

    # Notes
    if cmd_clean.startswith("note "):
        note = cmd[5:].strip()
        if note:
            save_note(note)
            talk("Note saved.")
        else:
            talk("What should I note?")
        return

    if cmd_clean in ["show notes", "show my notes", "notes"]:
        notes = read_notes()
        messagebox.showinfo("Your Notes", notes)
        return

    if cmd_clean in ["clear notes", "delete notes"]:
        if confirm_dialog("Clear Notes", "Delete all notes?"):
            clear_notes()
            talk("All notes cleared.")
        return

    # Screenshot
    if "screenshot" in cmd_clean:
        path = take_screenshot()
        message = path if os.path.isfile(path) else str(path)
        talk("Screenshot saved." if os.path.isfile(path) else "Could not take screenshot.")
        messagebox.showinfo("Screenshot", f"{message}")
        return

    # Jokes / facts
    if "joke" in cmd_clean:
        j = random_joke()
        talk(j)
        messagebox.showinfo("Joke", j)
        return

    if "fun fact" in cmd_clean or "fact" in cmd_clean:
        f = random_fact()
        talk(f)
        messagebox.showinfo("Fun Fact", f)
        return

    # Calculator
    if cmd_clean.startswith("calculate "):
        expr = cmd[len("calculate "):].strip()
        result = safe_calculate(expr)
        talk(f"The result is {result}.")
        messagebox.showinfo("Calculation", f"{expr} = {result}")
        return

    # Coin / dice
    if "flip a coin" in cmd_clean:
        talk(coin_flip())
        return

    if "roll a dice" in cmd_clean or "roll a die" in cmd_clean:
        talk(f"You rolled a {roll_dice()}.")
        return

    # Password generation (vault)
    if "generate password" in cmd_clean:
        m = re.search(r'generate password\s*(\d{1,2})?', cmd_clean)
        length = 12
        if m and m.group(1):
            length = int(m.group(1))
        definition_text = AIMessageBox("Optional: What is this password for? (e.g., 'Gmail account')").get_input()
        pwd = generate_password(length)
        meta = {"length": length}
        if definition_text and definition_text.strip():
            meta["definition"] = definition_text.strip()
        add_password_to_vault(pwd, meta=meta)
        # Popup with copy button
        def show_pwd_dialog():
            t = get_theme()
            win = tk.Tk()
            win.title("Generated Password")
            win.geometry("500x160")
            win.configure(bg=t["bg"])
            tk.Label(win, text="Generated Password:", font=("Segoe UI", 11), bg=t["bg"], fg=t["fg"]).pack(pady=(15, 0))
            pwd_entry = tk.Entry(win, font=("Segoe UI", 12), width=40, justify="center", bg="white" if t["bg"]=="white" else "#1e1e1e", fg=t["fg"], insertbackground=t["fg"])
            pwd_entry.insert(0, pwd)
            pwd_entry.configure(state="readonly")
            pwd_entry.pack(pady=(5, 10))
            def copy_to_clipboard():
                win.clipboard_clear()
                win.clipboard_append(pwd)
                win.update()
                messagebox.showinfo("Clipboard", "Password copied to clipboard.")
            tk.Button(win, text="Copy to Clipboard", command=copy_to_clipboard,
                      font=("Segoe UI", 10), bg=get_theme()["accent"], fg="white").pack()
            win.attributes("-topmost", True)
            win.mainloop()
        show_pwd_dialog()
        return

    # Vault commands
    if cmd_clean in ["show passwords", "show saved passwords", "passwords"]:
        contents = show_saved_passwords()
        messagebox.showinfo("Saved Passwords", contents)
        return

    if cmd_clean in ["clear passwords", "delete passwords", "wipe passwords"]:
        if confirm_dialog("Clear Password Vault", "Erase all saved generated passwords?"):
            clear_password_vault()
            talk("Password vault cleared.")
        return

    # IP
    if cmd_clean in ["my ip", "what is my ip", "ip address"]:
        ip = get_local_ip() if not offline_mode else "Unavailable offline"
        talk(f"Your local IP is {ip}.")
        return

    # Learn command
    if cmd_clean.startswith("learn command"):
        trig = AIMessageBox("Type the exact phrase that should trigger the command:").get_input()
        if not trig:
            talk("Cancelled.")
            return
        kind = AIMessageBox("Should this open an 'app' or a 'url'?\nType app or url:").get_input()
        if not kind or kind.strip().lower() not in ["app", "url"]:
            talk("Cancelled.")
            return
        val_prompt = "Type the application name to open:" if kind.strip().lower() == "app" else "Type the full URL (or domain):"
        val = AIMessageBox(val_prompt).get_input()
        if not val:
            talk("Cancelled.")
            return
        learn_custom_command(trig, kind.strip().lower(), val.strip())
        talk("Learned your custom command.")
        return

    # Shutdown / Restart
    if cmd_clean in ["shutdown", "restart"]:
        action = cmd_clean
        if confirm_dialog(action.title(), f"Are you sure you want to {action}?"):
            try:
                if os.name == "nt":
                    if action == "shutdown":
                        os.system("shutdown /s /t 0")
                    else:
                        os.system("shutdown /r /t 0")
                elif sys.platform == "darwin":
                    if action == "shutdown":
                        os.system("osascript -e 'tell app \"System Events\" to shut down'")
                    else:
                        os.system("osascript -e 'tell app \"System Events\" to restart'")
                else:
                    if action == "shutdown":
                        os.system("shutdown -h now")
                    else:
                        os.system("shutdown -r now")
            except Exception:
                talk("I couldn't perform that action.")
        return

    # Security commands
    if cmd_clean in ["security scan", "scan security", "scan spyware"]:
        report, path = build_security_report(full=False)
        messagebox.showinfo("Security Scan (Quick)", f"Report saved to:\n{path}")
        return

    if cmd_clean in ["security full scan", "full security scan", "full scan"]:
        if confirm_dialog("Full Security Scan", "This may take several minutes. Continue?"):
            report, path = build_security_report(full=True)
            messagebox.showinfo("Security Scan (Full)", f"Report saved to:\n{path}")
        return

    if cmd_clean in ["security report", "open security report"]:
        files = sorted(Path(BASE_DIR).glob("security_report_*.txt"))
        if files:
            messagebox.showinfo("Latest Security Report", f"{files[-1]}")
        else:
            messagebox.showinfo("Latest Security Report", "No reports found yet.")
        return

    if cmd_clean.startswith("quarantine "):
        target = cmd[len("quarantine "):].strip().strip('"').strip("'")
        if not target:
            talk("Please specify a file path.")
            return
        ok, msg = quarantine_file(target)
        if ok:
            talk("File quarantined.")
        messagebox.showinfo("Quarantine", msg)
        return

    if cmd_clean in ["list connections", "show connections"]:
        txt = list_connections_text()
        messagebox.showinfo("Connections", _shorten(txt, 8000))
        return

    if cmd_clean in ["list startup", "show startup"]:
        txt = list_startup_items_text()
        messagebox.showinfo("Startup Items", _shorten(txt, 8000))
        return

    # Organizer & search
    if cmd_clean == "organize downloads":
        result = organize_downloads()
        messagebox.showinfo("Downloads", result)
        talk(result)
        return

    if cmd_clean.startswith("search file"):
        keyword = cmd_clean.replace("search file", "", 1).strip()
        if not keyword:
            keyword = AIMessageBox("Enter a keyword to search for files:").get_input() or ""
            keyword = keyword.strip()
        if not keyword:
            talk("No keyword provided.")
            return
        results = search_files(keyword)
        if results:
            messagebox.showinfo("Files Found", "\n".join(results))
        else:
            talk("No matching files found.")
        return

    # System monitor / clipboard
    if cmd_clean in ["system monitor", "show system monitor"]:
        show_system_monitor()
        return

    if cmd_clean in ["clipboard history", "show clipboard"]:
        show_clipboard_history()
        return

    # Weather
    if cmd_clean.startswith("weather in "):
        city = cmd_clean.replace("weather in ", "", 1).strip()
        if offline_mode:
            queue_online_command(cmd)
            return
        info = get_weather(city)
        messagebox.showinfo("Weather", info)
        talk(info)
        return

    # News
    if cmd_clean in ["news today", "news", "headlines"]:
        if offline_mode:
            queue_online_command(cmd)
            return
        # Try to guess country from locale (fallback to 'us')
        country = "us"
        info = get_news_headlines(country=country, limit=5)
        messagebox.showinfo("News Headlines", info)
        talk("Here are today's headlines.")
        return

    # Translate
    if cmd_clean.startswith("translate "):
        if offline_mode:
            queue_online_command(cmd)
            return
        # Pattern: translate <text> to <language>
        m = re.match(r"translate\s+(.+?)\s+to\s+([a-zA-Z]+)$", cmd_clean)
        if not m:
            text = AIMessageBox("What text should I translate (from English)?").get_input() or ""
            lang = AIMessageBox("Translate to which language (e.g., French)?").get_input() or ""
        else:
            text, lang = m.group(1), m.group(2)
        if not text or not lang:
            talk("Cancelled.")
            return
        result = translate_text(text, lang)
        messagebox.showinfo("Translation", result)
        talk(result)
        return

    
    # ---- Tasks ----
    if cmd_clean.startswith("add task "):
        text = cmd[len("add task "):].strip()
        if text:
            add_task(text)
            talk("Task added.")
        else:
            talk("Please provide the task details.")
        return

    if cmd_clean in ["show tasks", "tasks", "list tasks"]:
        messagebox.showinfo("Tasks", format_tasks())
        return

    if cmd_clean.startswith("done task "):
        m = re.match(r"done task\s+(\d+)", cmd_clean)
        if m:
            idx = int(m.group(1))
            ok = mark_task_done(idx)
            talk("Marked done." if ok else "Invalid task number.")
        else:
            talk("Please say: done task <number>.")
        return

    if cmd_clean == "clear tasks":
        if confirm_dialog("Clear Tasks", "Delete all tasks?"):
            clear_all_tasks()
            talk("All tasks cleared.")
        return

    # ---- Reminders ----
    if cmd_clean.startswith("remind me "):
        # Pattern: remind me <text> at <time>
        m = re.match(r"remind me\s+(.+)\s+at\s+(.+)$", cmd_clean)
        if not m:
            text = AIMessageBox("What should I remind you about?").get_input() or ""
            when = AIMessageBox("When? (e.g., 14:30 or 2:30 pm)").get_input() or ""
        else:
            text, when = m.group(1), m.group(2)
        if not text or not when:
            talk("Cancelled.")
            return
        ok, dt = add_reminder(text, when)
        if ok:
            # Also schedule soon (scheduler loop handles it)
            talk(f"Reminder set for {dt.strftime('%Y-%m-%d %H:%M')}")
        else:
            talk(dt)  # dt contains error message
        return

    if cmd_clean in ["show reminders", "reminders", "list reminders"]:
        messagebox.showinfo("Reminders", format_reminders())
        return

    if cmd_clean == "clear reminders":
        if confirm_dialog("Clear Reminders", "Delete all reminders?"):
            clear_reminders()
            talk("All reminders cleared.")
        return

    # ---- Wikipedia ----
    if cmd_clean.startswith("wiki "):
        topic = cmd[len("wiki "):].strip()
        if offline_mode:
            queue_online_command(cmd)
            return
        summary = wiki_summary(topic)
        messagebox.showinfo(f"Wikipedia: {topic.title()}", summary)
        talk("Here's a quick summary.")
        return

    # ---- Converters ----
    if cmd_clean.startswith("convert "):
        expr = cmd[len("convert "):].strip()
        # Try currency first: "100 usd to kes"
        res = convert_currency(expr)
        if res is None or "unavailable offline" in str(res).lower():
            # Try units
            unit_res = convert_units(expr)
            if unit_res:
                messagebox.showinfo("Conversion", unit_res)
                talk(unit_res)
                return
            elif res:
                messagebox.showinfo("Conversion", res)
                talk(res)
                return
            else:
                talk("Sorry, I couldn't parse that conversion.")
                return
        else:
            messagebox.showinfo("Conversion", res)
            talk(res)
            return

    # ---- QR Code ----
    if cmd_clean.startswith("make qr "):
        text = cmd[len("make qr "):].strip()
        if not text:
            talk("What should I encode?")
            return
        ok, msg = make_qr_code(text)
        if ok:
            messagebox.showinfo("QR Code", f"Saved to:\n{msg}")
            talk("QR code saved.")
        else:
            messagebox.showinfo("QR Code", msg)
        return
# Exit
    if cmd_clean in ["exit", "quit", "stop", "goodbye"]:
        keep_listening = False
        globals()["SESSION_MASTER_PASSWORD"] = "stano"
        talk("Goodbye!")
        return

    # Fallback: try web search (queue if offline)
    if offline_mode:
        queue_online_command(cmd)
        return
    open_website_or_search(cmd)
    talk("Here's what I found.")

# ------------------------
# Main
# ------------------------


def show_splash_screen():
    """Display a floating splash screen with logo before login."""
    try:
        t = get_theme()
    except Exception:
        # fallback theme
        t = {"bg": "#1e1e1e", "fg": "#ffffff", "accent": "#4CAF50"}
    import tkinter as tk  # ensure tk alias in this scope
    splash = tk.Tk()
    splash.title("AI Assistant")
    try:
        splash.attributes("-topmost", True)
    except Exception:
        pass
    splash.configure(bg=t.get("bg", "#1e1e1e"))
    splash.geometry("340x460")
    splash.resizable(False, False)

    # Try loading logo if Pillow is available
    added_logo = False
    logo_path = "ai-logo-generator-4.png"  # Put your logo in the same folder as the script
    if 'Image' in globals() and Image is not None and 'ImageTk' in globals() and ImageTk is not None and os.path.exists(logo_path):
        try:
            img = Image.open(logo_path)
            if hasattr(Image, "Resampling"):
                resample = Image.Resampling.LANCZOS
            else:
                resample = getattr(Image, "LANCZOS", getattr(Image, "ANTIALIAS", 1))
            img = img.resize((200, 200), resample)
            logo_img = ImageTk.PhotoImage(img)
            logo_label = tk.Label(splash, image=logo_img, bg=t.get("bg", "#1e1e1e"))
            logo_label.image = logo_img
            logo_label.pack(pady=(20, 10))
            added_logo = True
        except Exception:
            added_logo = False

    if not added_logo:
        tk.Label(splash, text="AI Assistant", font=("Segoe UI", 18, "bold"),
                 bg=t.get("bg", "#1e1e1e"), fg=t.get("fg", "#ffffff")).pack(pady=(30, 10))

    tk.Label(splash, text="Welcome", font=("Segoe UI", 14),
             bg=t.get("bg", "#1e1e1e"), fg=t.get("fg", "#ffffff")).pack(pady=(0, 6))
    tk.Label(splash, text="Click Start to begin", font=("Segoe UI", 11),
             bg=t.get("bg", "#1e1e1e"), fg=t.get("fg", "#ffffff")).pack(pady=(0, 12))

    def proceed():
        splash.destroy()
    tk.Button(splash, text="Start Assistant", font=("Segoe UI", 12),
              bg=t.get("accent", "#4CAF50"), fg="white", activebackground=t.get("accent", "#4CAF50"),
              relief="flat", padx=16, pady=6, command=proceed).pack(pady=14)

    try:
        splash.attributes("-topmost", True)
    except Exception:
        pass
    splash.mainloop()

def main():
    load_settings()
    _init_tts()
    initialize_mode()
    start_clipboard_watcher()
    _load_or_create_key()   # ensure key exists
    ok = login_gate()
    start_reminder_scheduler()
    if not ok:
        return
    load_learned_commands()
    talk("Assistant is ready. Say 'help' to see what I can do.")
    process_offline_queue()

    while keep_listening:
        cmd = listen_command()
        if not cmd:
            continue
        # Re-check connectivity each loop; if we just came online, process queue
        prev_offline = offline_mode
        initialize_mode()
        if prev_offline and not offline_mode:
            process_offline_queue()
        try:
            handle_command(cmd)
        except Exception as e:
            messagebox.showerror("Error", f"Something went wrong: {e}")

if __name__ == "__main__":
    try:
        main()
    finally:
        SESSION_MASTER_PASSWORD = "stano"
