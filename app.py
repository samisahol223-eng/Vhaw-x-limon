#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Vhaw_X_limon PANEL  —  All-in-One Combined Edition                            ║
║  Features: Terminal | Credentials | 13 Tools | Admin Panel | JWT Manager    ║
╚══════════════════════════════════════════════════════════════════════════════╝
Admin: GET /admin  →  username: @rizer  |  password: @rizer14890
"""

# ══════════════════════════════════════════════════════════════════════════════
#  STANDARD LIBRARY IMPORTS
# ══════════════════════════════════════════════════════════════════════════════
import os
import sys
import re
import json
import time
import uuid
import shutil
import hmac
import hashlib
import secrets
import logging
import sqlite3
import subprocess
import threading
import asyncio
import base64
import gzip
import binascii
import importlib.util
import tempfile
import urllib3
import smtplib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'pb2_folder'))
from pb2_folder import *
# Core protos
from MajorLoginReq_pb2 import MajorLogin, GameSecurity
from MajorLoginRes_pb2 import MajorLoginRes

# Friend
from Friends_pb2 import Friends, Friend
from GetLoginDataRes_pb2 import GetLoginData
# Bio
from bio_pb2 import Data as BioData, EmptyMessage

# Remove friend
from RemoveFriend_Req_pb2 import RemoveFriend

# Guild
from ReqCLan_pb2 import MyMessage as ReqCLan
from QuitClanReq_pb2 import QuitClanReq
from clan_pb2 import GetClanMembersResponse, MemberInfo, ClanMemberEntry
# Flask imports
from flask import (
    Flask, request, jsonify, session, redirect,
    make_response, send_from_directory, render_template_string
)

# ══════════════════════════════════════════════════════════════════════════════
#  DISABLE WARNINGS
# ══════════════════════════════════════════════════════════════════════════════
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
SECRET_KEY = secrets.token_hex(32)
ADMIN_USER = "@rizer"
ADMIN_PASS = "@rizer14890"
DB_PATH = "rizertcp.db"
DATA_DIR = Path("DATA")
TCP_DIR = Path("TCP")
SESSION_DAYS = 30

# SMTP defaults
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "your@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "yourpassword")
SMTP_FROM = os.getenv("SMTP_FROM", "Vhaw_X_limon <your@gmail.com>")

# ══════════════════════════════════════════════════════════════════════════════
#  FLASK APP INIT
# ══════════════════════════════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=SESSION_DAYS)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("Vhaw_X_limon")

# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════
user_processes: dict[str, subprocess.Popen] = {}
user_output: dict[str, list] = {}
user_locks: dict[str, threading.Lock] = {}
broadcasts: list[dict] = []
maintenance_mode = False
# JWT token cache per user: {username: {"token": "...", "expires": timestamp}}
jwt_cache: dict[str, dict] = {}
# Admin SMTP config (runtime mutable)
_admin_smtp = {
    "host": SMTP_HOST, "port": SMTP_PORT,
    "user": SMTP_USER, "pass": SMTP_PASS, "from": SMTP_FROM
}

# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            is_blocked  INTEGER DEFAULT 0,
            is_banned   INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now')),
            last_login  TEXT
        );
        CREATE TABLE IF NOT EXISTS credentials (
            username    TEXT PRIMARY KEY,
            uid         TEXT,
            password    TEXT,
            owner_uid   TEXT,
            owner_name  TEXT,
            updated_at  TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token       TEXT PRIMARY KEY,
            email       TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            used        INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS verify_codes (
            email       TEXT PRIMARY KEY,
            code        TEXT NOT NULL,
            expires_at  TEXT NOT NULL
        );
        """)

# ══════════════════════════════════════════════════════════════════════════════
#  PASSWORD HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def hash_password(plain: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260_000)
    return f"{salt}${h.hex()}"

def verify_password(plain: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260_000)
        return hmac.compare_digest(candidate.hex(), h)
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  AUTH / SESSION HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def current_user():
    return session.get("username")

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        cu = current_user()
        if not cu:
            if request.is_json:
                return jsonify({"ok": False, "msg": "Not authenticated"}), 401
            return redirect("/login")
        with get_db() as db:
            u = db.execute("SELECT * FROM users WHERE username=?", (cu,)).fetchone()
        if not u:
            session.clear()
            return redirect("/login")
        if u["is_banned"]:
            session.clear()
            return jsonify({"ok": False, "msg": "Account banned"}), 403
        if u["is_blocked"]:
            return jsonify({"ok": False, "msg": "Account blocked"}), 403
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("is_admin") is not True:
            return redirect("/admin")
        return f(*args, **kwargs)
    return wrapper

# ══════════════════════════════════════════════════════════════════════════════
#  SMTP
# ══════════════════════════════════════════════════════════════════════════════
def send_email(to: str, subject: str, html: str) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.ehlo()
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, to, msg.as_string())
        log.info(f"Email sent to {to}")
        return True
    except Exception as e:
        log.error(f"Email failed: {e}")
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  FILE HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def ensure_user_data(username: str) -> Path:
    dest = DATA_DIR / username
    dest.mkdir(parents=True, exist_ok=True)
    return dest

def copy_tcp_to_user(username: str):
    src = TCP_DIR
    dest = ensure_user_data(username)
    if not src.exists():
        src.mkdir(parents=True, exist_ok=True)
        return
    for item in src.iterdir():
        d = dest / item.name
        if item.is_dir():
            if d.exists():
                shutil.rmtree(d)
            shutil.copytree(item, d)
        else:
            shutil.copy2(item, d)

def write_rizer_txt(username: str, uid: str, password: str):
    path = DATA_DIR / username / "Vhaw.txt"
    path.write_text(f"uid={uid}\npassword={password}\n")

def get_user_creds(username: str):
    with get_db() as db:
        row = db.execute("SELECT * FROM credentials WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None

def user_process_lock(username: str) -> threading.Lock:
    if username not in user_locks:
        user_locks[username] = threading.Lock()
    return user_locks[username]

def stream_output(username: str, proc: subprocess.Popen):
    if username not in user_output:
        user_output[username] = []
    try:
        for line in iter(proc.stdout.readline, b""):
            txt = line.decode("utf-8", errors="replace").rstrip()
            with user_process_lock(username):
                user_output[username].append(txt)
        proc.wait()
    except Exception as e:
        with user_process_lock(username):
            user_output[username].append(f"[stream error] {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  JWT TOKEN MANAGER
# ══════════════════════════════════════════════════════════════════════════════
def get_jwt_token_path(username: str) -> Path:
    return DATA_DIR / username / "token.txt"

def save_jwt_token(username: str, token: str):
    path = get_jwt_token_path(username)
    path.write_text(token)
    expires = (datetime.utcnow() + timedelta(hours=6)).timestamp()
    jwt_cache[username] = {"token": token, "expires": expires}

def load_jwt_token(username: str) -> str | None:
    cached = jwt_cache.get(username)
    if cached:
        if datetime.utcnow().timestamp() < cached["expires"]:
            return cached["token"]
    path = get_jwt_token_path(username)
    if path.exists():
        token = path.read_text().strip()
        expires = (datetime.utcnow() + timedelta(hours=6)).timestamp()
        jwt_cache[username] = {"token": token, "expires": expires}
        return token
    return None

def clear_jwt_token(username: str):
    jwt_cache.pop(username, None)
    path = get_jwt_token_path(username)
    if path.exists():
        path.unlink()

def generate_jwt_for_user(username: str) -> tuple[bool, str, str | None]:
    creds = get_user_creds(username)
    if not creds or not creds.get("uid") or not creds.get("password"):
        return False, "Credentials not set.", None
    uid = creds["uid"].strip()
    pwd = creds["password"].strip()
    ok, result, jwt = _process_credentials_internal(uid, pwd)
    if ok and jwt:
        save_jwt_token(username, jwt)
        return True, "JWT generated and saved.", jwt
    return False, result if isinstance(result, str) else "JWT generation failed.", None

# ══════════════════════════════════════════════════════════════════════════════
#  PROCESS MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
def start_user_process(username: str) -> tuple[bool, str]:
    creds = get_user_creds(username)
    if not creds or not creds.get("uid") or not creds.get("password"):
        return False, "Credentials not set. Go to Menu > Credentials first."
    if username in user_processes:
        p = user_processes[username]
        if p.poll() is None:
            return False, "Process already running."

    copy_tcp_to_user(username)

    owner_uid = creds.get("owner_uid") or None
    owner_name = creds.get("owner_name") or None
    if owner_uid or owner_name:
        update_rizer4_owner(username, owner_uid, owner_name)

    write_rizer_txt(username, creds["uid"], creds["password"])

    work_dir = str(DATA_DIR / username)
    rizer_py = Path(work_dir) / "Vhaw.py"
    if not rizer_py.exists():
        return False, "Vhaw.py not found in your data folder. Check TCP/ source."

    user_output[username] = [
        f"[Vhaw_X_limon] Starting session for user: {username}",
        f"[Vhaw_X_limon] Working directory: {work_dir}",
        f"[Vhaw_X_limon] Updating Vhaw.txt ...",
        f"[Vhaw_X_limon] Launching Vhaw.py ...",
        ""
    ]

    proc = subprocess.Popen(
        [sys.executable, "-u", "Vhaw.py"],
        cwd=work_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1
    )
    user_processes[username] = proc
    t = threading.Thread(target=stream_output, args=(username, proc), daemon=True)
    t.start()
    return True, "Process started."

def stop_user_process(username: str, force: bool = False) -> tuple[bool, str]:
    proc = user_processes.get(username)
    if not proc:
        return False, "No process running."
    if force:
        proc.kill()
        msg = "Process force-killed."
    else:
        proc.terminate()
        msg = "Process stopped."
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    user_processes.pop(username, None)
    with user_process_lock(username):
        user_output.setdefault(username, []).append(f"[Vhaw_X_limon] {msg}")
    return True, msg

def restart_user_process(username: str) -> tuple[bool, str]:
    stop_user_process(username, force=True)
    time.sleep(0.5)
    return start_user_process(username)

def process_status(username: str) -> str:
    proc = user_processes.get(username)
    if not proc:
        return "stopped"
    return "running" if proc.poll() is None else "stopped"

# ══════════════════════════════════════════════════════════════════════════════
#  OWNER UID / NAME IN Vhaw.py
# ══════════════════════════════════════════════════════════════════════════════
def update_rizer4_owner(username: str, owner_uid: str | None = None, owner_name: str | None = None):
    rizer4_path = DATA_DIR / username / "Vhaw.py"
    if not rizer4_path.exists():
        return False, "Vhaw.py not found."
    try:
        content = rizer4_path.read_text()
        if owner_uid:
            content = content.replace("8173310382", owner_uid)
        if owner_name:
            content = content.replace("RIZER", owner_name)
        rizer4_path.write_text(content)
        return True, "Vhaw.py updated with owner info."
    except Exception as e:
        return False, str(e)

# ══════════════════════════════════════════════════════════════════════════════
#  ══════ GAY.PY CORE FUNCTIONS (TOKEN EXTRACTION + 13 TOOLS) ══════
# ══════════════════════════════════════════════════════════════════════════════

# ── Constants ──
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"
GET_LOGIN_DATA_URL_SUFFIX = "/GetLoginData"
MODIFY_NICKNAME_URL = "https://loginbp.ggblueshark.com/MajorModifyNickname"
CLIENT_ID = "100067"
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
PROTO_KEY = b'Yg&tc%DEuh6%Zc^8'
PROTO_IV = b'6oyZDr22E3ychjM%'

BASE_HEADERS = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB53"
}

MAJOR_LOGIN_REQ_B64 = "ChNNYWpvckxvZ2luUmVxLnByb3RvIvoKCgpNYWpvckxvZ2luEhIKCmV2ZW50X3RpbWUYAyABKAkSEQoJZ2FtZV9uYW1lGAQgASgJEhMKC3BsYXRmb3JtX2lkGAUgASgFEhYKDmNsaWVudF92ZXJzaW9uGAcgASgJEhcKD3N5c3RlbV9zb2Z0d2FyZRgIIAEoCRIXCg9zeXN0ZW1faGFyZHdhcmUYCSABKAkSGAoQdGVsZWNvbV9vcGVyYXRvchgKIAEoCRIUCgxuZXR3b3JrX3R5cGUYCyABKAkSFAoMc2NyZWVuX3dpZHRoGAwgASgNEhUKDXNjcmVlbl9oZWlnaHQYDSABKA0SEgoKc2NyZWVuX2RwaRgOIAEoCRIZChFwcm9jZXNzb3JfZGV0YWlscxgPIAEoCRIOCgZtZW1vcnkYECABKA0SFAoMZ3B1X3JlbmRlcmVyGBEgASgJEhMKC2dwdV92ZXJzaW9uGBIgASgJEhgKEHVuaXF1ZV9kZXZpY2VfaWQYEyABKAkSEQoJY2xpZW50X2lwGBQgASgJEhAKCGxhbmd1YWdlGBUgASgJEg8KB29wZW5faWQYFiABKAkSFAoMb3Blbl9pZF90eXBlGBcgASgJEhMKC2RldmljZV90eXBlGBggASgJEicKEG1lbW9yeV9hdmFpbGFibGUYGSABKAsyDS5HYW1lU2VjdXJpdHkSFAoMYWNjZXNzX3Rva2VuGB0gASgJEhcKD3BsYXRmb3JtX3Nka19pZBgeIAEoBRIaChJuZXR3b3JrX29wZXJhdG9yX2EYKSABKAkSFgoObmV0d29ya190eXBlX2EYKiABKAkSHAoUY2xpZW50X3VzaW5nX3ZlcnNpb24YOSABKAkSHgoWZXh0ZXJuYWxfc3RvcmFnZV90b3RhbBg8IAEoBRIiChpleHRlcm5hbF9zdG9yYWdlX2F2YWlsYWJsZRg9IAEoBRIeChhpbnRlcm5hbF9zdG9yYWdlX3RvdGFsGD4gASgFEiIKGmludGVybmFsX3N0b3JhZ2VfYXZhaWxhYmxlGD8gASgFEiMKG2dhbWVfZGlza19zdG9yYWdlX2F2YWlsYWJsZRhAIAEoBRIfChdnYW1lX2Rpc2tfc3RvcmFnZV90b3RhbBhBIAEoBRIlCh1leHRlcm5hbF9zZGNhcmRfYXZhaWxfc3RvcmFnZRhCIAEoBRIlCh1leHRlcm5hbF9zZGNhcmRfdG90YWxfc3RvcmFnZRhDIAEoBRIQCghsb2dpbl9ieRhJIAEoBRIUCgxsaWJyYXJ5X3BhdGgYSiABKAkSEgoKcmVnX2F2YXRhchhMIAEoBRIVCg1saWJyYXJ5X3Rva2VuGE0gASgJEhQKDGNoYW5uZWxfdHlwZRhOIAEoBRIQCghjcHVfdHlwZRhPIAEoBRIYChBjcHVfYXJjaGl0ZWN0dXJlGFEgASgJEhsKE2NsaWVudF92ZXJzaW9uX2NvZGUYUyABKAkSFAoMZ3JhcGhpY3NfYXBpGFYgASgJEh0KFXN1cHBvcnRlZF9hc3RjX2JpdHNldBhXIAEoDRIaChJsb2dpbl9vcGVuX2lkX3R5cGUYWCABKAUSGAoQYW5hbHl0aWNzX2RldGFpbBhZIAEoDBIUCgxsb2FkaW5nX3RpbWUYXCABKA0SFwoPcmVsZWFzZV9jaGFubmVsGF0gASgJEhIKCmV4dHJhX2luZm8YXiABKAkSIAoYYW5kcm9pZF9lbmdpbmVfaW5pdF9mbGFnGF8gASgNEg8KB2lmX3B1c2gYYSABKAUSDgoGaXNfdnBuGGIgASgFEhwKFG9yaWdpbl9wbGF0Zm9ybV90eXBlGGMgASgJEh0KFXByaW1hcnlfcGxhdGZvcm1fdHlwZRhkIAEoCSI1CgxHYW1lU2VjdXJpdHkSDwoHdmVyc2lvbhgGIAEoBRIUCgxoaWRkZW5fdmFsdWUYCCABKARiBnByb3RvMw=="
MAJOR_LOGIN_RES_B64 = "ChNNYWpvckxvZ2luUmVzLnByb3RvInwKDU1ham9yTG9naW5SZXMSEwoLYWNjb3VudF91aWQYASABKAQSDgoGcmVnaW9uGAIgASgJEg0KBXRva2VuGAggASgJEgsKA3VybBgKIAEoCRIRCgl0aW1lc3RhbXAYFSABKAMSCwoDa2V5GBYgASgMEgoKAml2GBcgASgMYgZwcm90bzM="
GET_LOGIN_DATA_B64 = "ChVHZXRMb2dpbkRhdGFSZXMucHJvdG8ipAEKDEdldExvZ2luRGF0YRISCgpBY2NvdW50VUlEGAEgASgEEg4KBlJlZ2lvbhgDIAEoCRITCgtBY2NvdW50TmFtZRgEIAEoCRIWCg5PbmxpbmVfSVBfUG9ydBgOIAEoCRIPCgdDbGFuX0lEGBQgASgDEhYKDkFjY291bnRJUF9Qb3J0GCAgASgJEhoKEkNsYW5fQ29tcGlsZWRfRGF0YRg3IAEoCWIGcHJvdG8z"

FREEFIRE_VERSION = "OB53"
FRIEND_ENDPOINT = "/GetFriend"
FRIEND_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
FRIEND_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
FRIEND_PAYLOAD_HEX = "080110011001"

SERVER_BASE_URLS = [
    "https://client.ind.freefiremobile.com",
    "https://clientbp.ggpolarbear.com",
    "https://clientbp.ggpolarbear.com",
    "https://clientbp.ggpolarbear.com",
    "https://client.us.freefiremobile.com",
]

LOGIN_HISTORY_PAYLOAD = bytes.fromhex(
    '31574468e21173866b9680a6ffb84e35e109c6850b919d09168148778839f3ed'
    '6696f58d4ec4c105a40b1063ecf5bb56'
)
LOGIN_HISTORY_SERVERS = [
    "https://client.ind.freefiremobile.com",
    "https://clientbp.ggpolarbear.com",
    "https://client.us.freefiremobile.com",
]

PROFILE_AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
PROFILE_AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
PROFILE_DEFAULT_ITEMS = "203000000/204000000/205000000/211000000/211000000/211000000/203000000/203000000/203000000/204000000/204000000/204000000/205000000/205000000/205000000"

WISHLIST_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
WISHLIST_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
WISHLIST_ITEMS = [
    101000001, 102000014, 101000005, 101000006, 101000011, 101000016, 101000027,
    102000021, 102000025, 102000030, 102000046, 102000055, 103000004, 103000003,
    203000001, 203000055, 203000074, 203000075, 203000076, 203000077, 203000078,
    203000150, 203000151, 203000156, 203000089, 203000084, 203000177, 203000182,
    203000202, 203000207, 203000245, 203000348, 203000349, 203000350, 203000351,
    203000352, 203000490, 1803400001, 1803400002, 1310000271, 1309000074, 1309000081,
    1309000091, 1309000083, 1309000084, 1309000101, 1309000102, 1309000103, 1309000104,
    1309000114, 1309000142, 1309000173, 1309000212, 928005203, 929005202, 929005203
]

CRAFTLAND_REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com",
    "ID": "https://clientbp.ggblueshark.com",
    "BR": "https://client.us.freefiremobile.com",
    "ME": "https://clientbp.common.ggbluefox.com",
    "VN": "https://clientbp.ggblueshark.com",
    "TH": "https://clientbp.common.ggbluefox.com",
    "CIS": "https://clientbp.ggblueshark.com",
    "BD": "https://clientbp.ggpolarbear.com",
    "PK": "https://clientbp.ggblueshark.com",
    "SG": "https://clientbp.ggblueshark.com",
    "SAC": "https://client.us.freefiremobile.com",
    "TW": "https://clientbp.ggblueshark.com"
}
CRAFTLAND_REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi",
    "TH": "th", "BD": "bn", "PK": "ur", "TW": "zh",
    "CIS": "ru", "SAC": "es", "BR": "pt", "SG": "en"
}
PLAYER_INFO_SERVERS = {
    "IND": "https://client.ind.freefiremobile.com",
    "BD": "https://clientbp.ggpolarbear.com",
    "SG": "https://clientbp.ggblueshark.com",
    "BR": "https://client.us.freefiremobile.com",
    "ID": "https://clientbp.ggblueshark.com",
    "TH": "https://clientbp.common.ggbluefox.com",
    "VN": "https://clientbp.ggblueshark.com",
    "PK": "https://clientbp.ggblueshark.com",
    "TW": "https://clientbp.ggblueshark.com",
    "CIS": "https://clientbp.ggblueshark.com",
    "ME": "https://clientbp.common.ggbluefox.com",
    "SAC": "https://client.us.freefiremobile.com"
}


# ── Protobuf Loaders (Multi-Version Compatible) ──
def _get_protobuf_builder():
    """Get the builder module, handling different protobuf versions."""
    try:
        from google.protobuf.internal import builder as _builder
        return _builder
    except ImportError:
        try:
            from google.protobuf import builder as _builder
            return _builder
        except ImportError:
            return None

def _get_descriptor_pool():
    """Get descriptor pool with fallback for different protobuf versions."""
    from google.protobuf import descriptor_pool as _descriptor_pool
    return _descriptor_pool

def _get_symbol_database():
    """Get symbol database."""
    from google.protobuf import symbol_database as _symbol_database
    return _symbol_database

def _exec_proto_module(code, mod_name, temp_dir):
    """Execute generated protobuf module code safely."""
    import os
    import sys
    import importlib.util
    p = os.path.join(temp_dir, f"{mod_name}.py")
    with open(p, "w", encoding="utf-8") as f:
        f.write(code)
    spec = importlib.util.spec_from_file_location(mod_name, p)
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module
def encrypt_proto(payload_bytes, key=PROTO_KEY, iv=PROTO_IV):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload_bytes, AES.block_size))

def decrypt_proto(encrypted_bytes, key=PROTO_KEY, iv=PROTO_IV):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
    except Exception:
        return None

def encrypt_friend_payload(hex_data: str) -> bytes:
    raw = bytes.fromhex(hex_data)
    cipher = AES.new(FRIEND_KEY, AES.MODE_CBC, FRIEND_IV)
    return cipher.encrypt(pad(raw, AES.block_size))

def encode_varint(num):
    result = bytearray()
    num = int(num)
    while True:
        byte = num & 0x7F
        num >>= 7
        if num:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            break
    return bytes(result)

def decode_varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, pos


# ══════════════════════════════════════════════════════════════════════════════
#  TOKEN EXTRACTION (Internal — used by gay.py features)
# ══════════════════════════════════════════════════════════════════════════════
def generate_access_token(uid, password):
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/5.5.2P3(SM-A515F;Android 12;en-US;IND;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid, "password": password, "response_type": "token",
        "client_type": "2", "client_secret": CLIENT_SECRET, "client_id": CLIENT_ID
    }
    try:
        resp = requests.post(OAUTH_URL, headers=headers, data=data, timeout=30, verify=False)
        if resp.status_code == 200:
            j = resp.json()
            return j.get("open_id") or "", j.get("access_token") or "", None
        return "", "", f"HTTP {resp.status_code}"
    except Exception as e:
        return "", "", str(e)

def build_major_login_message(open_id, access_token):
    if MajorLogin is None:
        raise RuntimeError("MajorLogin protobuf class not loaded. Check protobuf installation.")
    ml = MajorLogin()
    
    # Required fields (always present)
    ml.event_time = str(datetime.now())[:-7]
    ml.game_name = "free fire"
    ml.platform_id = 1
    ml.client_version = "1.123.2"
    ml.system_software = "Android OS 10 / API-29 (QD1A.190821.011/5849216)"
    ml.system_hardware = "Handheld"
    ml.telecom_operator = "China Unicom"
    ml.network_type = "WIFI"
    ml.screen_width = 1280
    ml.screen_height = 720
    ml.screen_dpi = "320"
    ml.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    ml.memory = 14744
    ml.gpu_renderer = "Mali-G610"
    ml.gpu_version = "OpenGL ES 3.2 v1.g18p0-01eac0.afc0c44d2bf700b7b3cddd89c9a98ddb"
    ml.unique_device_id = "Google|1ade57f4-d8bd-4394-983d-5abc08665af5"
    ml.client_ip = ""          # optional, can be left empty
    ml.language = "en"
    ml.open_id = open_id
    ml.open_id_type = "4"
    ml.device_type = "Handheld"
    
    # memory_available (nested GameSecurity)
    if hasattr(ml, 'memory_available'):
        ml.memory_available.version = 55
        ml.memory_available.hidden_value = 81
    
    ml.access_token = access_token
    ml.platform_sdk_id = 1
    ml.network_operator_a = "China Unicom"
    ml.network_type_a = "WIFI"
    ml.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    
    # Storage fields – only set if they exist in the protobuf
    if hasattr(ml, 'external_storage_total'):
        ml.external_storage_total = 217556
    if hasattr(ml, 'external_storage_available'):
        ml.external_storage_available = 171819
    if hasattr(ml, 'internal_storage_total'):
        ml.internal_storage_total = 217556
    if hasattr(ml, 'internal_storage_available'):
        ml.internal_storage_available = 171819
    if hasattr(ml, 'game_disk_storage_available'):
        ml.game_disk_storage_available = 182941
    if hasattr(ml, 'game_disk_storage_total'):
        ml.game_disk_storage_total = 217556
    if hasattr(ml, 'external_sdcard_avail_storage'):
        ml.external_sdcard_avail_storage = 182941
    if hasattr(ml, 'external_sdcard_total_storage'):
        ml.external_sdcard_total_storage = 217556
    
    ml.login_by = 3
    ml.library_path = "/data/app/com.dts.freefireth-hIsmpRep4Cnt3cAycAAo_w==/lib/arm64"
    ml.reg_avatar = 1
    ml.library_token = "17e6a447803a17e4f59e3fd734efc5ae|/data/app/com.dts.freefireth-hIsmpRep4Cnt3cAycAAo_w==/base.apk"
    ml.channel_type = 3
    ml.cpu_type = 2
    ml.cpu_architecture = "64"
    
    if hasattr(ml, 'client_version_code'):
        ml.client_version_code = "2019120270"
    
    ml.graphics_api = "OpenGLES2"
    
    if hasattr(ml, 'supported_astc_bitset'):
        ml.supported_astc_bitset = 255
    
    ml.login_open_id_type = 4
    ml.loading_time = 6155
    ml.release_channel = "android"
    ml.extra_info = "KqsHTy3KUhvha/qugOBot9Bf7gcwqrf2btWC5rnrKZxrHIxEFfgxmPVkTxN+2dHiSprlxvm2Kl6o8EEgBJy7FzLLpbARlcqc2f/GQz+6UsLSMGXd"
    ml.android_engine_init_flag = 111107
    ml.if_push = 1
    ml.is_vpn = 1
    ml.origin_platform_type = "4"
    ml.primary_platform_type = "4"
    
    # analytics_detail – must be bytes
    ml.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
    
    return ml.SerializeToString()

def major_login(open_id, access_token, retries=3):
    if MajorLoginRes is None:
        return False, "MajorLoginRes protobuf class not loaded."
    payload = encrypt_proto(build_major_login_message(open_id, access_token))
    for attempt in range(retries):
        try:
            resp = requests.post(MAJOR_LOGIN_URL, data=payload, headers=BASE_HEADERS, timeout=30, verify=False)
            if resp.status_code != 200:
                if attempt < retries - 1:
                    time.sleep(1)
                    continue
                return False, f"HTTP {resp.status_code}"
            data = resp.content
            res = MajorLoginRes()
            if len(data) % 16 == 0:
                dec = decrypt_proto(data)
                if dec:
                    res.ParseFromString(dec)
            else:
                res.ParseFromString(data)
            if res.token:
                return True, {
                    "account_uid": res.account_uid,
                    "region": res.region,
                    "token": res.token,
                    "url": res.url,
                    "timestamp": res.timestamp,
                    "key": res.key.hex() if isinstance(res.key, bytes) else res.key,
                    "iv": res.iv.hex() if isinstance(res.iv, bytes) else res.iv,
                }
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return False, "No token in response"
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return False, str(e)
    return False, "Max retries exceeded"

def get_login_data(base_url, token, payload_to_resend):
    if GetLoginData is None:
        return False, "GetLoginData protobuf class not loaded."
    url = f"{base_url}{GET_LOGIN_DATA_URL_SUFFIX}"
    headers = BASE_HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.post(url, data=payload_to_resend, headers=headers, timeout=30, verify=False)
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}"
        data = resp.content
        res = GetLoginData()
        if len(data) % 16 == 0:
            dec = decrypt_proto(data)
            if dec:
                res.ParseFromString(dec)
        else:
            res.ParseFromString(data)
        if res.AccountUID:
            return True, {
                "account_uid": res.AccountUID,
                "region": res.Region,
                "account_name": res.AccountName,
                "online_ip_port": res.Online_IP_Port,
                "clan_id": getattr(res, "Clan_ID", 0),
                "account_ip_port": res.AccountIP_Port,
            }
        return False, "No AccountUID"
    except Exception as e:
        return False, str(e)

def _process_credentials_internal(uid, password):
    if MajorLogin is None or MajorLoginRes is None:
        return False, "Protobuf classes not loaded. Check server logs and protobuf installation (pip install protobuf).", None
    open_id, access_token, err = generate_access_token(uid, password)
    if err:
        return False, f"Auth failed: {err}", None
    success, login_res = major_login(open_id, access_token)
    if not success:
        return False, f"Major login failed: {login_res}", None
    jwt_token = login_res.get("token")
    return True, login_res, jwt_token


# ══════════════════════════════════════════════════════════════════════════════
#  13 TOOL FUNCTIONS FROM GAY.PY
# ══════════════════════════════════════════════════════════════════════════════

# ── Nickname ──
def _encode_varint_nick(value):
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result) if result else b'\x00'

def _create_name_protobuf(nickname, idk):
    result = b''
    nb = nickname.encode("utf-8")
    result += bytes([(1 << 3) | 2])
    result += _encode_varint_nick(len(nb))
    result += nb
    result += bytes([(2 << 3) | 0])
    result += _encode_varint_nick(idk)
    return result

def _encrypt_nickname(nickname, key, iv):
    serialized = _create_name_protobuf(nickname, secrets.randbits(32))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(serialized, AES.block_size))
    return binascii.hexlify(encrypted).decode("utf-8")

def change_nickname(jwt_token, new_name):
    try:
        payload = decode_jwt_payload(jwt_token)
        region = payload.get("lock_region", "BD").upper() if payload else "BD"
    except Exception:
        region = "BD"
    key = PROTO_KEY
    iv = PROTO_IV
    encrypted_hex = _encrypt_nickname(new_name, key, iv)
    payload = bytes.fromhex(encrypted_hex)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Content-Type": "application/octet-stream",
        "Authorization": f"Bearer {jwt_token}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53"
    }
    try:
        r = requests.post(MODIFY_NICKNAME_URL, data=payload, headers=headers, timeout=30, verify=False)
        if r.status_code == 200:
            return True, f"Nickname changed to '{new_name}'"
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)


# ── Login History ──
def _parse_login_history(data):
    logins = []
    pos = 0
    while pos < len(data):
        try:
            if data[pos] != 0x0A:
                pos += 1
                continue
            pos += 1
            entry_len, pos = decode_varint(data, pos)
            entry_end = pos + entry_len
            entry = {}
            while pos < entry_end and pos < len(data):
                tag = data[pos]
                pos += 1
                field_num = tag >> 3
                wire_type = tag & 0x07
                if wire_type == 0:
                    value, pos = decode_varint(data, pos)
                    if field_num == 1:
                        entry["timestamp"] = value
                        try:
                            dt = datetime.fromtimestamp(value)
                            entry["time"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            entry["time"] = "Invalid"
                    elif field_num == 2:
                        entry["field2"] = value
                elif wire_type == 2:
                    str_len, pos = decode_varint(data, pos)
                    if pos + str_len <= len(data):
                        value = data[pos:pos + str_len].decode("utf-8", errors="ignore")
                        if field_num == 3:
                            entry["device"] = value
                        elif field_num == 4:
                            entry["arch"] = value
                        pos += str_len
            if "device" in entry:
                entry.setdefault("timestamp", 0)
                entry.setdefault("time", "Unknown")
                entry.setdefault("arch", "Unknown")
                entry.setdefault("field2", "N/A")
                logins.append(entry)
        except Exception:
            pos += 1
            continue
    return logins

def fetch_login_history(jwt_token):
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; V2065A Build/QP1A.190711.020)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    for server in LOGIN_HISTORY_SERVERS:
        url = f"{server}/GetLoginHistory"
        try:
            resp = requests.post(url, headers=headers, data=LOGIN_HISTORY_PAYLOAD, timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.content
                if data[:2] == b'\x1f\x8b':
                    data = gzip.decompress(data)
                return _parse_login_history(data)
        except Exception:
            continue
    return None


# ── Friend List ──
def _parse_friend_response(content_bytes):
    pb = Friends()
    pb.ParseFromString(content_bytes)
    friends_list = []
    my_info = None
    entries = getattr(pb, "field_1", getattr(pb, "field1", None))
    if entries is None:
        return None, "No friend list field"
    for f in entries:
        friends_list.append({"uid": str(f.ID), "name": f.Name})
    if friends_list:
        my_info = friends_list[-1]
        friends_list = friends_list[:-1]
    return friends_list, my_info

def _fetch_friend_from_server(base_url, jwt, timeout=10):
    url = f"{base_url}{FRIEND_ENDPOINT}"
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": FREEFIRE_VERSION,
        "Content-Type": "application/octet-stream",
        "User-Agent": "Dalvik/2.1.0 (Linux; Android 11)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
    encrypted_payload = encrypt_friend_payload(FRIEND_PAYLOAD_HEX)
    try:
        r = requests.post(url, headers=headers, data=encrypted_payload, timeout=timeout, verify=False)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        friends, my_info = _parse_friend_response(r.content)
        if friends is None:
            return None, "Parse error"
        return (friends, my_info), None
    except Exception as e:
        return None, str(e)

def get_friend_list_from_jwt(jwt):
    with ThreadPoolExecutor(max_workers=len(SERVER_BASE_URLS)) as executor:
        future_to_url = {executor.submit(_fetch_friend_from_server, url, jwt): url for url in SERVER_BASE_URLS}
        errors = []
        for future in as_completed(future_to_url):
            result, error = future.result()
            if result is not None:
                for f in future_to_url:
                    f.cancel()
                return result[0], result[1]
            else:
                errors.append(error)
    return None, f"All servers failed: {errors[:3]}"


# ── Friend Manager (Add / Remove) ──
def get_account_uid_from_jwt(jwt_token):
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return str(data.get("account_id") or data.get("sub"))
    except Exception:
        return None

def _build_friend_action_protobuf(author_uid, target_uid):
    rf = RemoveFriend()
    rf.AuthorUid = int(author_uid)
    rf.TargetUid = int(target_uid)
    return rf.SerializeToString()

def send_friend_request(jwt_token, target_uid):
    author_uid = get_account_uid_from_jwt(jwt_token)
    if not author_uid:
        return False, "Could not extract account UID from JWT"
    proto_data = _build_friend_action_protobuf(author_uid, target_uid)
    encrypted = encrypt_proto(proto_data, PROTO_KEY, PROTO_IV)
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/octet-stream",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)"
    }
    endpoints = ["/RequestAddingFriend", "/AddFriend", "/SendFriendRequest"]
    for server in SERVER_BASE_URLS:
        for endpoint in endpoints:
            url = f"{server}{endpoint}"
            try:
                resp = requests.post(url, data=encrypted, headers=headers, timeout=10, verify=False)
                if resp.status_code == 200:
                    return True, f"Friend request sent via {server}{endpoint}"
            except Exception:
                continue
    return False, "All servers/endpoints failed for add friend"

def remove_friend(jwt_token, target_uid):
    author_uid = get_account_uid_from_jwt(jwt_token)
    if not author_uid:
        return False, "Could not extract account UID from JWT"
    proto_data = _build_friend_action_protobuf(author_uid, target_uid)
    encrypted = encrypt_proto(proto_data, PROTO_KEY, PROTO_IV)
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/octet-stream",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)"
    }
    for server in SERVER_BASE_URLS:
        url = f"{server}/RemoveFriend"
        try:
            resp = requests.post(url, data=encrypted, headers=headers, timeout=10, verify=False)
            if resp.status_code == 200:
                return True, f"Friend removed via {server}"
        except Exception:
            continue
    return False, "All servers failed for remove friend"


# ── Profile Item Add ──
def decode_jwt_payload(token):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64).decode())
    except Exception:
        return None

def _build_profile_protobuf(item_ids):
    packet = b''
    packet += encode_varint((1 << 3) | 0) + encode_varint(1)
    container1 = encode_varint((1 << 3) | 0) + encode_varint(1)
    for i, item_id in enumerate(item_ids[:15]):
        item = b''
        if i < 3:
            item += encode_varint((1 << 3) | 0) + encode_varint(2)
            item += encode_varint((4 << 3) | 0) + encode_varint(1)
        else:
            item += encode_varint((1 << 3) | 0) + encode_varint(13)
            item += encode_varint((3 << 3) | 0) + encode_varint(1)
            if i % 2 == 0:
                item += encode_varint((4 << 3) | 0) + encode_varint(2)
            else:
                item += encode_varint((5 << 3) | 0) + encode_varint(2)
        inner = encode_varint((6 << 3) | 0) + encode_varint(item_id)
        item += encode_varint((6 << 3) | 2) + encode_varint(len(inner)) + inner
        container1 += encode_varint((2 << 3) | 2) + encode_varint(len(item)) + item
    packet += encode_varint((2 << 3) | 2) + encode_varint(len(container1)) + container1
    container2 = encode_varint((1 << 3) | 0) + encode_varint(9)
    item7 = encode_varint((4 << 3) | 0) + encode_varint(3)
    inner7 = encode_varint((14 << 3) | 0) + encode_varint(3048205855)
    item7 += encode_varint((6 << 3) | 2) + encode_varint(len(inner7)) + inner7
    container2 += encode_varint((2 << 3) | 2) + encode_varint(len(item7)) + item7
    item8 = encode_varint((4 << 3) | 0) + encode_varint(3)
    item8 += encode_varint((5 << 3) | 0) + encode_varint(3)
    inner8 = encode_varint((14 << 3) | 0) + encode_varint(3048205855)
    item8 += encode_varint((6 << 3) | 2) + encode_varint(len(inner8)) + inner8
    container2 += encode_varint((2 << 3) | 2) + encode_varint(len(item8)) + item8
    packet += encode_varint((2 << 3) | 2) + encode_varint(len(container2)) + container2
    return packet

def add_profile_items(jwt_token, item_ids_str):
    try:
        payload = decode_jwt_payload(jwt_token)
        lock_region = payload.get("lock_region", "BD").upper() if payload else "BD"
    except Exception:
        lock_region = "BD"
    if lock_region == "IND":
        url = "https://client.ind.freefiremobile.com/SetPlayerGalleryShowInfo"
    elif lock_region in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/SetPlayerGalleryShowInfo"
    else:
        url = "https://clientbp.common.ggbluefox.com/SetPlayerGalleryShowInfo"
    item_ids = [int(x) for x in item_ids_str.split("/") if x.strip().isdigit()][:15]
    if not item_ids:
        return False, "No valid item IDs"
    proto_data = _build_profile_protobuf(item_ids)
    encrypted = encrypt_proto(proto_data, PROFILE_AES_KEY, PROFILE_AES_IV)
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/octet-stream",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)"
    }
    try:
        resp = requests.post(url, headers=headers, data=encrypted, timeout=10, verify=False)
        if resp.status_code == 200:
            return True, f"Success (HTTP {resp.status_code})"
        return False, f"HTTP {resp.status_code} - {resp.text[:200]}"
    except Exception as e:
        return False, str(e)


# ── Wishlist Add ──
def _build_wishlist_request(item_id):
    packet = encode_varint((1 << 3) | 0) + encode_varint(item_id)
    packet += encode_varint((2 << 3) | 2) + encode_varint(0) + b''
    name_bytes = "MallV2".encode()
    packet += encode_varint((3 << 3) | 2) + encode_varint(len(name_bytes)) + name_bytes
    return packet

def _add_wishlist_item(jwt_token, item_id, server_urls):
    for url in server_urls:
        try:
            proto = _build_wishlist_request(item_id)
            encrypted = encrypt_proto(proto, WISHLIST_KEY, WISHLIST_IV)
            headers = {
                "User-Agent": "UnityPlayer/2022.3.47f1",
                "Authorization": f"Bearer {jwt_token}",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB53",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Unity-Version": "2022.3.47f1"
            }
            resp = requests.post(f"{url}/ChangeWishListItem", data=encrypted, headers=headers, timeout=5, verify=False)
            if resp.status_code == 200:
                return True, item_id, 200
        except Exception:
            continue
    return False, item_id, "All servers failed"

def add_wishlist_batch(jwt_token, items, max_workers=50):
    servers = [
        "https://client.ind.freefiremobile.com",
        "https://clientbp.ggpolarbear.com",
        "https://clientbp.ggpolarbear.com",
        "https://clientbp.ggpolarbear.com",
        "https://client.us.freefiremobile.com",
    ]
    results = {"success": [], "failed": []}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_add_wishlist_item, jwt_token, item, servers): item for item in items}
        for future in as_completed(futures):
            success, item_id, status = future.result()
            if success:
                results["success"].append(item_id)
            else:
                results["failed"].append({"item": item_id, "status": status})
    return results


# ── Craftland Subscribe ──
def subscribe_craftland(jwt_token, map_code, region):
    try:
        base_url = CRAFTLAND_REGION_URLS.get(region.upper())
        if not base_url:
            return False, f"Unsupported region: {region}"
        lang = CRAFTLAND_REGION_LANG.get(region.upper(), "en")
        map_bytes = map_code.encode()
        lang_bytes = lang.encode()
        proto = b'\x08\x01\x12' + encode_varint(len(map_bytes)) + map_bytes + b'\x22' + encode_varint(len(lang_bytes)) + lang_bytes
        encrypted = encrypt_proto(proto, PROTO_KEY, PROTO_IV)
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)"
        }
        url = f"{base_url}/SubscribeWorkshopCode"
        resp = requests.post(url, data=encrypted, headers=headers, timeout=15, verify=False)
        if resp.status_code == 200:
            return True, "Subscribed successfully"
        return False, f"HTTP {resp.status_code} - {resp.text[:200]}"
    except Exception as e:
        return False, str(e)


# ── Craftland Info ──
def get_craftland_info(map_code, region="BD", lang="en"):
    try:
        if map_code.startswith("#"):
            map_code = map_code[1:]
        encoded = f"%23{map_code}"
        device_id = "4e93e5106b39e1902e24d1ba2f17c709"
        url = f"https://mapshare.freefiremobile.com/api/info?lang={lang.lower()}&region={region.upper()}&map_code={encoded}&device_id={device_id}"
        resp = requests.get(url, timeout=15, verify=False)
        if resp.status_code != 200:
            return None, f"API error: HTTP {resp.status_code}"
        data = resp.json()
        if data.get("code") != 0:
            return None, data.get("msg", "Unknown error")
        info = data["data"]["workshop_code_info"]
        return {
            "workshop_code": info["workshop_code"],
            "map_name": info["workshop_name"],
            "author": info["author_name"],
            "description": info["workshop_desc"],
            "team_count": info["team_count"],
            "subscribe_count": info["subscribe_count"],
            "like_count": info["like_count"],
            "estimated_play_time": f"{info['min_est_play_time']} - {info['max_est_play_time']} seconds",
            "tags": info.get("tags", [])
        }, None
    except Exception as e:
        return None, str(e)


# ── Player Info ──
def _build_player_info_request(target_uid):
    req = b''
    req += encode_varint((1 << 3) | 0) + encode_varint(int(target_uid))
    req += encode_varint((2 << 3) | 0) + encode_varint(7)
    return req

def _parse_player_info_response(data):
    result = {}
    pos = 0
    data_len = len(data)

    def read_submessage(length):
        nonlocal pos
        end = pos + length
        sub_result = {}
        while pos < end:
            if pos >= data_len:
                break
            tag_byte = data[pos]
            pos += 1
            field_num = tag_byte >> 3
            wire_type = tag_byte & 0x07
            if wire_type == 0:
                val, pos = decode_varint(data, pos)
                sub_result[field_num] = val
            elif wire_type == 2:
                l, pos = decode_varint(data, pos)
                if pos + l > data_len:
                    break
                val = data[pos:pos + l]
                pos += l
                try:
                    val = val.decode("utf-8", errors="ignore")
                except Exception:
                    pass
                sub_result[field_num] = val
        return sub_result

    while pos < data_len:
        tag_byte = data[pos]
        pos += 1
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07
        if wire_type == 2:
            length, pos = decode_varint(data, pos)
            if pos + length > data_len:
                break
            if field_num == 1:
                sub = read_submessage(length)
                result["nickname"] = sub.get(3, "Unknown")
                result["level"] = sub.get(6, 0)
                result["rank"] = sub.get(14, 0)
                result["clan_name"] = sub.get(13, "")
                result["external_id"] = sub.get(4, "")
                result["head_pic"] = sub.get(12, 0)
                result["account_uid"] = sub.get(1, 0)
            else:
                pos += length
        else:
            if wire_type == 0:
                _, pos = decode_varint(data, pos)
            else:
                break
    return result

def get_player_info(jwt_token, target_uid, region=None):
    if not region:
        payload = decode_jwt_payload(jwt_token)
        region = payload.get("lock_region", "BD").upper() if payload else "BD"
    regions_to_try = [region] + [r for r in PLAYER_INFO_SERVERS.keys() if r != region]
    for reg in regions_to_try:
        server = PLAYER_INFO_SERVERS.get(reg)
        if not server:
            continue
        try:
            req_pb = _build_player_info_request(target_uid)
            encrypted = encrypt_proto(req_pb, PROTO_KEY, PROTO_IV)
            headers = {
                "Authorization": f"Bearer {jwt_token}",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB53",
                "Content-Type": "application/octet-stream",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)"
            }
            url = f"{server}/GetPlayerPersonalShow"
            resp = requests.post(url, data=encrypted, headers=headers, timeout=10, verify=False)
            if resp.status_code != 200:
                continue
            decrypted = decrypt_proto(resp.content, PROTO_KEY, PROTO_IV)
            if not decrypted or len(decrypted) < 2:
                continue
            info = _parse_player_info_response(decrypted)
            if info and info.get("nickname") != "Unknown":
                info["region"] = reg
                return info, reg
        except Exception:
            continue
    return None, "UID not found in any region"


# ── Bio Changer ──
def change_bio(jwt_token, new_bio, region=None):
    if not region:
        payload = decode_jwt_payload(jwt_token)
        region = payload.get("lock_region", "BD").upper() if payload else "BD"
    server = PLAYER_INFO_SERVERS.get(region)
    if not server:
        return False, f"Unsupported region: {region}"
    try:
        bio_msg = BioData()
        bio_msg.field_2 = 17
        bio_msg.field_5.CopyFrom(EmptyMessage())
        bio_msg.field_6.CopyFrom(EmptyMessage())
        bio_msg.field_8 = new_bio
        bio_msg.field_9 = 1
        bio_msg.field_11.CopyFrom(EmptyMessage())
        bio_msg.field_12.CopyFrom(EmptyMessage())
        data_bytes = bio_msg.SerializeToString()
        encrypted = encrypt_proto(data_bytes, PROTO_KEY, PROTO_IV)
        headers = {
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Authorization": f"Bearer {jwt_token}"
        }
        url = f"{server}/UpdateSocialBasicInfo"
        resp = requests.post(url, headers=headers, data=encrypted, timeout=15, verify=False)
        if resp.status_code == 200:
            return True, "Bio updated successfully"
        return False, f"HTTP {resp.status_code} - {resp.text[:200]}"
    except Exception as e:
        return False, str(e)


# ── Guild Manager ──
def join_guild(jwt_token, clan_id, region):
    server = PLAYER_INFO_SERVERS.get(region)
    if not server:
        return False, f"Unsupported region: {region}"
    try:
        msg = ReqCLan()
        msg.field_1 = int(clan_id)
        encrypted = encrypt_proto(msg.SerializeToString(), PROTO_KEY, PROTO_IV)
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)"
        }
        url = f"{server}/RequestJoinClan"
        resp = requests.post(url, data=encrypted, headers=headers, timeout=10, verify=False)
        if resp.status_code == 200:
            return True, "Join request sent successfully"
        return False, f"HTTP {resp.status_code} - {resp.text[:200]}"
    except Exception as e:
        return False, str(e)

def leave_guild(jwt_token, clan_id, region):
    server = PLAYER_INFO_SERVERS.get(region)
    if not server:
        return False, f"Unsupported region: {region}"
    try:
        msg = QuitClanReq()
        msg.field_1 = int(clan_id)
        encrypted = encrypt_proto(msg.SerializeToString(), PROTO_KEY, PROTO_IV)
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)"
        }
        url = f"{server}/QuitClan"
        resp = requests.post(url, data=encrypted, headers=headers, timeout=10, verify=False)
        if resp.status_code == 200:
            return True, "Left guild successfully"
        return False, f"HTTP {resp.status_code} - {resp.text[:200]}"
    except Exception as e:
        return False, str(e)

def get_clan_info_sync(jwt_token, clan_id, region):
    server = PLAYER_INFO_SERVERS.get(region)
    if not server:
        return None, f"Unsupported region: {region}"
    try:
        req = encode_varint((1 << 3) | 0) + encode_varint(int(clan_id)) + encode_varint((2 << 3) | 0) + encode_varint(1)
        encrypted = encrypt_proto(req, PROTO_KEY, PROTO_IV)
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)"
        }
        url = f"{server}/GetClanInfoByClanID"
        resp = requests.post(url, data=encrypted, headers=headers, timeout=10, verify=False)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"
        data = resp.content
        if data[:2] == b'\x1f\x8b':
            data = gzip.decompress(data)
        result = {}
        pos = 0
        while pos < len(data):
            tag, pos = decode_varint(data, pos)
            field_num = tag >> 3
            wire_type = tag & 0x07
            if wire_type == 0:
                val, pos = decode_varint(data, pos)
                result[field_num] = val
            elif wire_type == 2:
                length, pos = decode_varint(data, pos)
                val = data[pos:pos + length]
                pos += length
                try:
                    val = val.decode("utf-8", errors="ignore")
                except Exception:
                    pass
                result[field_num] = val
        return result, None
    except Exception as e:
        return None, str(e)

def get_clan_members_sync(jwt_token, clan_id, region):
    server = PLAYER_INFO_SERVERS.get(region)
    if not server:
        return None, f"Unsupported region: {region}"
    try:
        req = encode_varint((1 << 3) | 0) + encode_varint(int(clan_id))
        encrypted = encrypt_proto(req, PROTO_KEY, PROTO_IV)
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)"
        }
        url = f"{server}/GetClanMembers"
        resp = requests.post(url, data=encrypted, headers=headers, timeout=15, verify=False)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"
        data = resp.content
        if data[:2] == b'\x1f\x8b':
            data = gzip.decompress(data)
        pb = GetClanMembersResponse()
        pb.ParseFromString(data)
        members = []
        for entry in pb.entries:
            members.append({
                "uid": str(entry.info.uid),
                "name": entry.info.name,
                "role": entry.role,
                "total_glory": entry.total_glory,
                "weekly_glory": entry.weekly_glory
            })
        return members, None
    except Exception as e:
        return None, str(e)



# ══════════════════════════════════════════════════════════════════════════════
#  HTML TEMPLATES — WITH MOBILE HAMBURGER MENU
# ══════════════════════════════════════════════════════════════════════════════

BASE_CSS = """
:root{
  --bg:#0a0a0f;--bg2:#12121a;--bg3:#1a1a28;
  --accent:#7c3aed;--accent2:#a855f7;--accent3:#06b6d4;
  --green:#22c55e;--red:#ef4444;--yellow:#eab308;
  --text:#e2e8f0;--muted:#64748b;--border:#2d2d45;
  --card:#161625;--radius:12px;
  --font:'JetBrains Mono',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh;overflow-x:hidden}
a{color:var(--accent2);text-decoration:none}
input,textarea,select{
  background:var(--bg3);color:var(--text);border:1px solid var(--border);
  border-radius:8px;padding:10px 14px;width:100%;font-family:var(--font);font-size:14px;outline:none;
  transition:border .2s;
}
input:focus,textarea:focus{border-color:var(--accent2)}
button,.btn{
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  color:#fff;border:none;border-radius:8px;padding:10px 22px;
  font-family:var(--font);font-size:14px;font-weight:700;cursor:pointer;
  transition:opacity .2s,transform .1s;letter-spacing:.5px;
}
button:hover,.btn:hover{opacity:.85;transform:translateY(-1px)}
button:active{transform:translateY(0)}
.btn-red{background:linear-gradient(135deg,#b91c1c,var(--red))}
.btn-green{background:linear-gradient(135deg,#15803d,var(--green))}
.btn-yellow{background:linear-gradient(135deg,#92400e,var(--yellow));color:#000}
.btn-cyan{background:linear-gradient(135deg,#0e7490,var(--accent3))}
.btn-sm{padding:6px 14px;font-size:12px;border-radius:6px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:24px}
.tag{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:700}
.tag-green{background:#14532d;color:var(--green)}
.tag-red{background:#7f1d1d;color:var(--red)}
.tag-yellow{background:#713f12;color:var(--yellow)}
.tag-muted{background:var(--bg3);color:var(--muted)}
.flash{padding:10px 16px;border-radius:8px;margin-bottom:16px;font-size:13px}
.flash-err{background:#7f1d1d;border:1px solid var(--red);color:#fca5a5}
.flash-ok{background:#14532d;border:1px solid var(--green);color:#86efac}
.flash-warn{background:#713f12;border:1px solid var(--yellow);color:#fde68a}
@keyframes glow{0%,100%{text-shadow:0 0 10px var(--accent2)}50%{text-shadow:0 0 30px var(--accent2),0 0 60px var(--accent)}}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.fade-in{animation:fadeIn .35s ease forwards}
.logo-text{
  font-size:26px;font-weight:900;letter-spacing:2px;
  background:linear-gradient(135deg,var(--accent2),var(--accent3));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  animation:glow 3s ease-in-out infinite;
}

/* ===== Mobile Hamburger Menu ===== */
.hamburger{
  display:none;flex-direction:column;justify-content:center;align-items:center;
  width:40px;height:40px;cursor:pointer;gap:5px;padding:8px;
  border-radius:8px;transition:background .2s;z-index:200;
}
.hamburger:hover{background:var(--bg3)}
.hamburger span{
  display:block;width:22px;height:2px;background:var(--text);
  border-radius:2px;transition:all .3s ease;
}
.hamburger.active span:nth-child(1){transform:rotate(45deg) translate(5px,5px)}
.hamburger.active span:nth-child(2){opacity:0}
.hamburger.active span:nth-child(3){transform:rotate(-45deg) translate(5px,-5px)}
.sidebar-overlay{
  display:none;position:fixed;top:0;left:0;right:0;bottom:0;
  background:rgba(0,0,0,.6);z-index:90;
}
.sidebar-overlay.show{display:none}

/* ===== Layout ===== */
.topbar{
  display:flex;align-items:center;justify-content:space-between;
  padding:0 16px 0 24px;height:56px;background:var(--bg2);
  border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;
}
.topbar .logo-text{font-size:18px}
.topbar-right{display:flex;align-items:center;gap:12px}
.user-pill{
  display:flex;align-items:center;gap:8px;padding:6px 14px;
  background:var(--bg3);border-radius:20px;font-size:13px;
}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.status-dot.running{background:var(--green);box-shadow:0 0 6px var(--green)}
.layout{display:flex;min-height:calc(100vh - 56px)}
.sidebar{
  width:220px;flex-shrink:0;background:var(--bg2);
  border-right:1px solid var(--border);padding:20px 0;
  display:flex;flex-direction:column;transition:transform .3s ease;
}
.sidebar-section{padding:0 12px;margin-bottom:8px}
.sidebar-label{
  font-size:10px;color:var(--muted);letter-spacing:2px;
  padding:0 8px;margin-bottom:4px;margin-top:12px;
}
.menu-item{
  display:flex;align-items:center;gap:10px;padding:10px 12px;
  border-radius:8px;font-size:13px;color:var(--muted);
  cursor:pointer;transition:all .15s;margin-bottom:2px;border:none;
  background:none;width:100%;text-align:left;font-family:var(--font);
}
.menu-item:hover{background:var(--bg3);color:var(--text)}
.menu-item.active{background:var(--bg3);color:var(--accent2);border-left:2px solid var(--accent2)}
.menu-item .ico{font-size:16px;width:20px;text-align:center}
.menu-bar{
  padding:4px 12px;margin-bottom:2px;
  font-size:11px;color:var(--muted);letter-spacing:1px;
  display:flex;align-items:center;gap:6px;
}
.menu-bar span{flex:1;height:1px;background:var(--border)}
.main{flex:1;padding:28px;overflow-y:auto}
.section-page{display:none}
.section-page.active{display:block;animation:fadeIn .25s ease}
.section-title{
  font-size:22px;font-weight:900;margin-bottom:6px;
  background:linear-gradient(135deg,var(--accent2),var(--accent3));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.section-sub{color:var(--muted);font-size:13px;margin-bottom:24px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}

/* Terminal */
.terminal-wrap{
  background:#050508;border:1px solid var(--border);border-radius:12px;
  overflow:hidden;font-size:13px;
}
.terminal-bar{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 16px;background:var(--bg3);border-bottom:1px solid var(--border);
  flex-wrap:wrap;gap:8px;
}
.terminal-dots{display:flex;gap:6px}
.terminal-dots span{width:12px;height:12px;border-radius:50%}
.t-red{background:#ef4444}.t-yellow{background:#eab308}.t-green{background:#22c55e}
#terminal{
  padding:16px;min-height:340px;max-height:480px;
  overflow-y:auto;line-height:1.6;color:#a3e635;
  font-family:var(--font);white-space:pre-wrap;word-break:break-all;
}
.t-dim{color:var(--muted)}
.t-info{color:var(--accent3)}
.t-err{color:var(--red)}
.ctrl-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}

/* Creds form */
.cred-card{max-width:540px}
.infobox{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:12px 16px;font-size:12px;color:var(--muted);margin-bottom:16px;
  line-height:1.7;
}
.infobox strong{color:var(--accent2)}

/* ===== Responsive Mobile ===== */
@media (max-width: 768px) {
  .hamburger{display:flex !important}
  .sidebar{
    position:fixed;top:56px;left:0;bottom:0;width:260px;z-index:95;
    transform:translateX(-100%);border-right:none;
    box-shadow:2px 0 20px rgba(0,0,0,.5);
  }
  .sidebar.show{transform:translateX(0)}
  .sidebar-overlay.show{display:block !important}
  .main{padding:16px;width:100vw;max-width:100vw}
  .grid2{grid-template-columns:1fr}
  .grid3{grid-template-columns:1fr}
  .topbar{padding:0 12px}
  .user-pill{display:none}
  #terminal{min-height:260px;max-height:380px}
  .section-title{font-size:18px}
}
@media (min-width: 769px) {
  .hamburger{display:none !important}
  .sidebar{transform:none !important;position:relative;top:auto}
  .sidebar-overlay{display:none !important}
}

/* Broadcast */
.broadcast-msg{
  background:linear-gradient(135deg,var(--accent) 0%,var(--accent3) 100%);
  border-radius:10px;padding:14px 18px;margin-bottom:12px;font-size:14px;
  display:none;
}
.broadcast-msg.show{display:block;animation:fadeIn .3s ease}

/* Admin */
.admin-table{width:100%;border-collapse:collapse;font-size:13px}
.admin-table th{text-align:left;padding:10px 14px;background:var(--bg3);color:var(--muted);font-size:11px;letter-spacing:1px}
.admin-table td{padding:10px 14px;border-bottom:1px solid var(--border)}
.admin-table tr:hover td{background:var(--bg3)}
.admin-actions{display:flex;gap:6px;flex-wrap:wrap}
.tabs{display:flex;gap:4px;margin-bottom:24px;border-bottom:1px solid var(--border);padding-bottom:0;overflow-x:auto}
.tab{
  padding:10px 18px;font-size:13px;font-family:var(--font);cursor:pointer;
  border-radius:8px 8px 0 0;color:var(--muted);background:none;border:none;
  border-bottom:2px solid transparent;transition:all .15s;font-weight:700;white-space:nowrap;
}
.tab.active,.tab:hover{color:var(--accent2);border-bottom-color:var(--accent2)}
.tab-page{display:none}
.tab-page.active{display:block;animation:fadeIn .2s ease}
.maint-banner{
  background:linear-gradient(135deg,#7f1d1d,#b91c1c);
  border-radius:10px;padding:16px 20px;margin-bottom:20px;display:none;
}
.maint-banner.show{display:block}
@media (max-width:768px){
  .admin-actions{flex-direction:column}
  .admin-actions .btn{width:100%;margin-bottom:4px}
  .tabs{gap:2px}
  .tab{padding:8px 12px;font-size:12px}
}
"""

AUTH_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Vhaw_X_limon — {{title}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;900&display=swap" rel="stylesheet">
<style>
""" + BASE_CSS + """
body{display:flex;align-items:center;justify-content:center;padding:20px}
.auth-wrap{width:100%;max-width:420px;animation:fadeIn .4s ease}
.auth-logo{text-align:center;margin-bottom:32px}
.auth-logo .logo-text{font-size:30px}
.auth-logo .sub{color:var(--muted);font-size:12px;margin-top:4px;letter-spacing:3px}
.auth-card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:32px}
.auth-card h2{font-size:18px;font-weight:700;margin-bottom:24px;color:var(--text)}
.field{margin-bottom:16px}
.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px;letter-spacing:.5px}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.auth-foot{text-align:center;margin-top:16px;font-size:13px;color:var(--muted)}
.divider{border:none;border-top:1px solid var(--border);margin:20px 0}
@media (max-width:480px){
  .auth-card{padding:20px}
  .auth-logo .logo-text{font-size:24px}
}
</style>
</head>
<body>
<div class="auth-wrap">
  <div class="auth-logo">
    <div class="logo-text">Vhaw_X_limon</div>
    <div class="sub">TCP PANEL</div>
  </div>
  {{body}}
</div>
</body>
</html>
"""

PANEL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Vhaw_X_limon Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;900&display=swap" rel="stylesheet">
<style>
""" + BASE_CSS + """
</style>
</head>
<body>
<div class="topbar">
  <div style="display:flex;align-items:center;gap:12px">
    <div class="hamburger" id="hamburger" onclick="toggleSidebar()">
      <span></span><span></span><span></span>
    </div>
    <div class="logo-text">Vhaw_X_limon</div>
  </div>
  <div class="topbar-right">
    <div id="proc-dot" class="status-dot"></div>
    <div class="user-pill">&#9656; <span id="top-user">{{username}}</span></div>
    <button class="btn btn-sm btn-red" onclick="doLogout()">Logout</button>
  </div>
</div>
<div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>
<div class="layout">
  <nav class="sidebar" id="sidebar">
    <div class="menu-bar"><span></span>MENU<span></span></div>
    <div class="sidebar-section">
      <div class="menu-item active" onclick="showPage('page-terminal',this)" id="mi-terminal">
        <span class="ico">&#9889;</span> Terminal
      </div>
      <div class="menu-item" onclick="showPage('page-creds',this)" id="mi-creds">
        <span class="ico">&#128273;</span> Credentials
      </div>
      <div class="menu-item" onclick="showPage('page-files',this)" id="mi-files">
        <span class="ico">&#128194;</span> Files
      </div>
    </div>
    <div class="menu-bar"><span></span>TOOLS<span></span></div>
    <div class="sidebar-section">
      <div class="menu-item" onclick="showPage('page-nickname',this)" id="mi-nickname">
        <span class="ico">&#128394;</span> Nickname
      </div>
      <div class="menu-item" onclick="showPage('page-loginhist',this)" id="mi-loginhist">
        <span class="ico">&#128220;</span> Login History
      </div>
      <div class="menu-item" onclick="showPage('page-friends',this)" id="mi-friends">
        <span class="ico">&#128101;</span> Friends
      </div>
      <div class="menu-item" onclick="showPage('page-profile',this)" id="mi-profile">
        <span class="ico">&#128248;</span> Profile Items
      </div>
      <div class="menu-item" onclick="showPage('page-wishlist',this)" id="mi-wishlist">
        <span class="ico">&#11088;</span> Wishlist
      </div>
      <div class="menu-item" onclick="showPage('page-craftland',this)" id="mi-craftland">
        <span class="ico">&#127957;</span> Craftland
      </div>
      <div class="menu-item" onclick="showPage('page-playerinfo',this)" id="mi-playerinfo">
        <span class="ico">&#128100;</span> Player Info
      </div>
      <div class="menu-item" onclick="showPage('page-bio',this)" id="mi-bio">
        <span class="ico">&#128221;</span> Change Bio
      </div>
      <div class="menu-item" onclick="showPage('page-friendmgr',this)" id="mi-friendmgr">
        <span class="ico">&#129333;</span> Friend Manager
      </div>
      <div class="menu-item" onclick="showPage('page-guild',this)" id="mi-guild">
        <span class="ico">&#127942;</span> Guild Manager
      </div>
    </div>
    <div class="menu-bar"><span></span>OPTIONS<span></span></div>
    <div class="sidebar-section">
      <div class="menu-item" onclick="showPage('page-status',this)" id="mi-status">
        <span class="ico">&#128202;</span> Status
      </div>
      <div class="menu-item" onclick="showPage('page-help',this)" id="mi-help">
        <span class="ico">&#10067;</span> Help
      </div>
      <div class="menu-item" onclick="window.open('/admin','_blank')">
        <span class="ico">&#128737;</span> Admin
      </div>
    </div>
  </nav>
  <div class="main">
    <div id="broadcast-area"></div>

    <!-- PAGE: Terminal -->
    <div class="section-page active" id="page-terminal">
      <div class="section-title">&#9889; Vhaw_X_limon Terminal</div>
      <div class="section-sub">Control and monitor your TCP process in real-time.</div>
      <div id="creds-warn" style="display:none" class="flash flash-warn">
        &#9888; Credentials not set. Please go to <b>Credentials</b> menu first.
      </div>
      <div class="terminal-wrap">
        <div class="terminal-bar">
          <div class="terminal-dots">
            <span class="t-red"></span><span class="t-yellow"></span><span class="t-green"></span>
          </div>
          <span style="font-size:12px;color:var(--muted)">Vhaw_X_limon &mdash; {{username}}</span>
          <div style="display:flex;gap:8px;align-items:center">
            <label style="font-size:11px;color:var(--muted);display:flex;align-items:center;gap:5px;cursor:pointer">
              <input type="checkbox" id="auto-scroll-chk" style="width:auto"> Auto-scroll
            </label>
            <button class="btn btn-sm btn-cyan" onclick="clearTerminal()">Clear</button>
          </div>
        </div>
        <div id="terminal"><span class="t-dim">&mdash; Vhaw_X_limon ready. Use controls below to start. &mdash;</span></div>
      </div>
      <div class="ctrl-row">
        <button class="btn btn-green" onclick="procAction('start')">&#9654; Start</button>
        <button class="btn" onclick="procAction('stop')">&#9632; Stop</button>
        <button class="btn btn-cyan" onclick="procAction('restart')">&#8634; Restart</button>
        <button class="btn btn-red" onclick="procAction('force_stop')">&#10005; Force Stop</button>
      </div>
    </div>

    <!-- PAGE: Credentials -->
    <div class="section-page" id="page-creds">
      <div class="section-title">&#128273; Credentials</div>
      <div class="section-sub">Set your UID and password. Files will be copied and Vhaw.txt updated.</div>
      <div class="card cred-card">
        <div class="infobox">
          Files from <strong>TCP/</strong> will be copied to <strong>DATA/{{username}}/</strong> and
          <strong>Vhaw.txt</strong> will be written with your credentials after saving.
        </div>
        <div id="cred-flash"></div>
        <div class="field">
          <label>UID</label>
          <input id="cred-uid" type="text" placeholder="Enter your UID">
        </div>
        <div class="field">
          <label>PASSWORD</label>
          <input id="cred-pass" type="password" placeholder="Enter credential password">
        </div>
        <div class="field">
          <label>OWNER UID</label>
          <input id="cred-owner-uid" type="text" placeholder="Enter Owner UID (optional)">
        </div>
        <div class="field">
          <label>OWNER NAME </label>
          <input id="cred-owner-name" type="text" placeholder="Enter Owner Name (optional)">
        </div>
        <button class="btn" onclick="saveCreds()">&#128190; Save &amp; Copy Files</button>
      </div>
    </div>

    <!-- PAGE: Files -->
    <div class="section-page" id="page-files">
      <div class="section-title">&#128194; Files</div>
      <div class="section-sub">Files currently in your data folder.</div>
      <div class="card">
        <button class="btn btn-sm btn-cyan" onclick="loadFiles()" style="margin-bottom:16px">&#8635; Refresh</button>
        <div id="file-list"><span class="t-dim">Loading...</span></div>
      </div>
    </div>

    <!-- PAGE: Nickname -->
    <div class="section-page" id="page-nickname">
      <div class="section-title">&#128394; Change Nickname</div>
      <div class="section-sub">Change your in-game nickname.</div>
      <div class="card cred-card">
        <div id="nick-flash"></div>
        <div class="field">
          <label>NEW NICKNAME</label>
          <input id="nick-input" type="text" placeholder="Enter new nickname">
        </div>
        <button class="btn" onclick="doNickname()">&#128190; Change Nickname</button>
        <div id="nick-result" style="margin-top:16px"></div>
      </div>
    </div>

    <!-- PAGE: Login History -->
    <div class="section-page" id="page-loginhist">
      <div class="section-title">&#128220; Login History</div>
      <div class="section-sub">View your recent login history.</div>
      <div class="card">
        <button class="btn btn-sm btn-cyan" onclick="doLoginHistory()" style="margin-bottom:16px">&#8635; Fetch</button>
        <div id="loginhist-result"><span class="t-dim">Click Fetch to load.</span></div>
      </div>
    </div>

    <!-- PAGE: Friends -->
    <div class="section-page" id="page-friends">
      <div class="section-title">&#128101; Friend List</div>
      <div class="section-sub">View your in-game friends.</div>
      <div class="card">
        <button class="btn btn-sm btn-cyan" onclick="doFriendList()" style="margin-bottom:16px">&#8635; Fetch</button>
        <div id="friends-result"><span class="t-dim">Click Fetch to load.</span></div>
      </div>
    </div>

    <!-- PAGE: Profile Items -->
    <div class="section-page" id="page-profile">
      <div class="section-title">&#128248; Profile Items</div>
      <div class="section-sub">Add items to your profile gallery.</div>
      <div class="card cred-card">
        <div id="profile-flash"></div>
        <div class="field">
          <label>ITEM IDs (slash separated, e.g. 203000000/204000000)</label>
          <input id="profile-items" type="text" value="" placeholder="Enter item IDs">
        </div>
        <button class="btn" onclick="doProfileItems()">&#11014; Add Profile Items</button>
        <div id="profile-result" style="margin-top:16px"></div>
      </div>
    </div>

    <!-- PAGE: Wishlist -->
    <div class="section-page" id="page-wishlist">
      <div class="section-title">&#11088; Wishlist</div>
      <div class="section-sub">Add all wishlist items in parallel.</div>
      <div class="card">
        <button class="btn" onclick="doWishlist()">&#11014; Add All Wishlist Items</button>
        <div id="wishlist-result" style="margin-top:16px"><span class="t-dim">Click button to add 55+ items.</span></div>
      </div>
    </div>

    <!-- PAGE: Craftland -->
    <div class="section-page" id="page-craftland">
      <div class="section-title">&#127957; Craftland</div>
      <div class="section-sub">Subscribe to map or get map info.</div>
      <div class="card cred-card">
        <div id="craft-flash"></div>
        <div class="field">
          <label>MAP CODE</label>
          <input id="craft-code" type="text" placeholder="Enter map code">
        </div>
        <div class="field">
          <label>REGION</label>
          <input id="craft-region" type="text" value="BD" placeholder="BD, IND, BR, etc">
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn" onclick="doCraftSubscribe()">&#128204; Subscribe</button>
          <button class="btn btn-cyan" onclick="doCraftInfo()">&#8505; Get Info</button>
        </div>
        <div id="craft-result" style="margin-top:16px"></div>
      </div>
    </div>

    <!-- PAGE: Player Info -->
    <div class="section-page" id="page-playerinfo">
      <div class="section-title">&#128100; Player Info</div>
      <div class="section-sub">Look up player info by UID.</div>
      <div class="card cred-card">
        <div id="pinfo-flash"></div>
        <div class="field">
          <label>TARGET UID</label>
          <input id="pinfo-uid" type="text" placeholder="Enter UID to lookup">
        </div>
        <button class="btn" onclick="doPlayerInfo()">&#128269; Lookup</button>
        <div id="pinfo-result" style="margin-top:16px"></div>
      </div>
    </div>

    <!-- PAGE: Change Bio -->
    <div class="section-page" id="page-bio">
      <div class="section-title">&#128221; Change Bio</div>
      <div class="section-sub">Update your social bio text.</div>
      <div class="card cred-card">
        <div id="bio-flash"></div>
        <div class="field">
          <label>NEW BIO TEXT</label>
          <input id="bio-input" type="text" placeholder="Enter new bio">
        </div>
        <button class="btn" onclick="doChangeBio()">&#128190; Update Bio</button>
        <div id="bio-result" style="margin-top:16px"></div>
      </div>
    </div>

    <!-- PAGE: Friend Manager -->
    <div class="section-page" id="page-friendmgr">
      <div class="section-title">&#129333; Friend Manager</div>
      <div class="section-sub">Add or remove friends by UID.</div>
      <div class="card cred-card">
        <div id="fmgr-flash"></div>
        <div class="field">
          <label>TARGET UID</label>
          <input id="fmgr-uid" type="text" placeholder="Enter UID">
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn btn-green" onclick="doFriendAdd()">&#10133; Add Friend</button>
          <button class="btn btn-red" onclick="doFriendRemove()">&#10134; Remove Friend</button>
        </div>
        <div id="fmgr-result" style="margin-top:16px"></div>
      </div>
    </div>

    <!-- PAGE: Guild Manager -->
    <div class="section-page" id="page-guild">
      <div class="section-title">&#127942; Guild Manager</div>
      <div class="section-sub">Join, leave, or get guild info.</div>
      <div class="card cred-card">
        <div id="guild-flash"></div>
        <div class="field">
          <label>CLAN ID</label>
          <input id="guild-id" type="text" placeholder="Enter clan ID">
        </div>
        <div class="field">
          <label>REGION</label>
          <input id="guild-region" type="text" value="BD" placeholder="BD, IND, BR, etc">
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
          <button class="btn btn-green" onclick="doGuildJoin()">&#128204; Join</button>
          <button class="btn btn-red" onclick="doGuildLeave()">&#128682; Leave</button>
          <button class="btn btn-cyan" onclick="doGuildInfo()">&#8505; Info</button>
          <button class="btn" onclick="doGuildMembers()">&#128101; Members</button>
        </div>
        <div id="guild-result"></div>
      </div>
    </div>

    <!-- PAGE: Status -->
    <div class="section-page" id="page-status">
      <div class="section-title">&#128202; Status</div>
      <div class="section-sub">Live session and process information.</div>
      <div class="grid2">
        <div class="card">
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px">PROCESS</div>
          <div id="status-proc" style="font-size:24px;font-weight:900">&mdash;</div>
        </div>
        <div class="card">
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px">CREDENTIALS</div>
          <div id="status-creds" style="font-size:24px;font-weight:900">&mdash;</div>
        </div>
        <div class="card">
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px">JWT TOKEN</div>
          <div id="status-jwt" style="font-size:18px;font-weight:900">&mdash;</div>
        </div>
        <div class="card">
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px">AUTO REFRESH</div>
          <div style="font-size:14px;color:var(--muted)">Every 6 hours</div>
        </div>
      </div>
    </div>

    <!-- PAGE: Help -->
    <div class="section-page" id="page-help">
      <div class="section-title">&#10067; Help</div>
      <div class="section-sub">How to use Vhaw_X_limon Panel</div>
      <div class="card">
        <div style="line-height:2;font-size:14px;color:var(--muted)">
          <b style="color:var(--accent2)">1. Set Credentials</b><br>
          Go to <b>Credentials</b> menu. Enter your UID and password. Click Save.<br><br>
          <b style="color:var(--accent2)">2. Start Process</b><br>
          Go back to <b>Terminal</b> and click <b>Start</b>.<br><br>
          <b style="color:var(--accent2)">3. Use Tools</b><br>
          All 13 tools use your saved credentials and auto-generated JWT token.<br>
          Token is saved to token.txt and refreshed every 6 hours.<br><br>
          <b style="color:var(--accent2)">4. Controls</b><br>
          &#9654; Start &mdash; launch Vhaw.py<br>
          &#9632; Stop &mdash; gracefully terminate<br>
          &#8634; Restart &mdash; stop then start<br>
          &#10005; Force Stop &mdash; kill immediately<br><br>
          <b style="color:var(--accent2)">5. Mobile</b><br>
          Tap the 3-line menu to open/close the sidebar on mobile.
        </div>
      </div>
    </div>
  </div>
</div>

<script>
const USERNAME = "{{username}}";
let pollInterval = null;
let lastLineCount = 0;
let autoScroll = false;

// ===== Mobile Hamburger Sidebar =====
function toggleSidebar(){
  const sb = document.getElementById('sidebar');
  const ov = document.getElementById('sidebarOverlay');
  const hb = document.getElementById('hamburger');
  sb.classList.toggle('show');
  ov.classList.toggle('show');
  hb.classList.toggle('active');
}

// ===== Page Navigation =====
function showPage(id, el){
  document.querySelectorAll('.section-page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.menu-item').forEach(m=>m.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if(el) el.classList.add('active');
  if(id==='page-files') loadFiles();
  if(id==='page-status') loadStatus();
  // Close mobile sidebar after selection
  if(window.innerWidth <= 768){
    const sb = document.getElementById('sidebar');
    if(sb.classList.contains('show')) toggleSidebar();
  }
}

// ===== Auto-scroll (default OFF) =====
document.getElementById('auto-scroll-chk').addEventListener('change', function(){
  autoScroll = this.checked;
});
function clearTerminal(){ document.getElementById('terminal').innerHTML='<span class="t-dim">&mdash; Terminal cleared &mdash;</span>'; lastLineCount=0; }

// ===== Process Controls =====
async function procAction(action){
  const res = await fetch('/api/process/'+action, {method:'POST'});
  const d = await res.json();
  showFlash(d.msg, d.ok ? 'ok':'err');
  if(action==='start' && d.ok) startPoll();
}

// ===== Terminal Polling =====
function startPoll(){ if(pollInterval) return; pollInterval = setInterval(fetchOutput, 1000); }
function stopPoll(){ clearInterval(pollInterval); pollInterval=null; }
async function fetchOutput(){
  try{
    const res = await fetch('/api/terminal/output?from='+lastLineCount);
    const d = await res.json();
    if(!d.ok) return;
    const term = document.getElementById('terminal');
    if(d.lines && d.lines.length){
      if(lastLineCount===0) term.innerHTML='';
      d.lines.forEach(line=>{
        const span = document.createElement('span');
        if(line.startsWith('[Vhaw_X_limon]')) span.className='t-info';
        else if(line.toLowerCase().includes('error')||line.startsWith('[stream error]')) span.className='t-err';
        span.textContent = line + '\\n';
        term.appendChild(span);
      });
      lastLineCount = d.total;
      if(autoScroll) term.scrollTop = term.scrollHeight;
    }
    const dot = document.getElementById('proc-dot');
    if(d.status==='running') dot.classList.add('running');
    else dot.classList.remove('running');
  } catch(e){}
}

// ===== Credentials =====
async function saveCreds(){
  const uid = document.getElementById('cred-uid').value.trim();
  const pass = document.getElementById('cred-pass').value.trim();
  const ownerUid = document.getElementById('cred-owner-uid').value.trim();
  const ownerName = document.getElementById('cred-owner-name').value.trim();
  if(!uid||!pass){ showCredFlash('UID and password are required.','err'); return; }
  const res = await fetch('/api/credentials', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({uid, password:pass, owner_uid:ownerUid, owner_name:ownerName})
  });
  const d = await res.json();
  showCredFlash(d.msg, d.ok?'ok':'err');
  if(d.ok) checkCreds();
}
async function checkCreds(){
  const res = await fetch('/api/credentials/check');
  const d = await res.json();
  const warn = document.getElementById('creds-warn');
  if(warn) warn.style.display = d.set ? 'none' : 'block';
}
function showCredFlash(msg,type){
  const el=document.getElementById('cred-flash');
  el.innerHTML='<div class="flash flash-'+(type==='ok'?'ok':'err')+'">'+msg+'</div>';
  setTimeout(()=>el.innerHTML='',4000);
}

// ===== Files =====
async function loadFiles(){
  const res = await fetch('/api/files');
  const d = await res.json();
  const el = document.getElementById('file-list');
  if(!d.ok||!d.files.length){ el.innerHTML='<span class="t-dim">No files found.</span>'; return; }
  el.innerHTML = d.files.map(f=>
    '<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:13px;display:flex;align-items:center;gap:10px;">'+
    '<span>'+(f.is_dir?'&#128194;':'&#128196;')+'</span>'+
    '<span style="flex:1">'+f.name+'</span>'+
    '<span style="color:var(--muted);font-size:11px">'+f.size+'</span></div>'
  ).join('');
}

// ===== Status =====
async function loadStatus(){
  const res = await fetch('/api/status');
  const d = await res.json();
  document.getElementById('status-proc').innerHTML = d.process==='running'
    ? '<span class="tag tag-green">RUNNING</span>' : '<span class="tag tag-red">STOPPED</span>';
  document.getElementById('status-creds').innerHTML = d.creds_set
    ? '<span class="tag tag-green">SET</span>' : '<span class="tag tag-yellow">NOT SET</span>';
  document.getElementById('status-jwt').innerHTML = d.jwt_ok
    ? '<span class="tag tag-green">VALID</span>' : '<span class="tag tag-yellow">NOT SET</span>';
}

// ===== Tool: Nickname =====
async function doNickname(){
  const name = document.getElementById('nick-input').value.trim();
  if(!name){ showFlashTo('nick-flash','Enter a nickname','err'); return; }
  document.getElementById('nick-result').innerHTML = '<span class="t-dim">Working...</span>';
  const res = await fetch('/api/tools/nickname', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name})});
  const d = await res.json();
  showFlashTo('nick-flash',d.msg,d.ok?'ok':'err');
  document.getElementById('nick-result').innerHTML = d.ok ? '<span class="tag tag-green">DONE</span>' : '<span class="tag tag-red">FAILED</span>';
}

// ===== Tool: Login History =====
async function doLoginHistory(){
  document.getElementById('loginhist-result').innerHTML = '<span class="t-dim">Loading...</span>';
  const res = await fetch('/api/tools/login-history');
  const d = await res.json();
  if(!d.ok || !d.logins || !d.logins.length){ document.getElementById('loginhist-result').innerHTML='<span class="t-dim">No data.</span>'; return; }
  let html = '<table style="width:100%;font-size:12px;border-collapse:collapse">';
  html += '<tr style="color:var(--muted)"><th style="text-align:left;padding:6px">#</th><th style="text-align:left">Time</th><th style="text-align:left">Device</th><th>Arch</th></tr>';
  d.logins.forEach((l,i)=>{
    html += '<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px">'+(i+1)+'</td><td>'+(l.time||'?')+'</td><td>'+(l.device||'?')+'</td><td>'+(l.arch||'?')+'</td></tr>';
  });
  html += '</table>';
  document.getElementById('loginhist-result').innerHTML = html;
}

// ===== Tool: Friends =====
async function doFriendList(){
  document.getElementById('friends-result').innerHTML = '<span class="t-dim">Loading...</span>';
  const res = await fetch('/api/tools/friends');
  const d = await res.json();
  if(!d.ok){ document.getElementById('friends-result').innerHTML='<span class="t-err">'+d.msg+'</span>'; return; }
  if(!d.friends || !d.friends.length){ document.getElementById('friends-result').innerHTML='<span class="t-dim">No friends.</span>'; return; }
  let html = '<div style="font-size:13px">';
  d.friends.forEach(f=>{ html += '<div style="padding:6px 0;border-bottom:1px solid var(--border)"><b>'+f.uid+'</b> &mdash; '+f.name+'</div>'; });
  html += '</div>';
  document.getElementById('friends-result').innerHTML = html;
}

// ===== Tool: Profile Items =====
async function doProfileItems(){
  const items = document.getElementById('profile-items').value.trim();
  document.getElementById('profile-result').innerHTML = '<span class="t-dim">Working...</span>';
  const res = await fetch('/api/tools/profile-items', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({items:items||''})});
  const d = await res.json();
  showFlashTo('profile-flash',d.msg,d.ok?'ok':'err');
  document.getElementById('profile-result').innerHTML = d.ok ? '<span class="tag tag-green">'+d.msg+'</span>' : '<span class="tag tag-red">'+d.msg+'</span>';
}

// ===== Tool: Wishlist =====
async function doWishlist(){
  document.getElementById('wishlist-result').innerHTML = '<span class="t-dim">Adding items in parallel, please wait...</span>';
  const res = await fetch('/api/tools/wishlist', {method:'POST'});
  const d = await res.json();
  document.getElementById('wishlist-result').innerHTML = d.ok
    ? '<span class="tag tag-green">Success: '+d.success_count+' items</span> <span class="tag tag-red">Failed: '+d.fail_count+'</span>'
    : '<span class="tag tag-red">'+d.msg+'</span>';
}

// ===== Tool: Craftland =====
async function doCraftSubscribe(){
  const code = document.getElementById('craft-code').value.trim();
  const region = document.getElementById('craft-region').value.trim() || 'BD';
  if(!code){ showFlashTo('craft-flash','Enter map code','err'); return; }
  document.getElementById('craft-result').innerHTML = '<span class="t-dim">Working...</span>';
  const res = await fetch('/api/tools/craftland/subscribe', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({code,region})});
  const d = await res.json();
  showFlashTo('craft-flash',d.msg,d.ok?'ok':'err');
  document.getElementById('craft-result').innerHTML = d.ok ? '<span class="tag tag-green">'+d.msg+'</span>' : '<span class="tag tag-red">'+d.msg+'</span>';
}
async function doCraftInfo(){
  const code = document.getElementById('craft-code').value.trim();
  const region = document.getElementById('craft-region').value.trim() || 'BD';
  if(!code){ showFlashTo('craft-flash','Enter map code','err'); return; }
  document.getElementById('craft-result').innerHTML = '<span class="t-dim">Loading...</span>';
  const res = await fetch('/api/tools/craftland/info?code='+encodeURIComponent(code)+'&region='+region);
  const d = await res.json();
  if(!d.ok){ document.getElementById('craft-result').innerHTML='<span class="tag tag-red">'+d.msg+'</span>'; return; }
  let html = '<div style="font-size:13px;line-height:1.8">';
  for(const [k,v] of Object.entries(d.info)){ html += '<div><b style="color:var(--accent2)">'+k+':</b> '+v+'</div>'; }
  html += '</div>';
  document.getElementById('craft-result').innerHTML = html;
}

// ===== Tool: Player Info =====
async function doPlayerInfo(){
  const uid = document.getElementById('pinfo-uid').value.trim();
  if(!uid){ showFlashTo('pinfo-flash','Enter UID','err'); return; }
  document.getElementById('pinfo-result').innerHTML = '<span class="t-dim">Loading...</span>';
  const res = await fetch('/api/tools/player-info?uid='+encodeURIComponent(uid));
  const d = await res.json();
  if(!d.ok){ document.getElementById('pinfo-result').innerHTML='<span class="tag tag-red">'+d.msg+'</span>'; return; }
  let html = '<div style="font-size:13px;line-height:1.8">';
  for(const [k,v] of Object.entries(d.info)){ html += '<div><b style="color:var(--accent2)">'+k+':</b> '+v+'</div>'; }
  html += '<div><b style="color:var(--accent2)">region:</b> '+d.region+'</div></div>';
  document.getElementById('pinfo-result').innerHTML = html;
}

// ===== Tool: Change Bio =====
async function doChangeBio(){
  const bio = document.getElementById('bio-input').value.trim();
  if(!bio){ showFlashTo('bio-flash','Enter bio text','err'); return; }
  document.getElementById('bio-result').innerHTML = '<span class="t-dim">Working...</span>';
  const res = await fetch('/api/tools/bio', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({bio})});
  const d = await res.json();
  showFlashTo('bio-flash',d.msg,d.ok?'ok':'err');
  document.getElementById('bio-result').innerHTML = d.ok ? '<span class="tag tag-green">'+d.msg+'</span>' : '<span class="tag tag-red">'+d.msg+'</span>';
}

// ===== Tool: Friend Manager =====
async function doFriendAdd(){
  const uid = document.getElementById('fmgr-uid').value.trim();
  if(!uid){ showFlashTo('fmgr-flash','Enter UID','err'); return; }
  document.getElementById('fmgr-result').innerHTML = '<span class="t-dim">Working...</span>';
  const res = await fetch('/api/tools/friend/add', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({target_uid:uid})});
  const d = await res.json();
  showFlashTo('fmgr-flash',d.msg,d.ok?'ok':'err');
  document.getElementById('fmgr-result').innerHTML = d.ok ? '<span class="tag tag-green">'+d.msg+'</span>' : '<span class="tag tag-red">'+d.msg+'</span>';
}
async function doFriendRemove(){
  const uid = document.getElementById('fmgr-uid').value.trim();
  if(!uid){ showFlashTo('fmgr-flash','Enter UID','err'); return; }
  document.getElementById('fmgr-result').innerHTML = '<span class="t-dim">Working...</span>';
  const res = await fetch('/api/tools/friend/remove', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({target_uid:uid})});
  const d = await res.json();
  showFlashTo('fmgr-flash',d.msg,d.ok?'ok':'err');
  document.getElementById('fmgr-result').innerHTML = d.ok ? '<span class="tag tag-green">'+d.msg+'</span>' : '<span class="tag tag-red">'+d.msg+'</span>';
}

// ===== Tool: Guild Manager =====
async function doGuildJoin(){
  const id = document.getElementById('guild-id').value.trim();
  const region = document.getElementById('guild-region').value.trim() || 'BD';
  if(!id){ showFlashTo('guild-flash','Enter clan ID','err'); return; }
  document.getElementById('guild-result').innerHTML = '<span class="t-dim">Working...</span>';
  const res = await fetch('/api/tools/guild/join', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({clan_id:id,region})});
  const d = await res.json();
  showFlashTo('guild-flash',d.msg,d.ok?'ok':'err');
  document.getElementById('guild-result').innerHTML = d.ok ? '<span class="tag tag-green">'+d.msg+'</span>' : '<span class="tag tag-red">'+d.msg+'</span>';
}
async function doGuildLeave(){
  const id = document.getElementById('guild-id').value.trim();
  const region = document.getElementById('guild-region').value.trim() || 'BD';
  if(!id){ showFlashTo('guild-flash','Enter clan ID','err'); return; }
  document.getElementById('guild-result').innerHTML = '<span class="t-dim">Working...</span>';
  const res = await fetch('/api/tools/guild/leave', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({clan_id:id,region})});
  const d = await res.json();
  showFlashTo('guild-flash',d.msg,d.ok?'ok':'err');
  document.getElementById('guild-result').innerHTML = d.ok ? '<span class="tag tag-green">'+d.msg+'</span>' : '<span class="tag tag-red">'+d.msg+'</span>';
}
async function doGuildInfo(){
  const id = document.getElementById('guild-id').value.trim();
  const region = document.getElementById('guild-region').value.trim() || 'BD';
  if(!id){ showFlashTo('guild-flash','Enter clan ID','err'); return; }
  document.getElementById('guild-result').innerHTML = '<span class="t-dim">Loading...</span>';
  const res = await fetch('/api/tools/guild/info?clan_id='+encodeURIComponent(id)+'&region='+region);
  const d = await res.json();
  if(!d.ok){ document.getElementById('guild-result').innerHTML='<span class="tag tag-red">'+d.msg+'</span>'; return; }
  let html = '<div style="font-size:13px;line-height:1.8">';
  for(const [k,v] of Object.entries(d.info)){ html += '<div><b style="color:var(--accent2)">'+k+':</b> '+v+'</div>'; }
  html += '</div>';
  document.getElementById('guild-result').innerHTML = html;
}
async function doGuildMembers(){
  const id = document.getElementById('guild-id').value.trim();
  const region = document.getElementById('guild-region').value.trim() || 'BD';
  if(!id){ showFlashTo('guild-flash','Enter clan ID','err'); return; }
  document.getElementById('guild-result').innerHTML = '<span class="t-dim">Loading...</span>';
  const res = await fetch('/api/tools/guild/members?clan_id='+encodeURIComponent(id)+'&region='+region);
  const d = await res.json();
  if(!d.ok || !d.members || !d.members.length){ document.getElementById('guild-result').innerHTML='<span class="t-dim">No members.</span>'; return; }
  let html = '<table style="width:100%;font-size:12px;border-collapse:collapse">';
  html += '<tr style="color:var(--muted)"><th style="text-align:left;padding:6px">#</th><th style="text-align:left">UID</th><th style="text-align:left">Name</th><th>Role</th><th>Glory</th></tr>';
  d.members.forEach((m,i)=>{
    const role = m.role==3?'Leader':m.role==4?'Acting Leader':m.role==2?'Officer':'Member';
    html += '<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px">'+(i+1)+'</td><td>'+m.uid+'</td><td>'+m.name+'</td><td>'+role+'</td><td>'+m.total_glory+'</td></tr>';
  });
  html += '</table>';
  document.getElementById('guild-result').innerHTML = html;
}

// ===== Broadcast Polling =====
async function pollBroadcasts(){
  try{
    const res = await fetch('/api/broadcasts');
    const d = await res.json();
    const area = document.getElementById('broadcast-area');
    area.innerHTML='';
    if(d.messages && d.messages.length){
      d.messages.forEach(m=>{
        const div=document.createElement('div');
        div.className='broadcast-msg show';
        div.innerHTML = '<b>&#128226; Admin:</b> '+m.content;
        area.appendChild(div);
      });
    }
  }catch(e){}
}

// ===== Logout =====
async function doLogout(){
  await fetch('/api/logout',{method:'POST'});
  location.href='/login';
}

// ===== Flash Helpers =====
function showFlash(msg,type){
  const d=document.createElement('div');
  d.className='flash flash-'+(type==='ok'?'ok':'err');
  d.textContent=msg;
  document.querySelector('.main').prepend(d);
  setTimeout(()=>d.remove(),3500);
}
function showFlashTo(id,msg,type){
  const el=document.getElementById(id);
  if(!el) return;
  el.innerHTML='<div class="flash flash-'+(type==='ok'?'ok':'err')+'" style="margin-bottom:12px">'+msg+'</div>';
  setTimeout(()=>el.innerHTML='',4000);
}

// ===== Init =====
checkCreds();
startPoll();
fetchOutput();
setInterval(pollBroadcasts, 8000);
pollBroadcasts();
</script>
</body>
</html>
"""

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN HTML TEMPLATE
# ══════════════════════════════════════════════════════════════════════════════
ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Vhaw_X_limon &mdash; Admin</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;900&display=swap" rel="stylesheet">
<style>
""" + BASE_CSS + """
.main-admin{padding:28px;max-width:1200px;margin:0 auto}
@media (max-width:768px){ .main-admin{padding:16px} }
</style>
</head>
<body>
<div class="topbar">
  <div style="display:flex;align-items:center;gap:12px">
    <div class="hamburger" id="hamburger" onclick="toggleSidebar()">
      <span></span><span></span><span></span>
    </div>
    <div class="logo-text">Vhaw_X_limon <span style="color:var(--red)">ADMIN</span></div>
  </div>
  <button class="btn btn-sm btn-red" onclick="adminLogout()">Logout</button>
</div>
<div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>
<div class="layout">
  <nav class="sidebar" id="sidebar">
    <div class="menu-bar"><span></span>PANEL<span></span></div>
    <div class="sidebar-section">
      <div class="menu-item active" onclick="showTab('tab-users',this)"><span class="ico">&#128101;</span> Users</div>
      <div class="menu-item" onclick="showTab('tab-broadcast',this)"><span class="ico">&#128226;</span> Broadcast</div>
      <div class="menu-item" onclick="showTab('tab-smtp',this)"><span class="ico">&#9993;</span> SMTP</div>
      <div class="menu-item" onclick="showTab('tab-server',this)"><span class="ico">&#9881;</span> Server</div>
      <div class="menu-item" onclick="window.open('/', '_blank')"><span class="ico">&#127760;</span> Main Site</div>
    </div>
  </nav>
  <div class="main main-admin">
    <div id="maint-banner" class="maint-banner">
      &#128295; SERVER MAINTENANCE MODE IS ACTIVE &mdash; Regular users are locked out.
    </div>
    <div id="admin-flash"></div>

    <!-- USERS TAB -->
    <div class="tab-page active" id="tab-users">
      <div class="section-title">User Management</div>
      <div class="section-sub">Block, ban, unban, remove users or stop their sessions.</div>
      <div class="card" style="overflow-x:auto">
        <button class="btn btn-sm btn-cyan" onclick="loadUsers()" style="margin-bottom:16px">&#8635; Refresh</button>
        <table class="admin-table" id="users-table" style="min-width:700px">
          <thead><tr>
            <th>Username</th><th>Email</th><th>Created</th><th>Status</th><th>Process</th><th>Actions</th>
          </tr></thead>
          <tbody id="users-tbody"><tr><td colspan="6" style="color:var(--muted)">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- BROADCAST TAB -->
    <div class="tab-page" id="tab-broadcast">
      <div class="section-title">Live Broadcast</div>
      <div class="section-sub">Send a message to all logged-in users.</div>
      <div class="card" style="max-width:560px">
        <div id="bc-flash"></div>
        <div class="field">
          <label>MESSAGE</label>
          <textarea id="bc-msg" rows="4" placeholder="Enter broadcast message..."></textarea>
        </div>
        <button class="btn" onclick="sendBroadcast()">&#128226; Send to All Users</button>
        <button class="btn btn-red btn-sm" style="margin-left:10px" onclick="clearBroadcasts()">&#10005; Clear All</button>
      </div>
      <div class="card" style="margin-top:16px;max-width:560px">
        <div style="font-size:13px;color:var(--muted);margin-bottom:10px">Active broadcasts:</div>
        <div id="active-broadcasts"><span style="color:var(--muted)">None</span></div>
      </div>
    </div>

    <!-- SMTP TAB -->
    <div class="tab-page" id="tab-smtp">
      <div class="section-title">SMTP Configuration</div>
      <div class="section-sub">Configure email for password resets and verification.</div>
      <div class="card" style="max-width:540px">
        <div id="smtp-flash"></div>
        <div class="field"><label>SMTP HOST</label><input id="smtp-host" value="smtp.gmail.com"></div>
        <div class="field"><label>SMTP PORT</label><input id="smtp-port" value="587" type="number"></div>
        <div class="field"><label>SMTP USER (email)</label><input id="smtp-user" type="email" placeholder="your@gmail.com"></div>
        <div class="field"><label>SMTP PASSWORD</label><input id="smtp-pass" type="password" placeholder="App password"></div>
        <div class="field"><label>FROM NAME</label><input id="smtp-from" placeholder="Vhaw_X_limon Panel"></div>
        <button class="btn" onclick="saveSmtp()">&#128190; Save SMTP Settings</button>
        <button class="btn btn-cyan btn-sm" style="margin-left:10px" onclick="testSmtp()">&#128269; Send Test</button>
        <div class="field" style="margin-top:16px"><label>TEST EMAIL</label><input id="smtp-test-to" placeholder="test@email.com"></div>
      </div>
    </div>

    <!-- SERVER TAB -->
    <div class="tab-page" id="tab-server">
      <div class="section-title">Server Control</div>
      <div class="section-sub">Maintenance mode and server management.</div>
      <div class="card" style="max-width:540px">
        <div id="srv-flash"></div>
        <div style="margin-bottom:16px">
          <div style="font-size:13px;margin-bottom:10px;color:var(--muted)">Maintenance Mode &mdash; blocks all non-admin access</div>
          <button class="btn btn-yellow" onclick="toggleMaint()">&#128295; Toggle Maintenance</button>
          <span id="maint-state" style="margin-left:12px;font-size:13px"></span>
        </div>
        <hr style="border:none;border-top:1px solid var(--border);margin:20px 0">
        <div style="margin-bottom:16px">
          <div style="font-size:13px;margin-bottom:10px;color:var(--muted)">Stop ALL user processes</div>
          <button class="btn btn-red" onclick="stopAllProcs()">&#9632; Kill All Sessions</button>
        </div>
        <hr style="border:none;border-top:1px solid var(--border);margin:20px 0">
        <div>
          <div style="font-size:13px;margin-bottom:10px;color:var(--red)">&#9888; Shutdown the server entirely</div>
          <button class="btn btn-red" onclick="shutdownSrv()">&#9211; Shutdown Server</button>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
// ===== Mobile Hamburger =====
function toggleSidebar(){
  const sb=document.getElementById('sidebar');
  const ov=document.getElementById('sidebarOverlay');
  const hb=document.getElementById('hamburger');
  sb.classList.toggle('show');
  ov.classList.toggle('show');
  hb.classList.toggle('active');
}
function showTab(id,el){
  document.querySelectorAll('.tab-page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.menu-item').forEach(t=>t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if(el) el.classList.add('active');
  if(id==='tab-users') loadUsers();
  if(id==='tab-broadcast') loadBroadcasts();
  if(id==='tab-server') loadMaint();
  if(window.innerWidth <= 768 && document.getElementById('sidebar').classList.contains('show')) toggleSidebar();
}

async function apiFetch(url,opts={}){
  opts.headers = opts.headers||{};
  opts.headers['Content-Type']='application/json';
  const r = await fetch(url,opts);
  return r.json();
}

// ===== Users =====
async function loadUsers(){
  const d = await apiFetch('/admin/api/users');
  const tb = document.getElementById('users-tbody');
  if(!d.ok||!d.users.length){tb.innerHTML='<tr><td colspan="6" style="color:var(--muted)">No users.</td></tr>';return;}
  tb.innerHTML = d.users.map(u=>{
    const banned = u.is_banned;
    const blocked = u.is_blocked;
    const status = banned?'<span class="tag tag-red">BANNED</span>':blocked?'<span class="tag tag-yellow">BLOCKED</span>':'<span class="tag tag-green">ACTIVE</span>';
    const proc = u.process==='running'?'<span class="tag tag-green">RUNNING</span>':'<span class="tag tag-muted">STOPPED</span>';
    const un = u.username.replace(/'/g,"&#39;").replace(/"/g,"&quot;");
    return '<tr>'+
      '<td><b>'+u.username+'</b></td>'+
      '<td style="color:var(--muted)">'+u.email+'</td>'+
      '<td style="color:var(--muted);font-size:11px">'+(u.created_at||'')+'</td>'+
      '<td>'+status+'</td>'+
      '<td>'+proc+'</td>'+
      '<td><div class="admin-actions">'+
        '<button class="btn btn-sm btn-yellow" onclick="userAction(&#39;'+un+'&#39;,&#39;block&#39;)">&#128683; Block</button>'+
        '<button class="btn btn-sm btn-red" onclick="userAction(&#39;'+un+'&#39;,&#39;ban&#39;)">&#128163; Ban</button>'+
        '<button class="btn btn-sm btn-green" onclick="userAction(&#39;'+un+'&#39;,&#39;unban&#39;)">&#9989; Unban</button>'+
        '<button class="btn btn-sm" onclick="userAction(&#39;'+un+'&#39;,&#39;unblock&#39;)">&#128275; Unblock</button>'+
        '<button class="btn btn-sm btn-cyan" onclick="userAction(&#39;'+un+'&#39;,&#39;stop_session&#39;)">&#9632; Stop</button>'+
        '<button class="btn btn-sm btn-red" onclick="userAction(&#39;'+un+'&#39;,&#39;remove&#39;)">&#10005; Remove</button>'+
      '</div></td></tr>';
  }).join('');
}
async function userAction(username, action){
  if(action==='remove' && !confirm('Remove user '+username+'? This cannot be undone.')) return;
  const d = await apiFetch('/admin/api/user-action',{method:'POST',body:JSON.stringify({username,action})});
  flashAdmin(d.msg, d.ok?'ok':'err');
  loadUsers();
}

// ===== Broadcast =====
async function sendBroadcast(){
  const content = document.getElementById('bc-msg').value.trim();
  if(!content){flashId('bc-flash','Message required','err');return;}
  const d = await apiFetch('/admin/api/broadcast',{method:'POST',body:JSON.stringify({content})});
  flashId('bc-flash',d.msg,d.ok?'ok':'err');
  loadBroadcasts();
}
async function clearBroadcasts(){
  await apiFetch('/admin/api/broadcast/clear',{method:'POST'});
  loadBroadcasts();
}
async function loadBroadcasts(){
  const d = await apiFetch('/admin/api/broadcasts');
  const el = document.getElementById('active-broadcasts');
  if(!d.messages||!d.messages.length){el.innerHTML='<span style="color:var(--muted)">None</span>';return;}
  el.innerHTML = d.messages.map(m=>
    '<div style="padding:8px;background:var(--bg3);border-radius:6px;margin-bottom:6px;font-size:13px">'+m.content+'</div>'
  ).join('');
}

// ===== SMTP =====
async function saveSmtp(){
  const cfg = {
    host: document.getElementById('smtp-host').value,
    port: parseInt(document.getElementById('smtp-port').value),
    user: document.getElementById('smtp-user').value,
    pass: document.getElementById('smtp-pass').value,
    from: document.getElementById('smtp-from').value
  };
  const d = await apiFetch('/admin/api/smtp',{method:'POST',body:JSON.stringify(cfg)});
  flashId('smtp-flash',d.msg,d.ok?'ok':'err');
}
async function testSmtp(){
  const to = document.getElementById('smtp-test-to').value.trim();
  if(!to){flashId('smtp-flash','Enter a test email first','err');return;}
  const d = await apiFetch('/admin/api/smtp/test',{method:'POST',body:JSON.stringify({to})});
  flashId('smtp-flash',d.msg,d.ok?'ok':'err');
}

// ===== Server =====
async function toggleMaint(){
  const d = await apiFetch('/admin/api/maintenance',{method:'POST'});
  flashId('srv-flash',d.msg,'ok');
  loadMaint();
}
async function loadMaint(){
  const d = await apiFetch('/admin/api/maintenance');
  const banner = document.getElementById('maint-banner');
  const state = document.getElementById('maint-state');
  if(d.maintenance){ banner.classList.add('show'); state.innerHTML='<span class="tag tag-red">ON</span>'; }
  else { banner.classList.remove('show'); state.innerHTML='<span class="tag tag-green">OFF</span>'; }
}
async function stopAllProcs(){
  if(!confirm('Stop ALL user processes?')) return;
  const d = await apiFetch('/admin/api/stop-all',{method:'POST'});
  flashId('srv-flash',d.msg,'ok');
}
async function shutdownSrv(){
  if(!confirm('Are you sure you want to SHUT DOWN the server?')) return;
  await apiFetch('/admin/api/shutdown',{method:'POST'});
  flashId('srv-flash','Shutdown signal sent.','ok');
}

// ===== Helpers =====
function flashAdmin(msg,type){ flashId('admin-flash',msg,type); }
function flashId(id,msg,type){
  const el = document.getElementById(id);
  if(!el) return;
  el.innerHTML='<div class="flash flash-'+(type==='ok'?'ok':'err')+'" style="margin-bottom:12px">'+msg+'</div>';
  setTimeout(()=>el.innerHTML='',4000);
}
async function adminLogout(){
  await fetch('/admin/logout',{method:'POST'});
  location.href='/admin';
}
loadUsers();
loadMaint();
</script>
</body>
</html>
"""


# ══════════════════════════════════════════════════════════════════════════════
#  FLASK AUTH PAGES
# ══════════════════════════════════════════════════════════════════════════════
def render_auth(title, body):
    return render_template_string(AUTH_HTML.replace("{{title}}", title).replace("{{body}}", body))

@app.before_request
def check_maintenance():
    global maintenance_mode
    exempt = ["/admin", "/admin/", "/admin/login", "/admin/api/", "/api/logout",
              "/login", "/register", "/forgot-password", "/reset-password",
              "/verify-email", "/static/"]
    path = request.path
    if maintenance_mode and not session.get("is_admin"):
        if not any(path.startswith(e) for e in exempt):
            if request.is_json:
                return jsonify({"ok": False, "msg": "Server maintenance in progress."}), 503
            return render_auth("Maintenance", """
            <div class="auth-card">
              <h2>&#128295; Server Maintenance</h2>
              <p style="color:var(--muted);font-size:14px;line-height:1.7;margin-top:10px">
                Vhaw_X_limon Panel is currently under maintenance.<br>Please check back shortly.
              </p>
            </div>""")

@app.route("/")
def index():
    if current_user():
        return redirect("/panel")
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        body = """
        <div class="auth-card fade-in">
          <h2>Sign In</h2>
          <div id="flash"></div>
          <div class="field"><label>USERNAME</label><input id="uname" type="text" placeholder="your_username" autocomplete="username"></div>
          <div class="field"><label>PASSWORD</label><input id="upass" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" autocomplete="current-password"></div>
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
            <label style="font-size:12px;display:flex;gap:6px;align-items:center;cursor:pointer">
              <input type="checkbox" id="remember" style="width:auto"> Remember me
            </label>
            <a href="/forgot-password" style="font-size:12px">Forgot password?</a>
          </div>
          <button class="btn" style="width:100%" onclick="doLogin()">Sign In &rarr;</button>
          <div class="auth-foot">No account? <a href="/register">Register</a></div>
        </div>
        <script>
        async function doLogin(){
          const u=document.getElementById('uname').value.trim();
          const p=document.getElementById('upass').value;
          const r=document.getElementById('remember').checked;
          const res=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p,remember:r})});
          const d=await res.json();
          if(d.ok){location.href='/panel';}
          else{document.getElementById('flash').innerHTML='<div class="flash flash-err">'+d.msg+'</div>';}
        }
        document.addEventListener('keydown',e=>{ if(e.key==='Enter') doLogin(); });
        </script>
        """
        return render_auth("Login", body)
    return redirect("/panel")

@app.route("/register", methods=["GET"])
def register():
    body = """
    <div class="auth-card fade-in">
      <h2>Create Account</h2>
      <div id="flash"></div>
      <div class="field"><label>USERNAME</label><input id="uname" type="text" placeholder="choose_username" autocomplete="username"></div>
      <div class="field"><label>EMAIL</label><input id="uemail" type="email" placeholder="you@email.com" autocomplete="email"></div>
      <div class="field"><label>PASSWORD</label><input id="upass" type="password" placeholder="min 8 characters" autocomplete="new-password"></div>
      <div class="field"><label>CONFIRM PASSWORD</label><input id="upass2" type="password" placeholder="repeat password"></div>
      <button class="btn" style="width:100%;margin-top:4px" onclick="doRegister()">Create Account &rarr;</button>
      <div class="auth-foot">Already have an account? <a href="/login">Sign In</a></div>
    </div>
    <script>
    async function doRegister(){
      const u=document.getElementById('uname').value.trim();
      const e=document.getElementById('uemail').value.trim();
      const p=document.getElementById('upass').value;
      const p2=document.getElementById('upass2').value;
      if(p!==p2){document.getElementById('flash').innerHTML='<div class="flash flash-err">Passwords do not match.</div>';return;}
      const res=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,email:e,password:p})});
      const d=await res.json();
      document.getElementById('flash').innerHTML=d.ok?'<div class="flash flash-ok">'+d.msg+' Redirecting...</div>':'<div class="flash flash-err">'+d.msg+'</div>';
      if(d.ok) setTimeout(()=>location.href='/login',1500);
    }
    </script>
    """
    return render_auth("Register", body)

@app.route("/forgot-password", methods=["GET"])
def forgot_password():
    body = """
    <div class="auth-card fade-in">
      <h2>Reset Password</h2>
      <p style="color:var(--muted);font-size:13px;margin-bottom:16px">Enter your email to receive a reset code.</p>
      <div id="flash"></div>
      <div class="field"><label>EMAIL</label><input id="uemail" type="email" placeholder="your@email.com"></div>
      <button class="btn" style="width:100%" onclick="doForgot()">Send Reset Code &rarr;</button>
      <div class="auth-foot"><a href="/login">&larr; Back to Login</a></div>
    </div>
    <script>
    async function doForgot(){
      const e=document.getElementById('uemail').value.trim();
      const res=await fetch('/api/forgot-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:e})});
      const d=await res.json();
      document.getElementById('flash').innerHTML=d.ok?'<div class="flash flash-ok">'+d.msg+'</div>':'<div class="flash flash-err">'+d.msg+'</div>';
      if(d.ok) setTimeout(()=>location.href='/reset-password?email='+encodeURIComponent(e),1500);
    }
    </script>
    """
    return render_auth("Forgot Password", body)

@app.route("/reset-password", methods=["GET"])
def reset_password_page():
    email = request.args.get("email", "")
    body = f"""
    <div class="auth-card fade-in">
      <h2>Enter Reset Code</h2>
      <p style="color:var(--muted);font-size:13px;margin-bottom:16px">Check your email for the 6-digit code.</p>
      <div id="flash"></div>
      <div class="field"><label>EMAIL</label><input id="uemail" value="{email}" type="email"></div>
      <div class="field"><label>CODE</label><input id="ucode" type="text" maxlength="6" placeholder="6-digit code"></div>
      <div class="field"><label>NEW PASSWORD</label><input id="upass" type="password" placeholder="min 8 chars"></div>
      <div class="field"><label>CONFIRM</label><input id="upass2" type="password"></div>
      <button class="btn" style="width:100%" onclick="doReset()">Reset Password &rarr;</button>
      <div class="auth-foot"><a href="/login">&larr; Back to Login</a></div>
    </div>
    <script>
    async function doReset(){{
      const e=document.getElementById('uemail').value.trim();
      const c=document.getElementById('ucode').value.trim();
      const p=document.getElementById('upass').value;
      const p2=document.getElementById('upass2').value;
      if(p!==p2){{document.getElementById('flash').innerHTML='<div class="flash flash-err">Passwords do not match.</div>';return;}}
      const res=await fetch('/api/reset-password',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email:e,code:c,password:p}})}});
      const d=await res.json();
      document.getElementById('flash').innerHTML=d.ok?'<div class="flash flash-ok">'+d.msg+'</div>':'<div class="flash flash-err">'+d.msg+'</div>';
      if(d.ok) setTimeout(()=>location.href='/login',1500);
    }}
    </script>
    """
    return render_auth("Reset Password", body)

@app.route("/panel")
@login_required
def panel():
    return render_template_string(PANEL_HTML.replace("{{username}}", current_user()))


# ══════════════════════════════════════════════════════════════════════════════
#  API: AUTH
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    remember = bool(data.get("remember", False))

    if not username or not password:
        return jsonify({"ok": False, "msg": "Username and password required."})

    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    if not u:
        return jsonify({"ok": False, "msg": "Invalid username or password."})
    if not verify_password(password, u["password"]):
        return jsonify({"ok": False, "msg": "Invalid username or password."})
    if u["is_banned"]:
        return jsonify({"ok": False, "msg": "Your account has been banned."})
    if u["is_blocked"]:
        return jsonify({"ok": False, "msg": "Your account is temporarily blocked."})

    session.permanent = remember
    session["username"] = username
    session["is_admin"] = False  # Regular user, not admin

    with get_db() as db:
        db.execute("UPDATE users SET last_login=? WHERE username=?",
                   (datetime.utcnow().isoformat(timespec="seconds"), username))

    # Auto-generate JWT on login
    threading.Thread(target=lambda: generate_jwt_for_user(username), daemon=True).start()

    return jsonify({"ok": True, "msg": "Logged in."})

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"ok": False, "msg": "All fields are required."})
    if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
        return jsonify({"ok": False, "msg": "Username: 3-32 chars, letters/numbers/underscores only."})
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({"ok": False, "msg": "Invalid email address."})
    if len(password) < 8:
        return jsonify({"ok": False, "msg": "Password must be at least 8 characters."})

    hashed = hash_password(password)
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)",
                       (username, email, hashed))
        ensure_user_data(username)
        return jsonify({"ok": True, "msg": "Account created successfully."})
    except sqlite3.IntegrityError as e:
        msg = "Username already taken." if "username" in str(e).lower() else "Email already registered."
        return jsonify({"ok": False, "msg": msg})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/forgot-password", methods=["POST"])
def api_forgot():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "msg": "Email required."})

    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u:
        return jsonify({"ok": True, "msg": "If that email is registered, a code has been sent."})

    code = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    expires = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    with get_db() as db:
        db.execute("INSERT OR REPLACE INTO verify_codes (email,code,expires_at) VALUES (?,?,?)",
                   (email, code, expires))

    html = f"""
    <div style="font-family:monospace;background:#0a0a0f;color:#e2e8f0;padding:30px;border-radius:12px">
      <h2 style="color:#a855f7">Vhaw_X_limon Password Reset</h2>
      <p style="margin-top:16px">Your reset code:</p>
      <div style="font-size:36px;font-weight:900;letter-spacing:8px;color:#06b6d4;margin:20px 0">{code}</div>
      <p style="color:#64748b;font-size:13px">This code expires in 15 minutes.</p>
    </div>
    """
    send_email(email, "Vhaw_X_limon &mdash; Password Reset Code", html)
    return jsonify({"ok": True, "msg": "If that email is registered, a code has been sent."})

@app.route("/api/reset-password", methods=["POST"])
def api_reset():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()
    password = data.get("password") or ""

    if not email or not code or not password:
        return jsonify({"ok": False, "msg": "All fields required."})
    if len(password) < 8:
        return jsonify({"ok": False, "msg": "Password must be at least 8 characters."})

    with get_db() as db:
        row = db.execute("SELECT * FROM verify_codes WHERE email=?", (email,)).fetchone()

    if not row:
        return jsonify({"ok": False, "msg": "No reset code found. Request a new one."})
    if row["code"] != code:
        return jsonify({"ok": False, "msg": "Invalid code."})
    if datetime.utcnow().isoformat() > row["expires_at"]:
        return jsonify({"ok": False, "msg": "Code expired. Request a new one."})

    hashed = hash_password(password)
    with get_db() as db:
        db.execute("UPDATE users SET password=? WHERE email=?", (hashed, email))
        db.execute("DELETE FROM verify_codes WHERE email=?", (email,))
    return jsonify({"ok": True, "msg": "Password reset successful."})


# ══════════════════════════════════════════════════════════════════════════════
#  API: PANEL (PROCESS, TERMINAL, FILES, STATUS, CREDS)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/process/<action>", methods=["POST"])
@login_required
def api_process(action):
    u = current_user()
    if action == "start":
        ok, msg = start_user_process(u)
    elif action == "stop":
        ok, msg = stop_user_process(u)
    elif action == "restart":
        ok, msg = restart_user_process(u)
    elif action == "force_stop":
        ok, msg = stop_user_process(u, force=True)
    else:
        return jsonify({"ok": False, "msg": "Unknown action."})
    return jsonify({"ok": ok, "msg": msg})

@app.route("/api/terminal/output")
@login_required
def api_terminal_output():
    u = current_user()
    from_idx = int(request.args.get("from", 0))
    with user_process_lock(u):
        lines = list(user_output.get(u, []))
    new_lines = lines[from_idx:]
    status = process_status(u)
    return jsonify({"ok": True, "lines": new_lines, "total": len(lines), "status": status})

@app.route("/api/credentials", methods=["POST"])
@login_required
def api_save_creds():
    u = current_user()
    data = request.get_json(silent=True) or {}
    uid = (data.get("uid") or "").strip()
    pwd = (data.get("password") or "").strip()
    owner_uid = (data.get("owner_uid") or "").strip()
    owner_name = (data.get("owner_name") or "").strip()

    if not uid or not pwd:
        return jsonify({"ok": False, "msg": "UID and password are required."})

    # Store in DB
    with get_db() as db:
        db.execute(
            """INSERT OR REPLACE INTO credentials (username,uid,password,owner_uid,owner_name,updated_at)
               VALUES (?,?,?,?,?,?)""",
            (u, uid, pwd, owner_uid, owner_name, datetime.utcnow().isoformat())
        )

    # Copy TCP files
    try:
        copy_tcp_to_user(u)
        write_rizer_txt(u, uid, pwd)
    except Exception as e:
        log.error(f"File copy error for {u}: {e}")
        return jsonify({"ok": False, "msg": f"File copy error: {e}"})

    # Update Vhaw.py with owner info
    if owner_uid or owner_name:
        ok, msg = update_rizer4_owner(u, owner_uid or None, owner_name or None)
        if not ok:
            log.warning(f"Vhaw.py owner update for {u}: {msg}")

    # Auto-generate JWT token
    ok, msg, jwt = generate_jwt_for_user(u)
    if ok:
        log.info(f"JWT auto-generated for {u}")
    else:
        log.warning(f"JWT auto-gen failed for {u}: {msg}")

    return jsonify({"ok": True, "msg": "Credentials saved, files synced, token generated."})

@app.route("/api/credentials/check")
@login_required
def api_check_creds():
    creds = get_user_creds(current_user())
    set_ = bool(creds and creds.get("uid") and creds.get("password"))
    return jsonify({"ok": True, "set": set_})

@app.route("/api/files")
@login_required
def api_files():
    u = current_user()
    dest = DATA_DIR / u
    if not dest.exists():
        return jsonify({"ok": True, "files": []})
    files = []
    for item in sorted(dest.iterdir(), key=lambda x: (x.is_file(), x.name)):
        size = ""
        if item.is_file():
            b = item.stat().st_size
            size = f"{b / 1024:.1f} KB" if b >= 1024 else f"{b} B"
        files.append({"name": item.name, "is_dir": item.is_dir(), "size": size})
    return jsonify({"ok": True, "files": files})

@app.route("/api/status")
@login_required
def api_status():
    u = current_user()
    creds = get_user_creds(u)
    jwt_token = load_jwt_token(u)
    return jsonify({
        "ok": True,
        "process": process_status(u),
        "creds_set": bool(creds and creds.get("uid") and creds.get("password")),
        "jwt_ok": bool(jwt_token)
    })

@app.route("/api/broadcasts")
@login_required
def api_broadcasts():
    return jsonify({"ok": True, "messages": broadcasts[-5:]})


# ══════════════════════════════════════════════════════════════════════════════
#  API: 13 TOOLS FROM GAY.PY
# ══════════════════════════════════════════════════════════════════════════════
def _ensure_jwt():
    u = current_user()
    token = load_jwt_token(u)
    if not token:
        ok, msg, token = generate_jwt_for_user(u)
        if not ok or not token:
            return None, msg or "Failed to generate JWT token. Check credentials."
    return token, None

@app.route("/api/tools/nickname", methods=["POST"])
@login_required
def tool_nickname():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "msg": "Nickname required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    ok, msg = change_nickname(jwt, name)
    return jsonify({"ok": ok, "msg": msg})

@app.route("/api/tools/login-history")
@login_required
def tool_login_history():
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    logins = fetch_login_history(jwt)
    if logins is None:
        return jsonify({"ok": False, "msg": "Failed to fetch login history."})
    return jsonify({"ok": True, "logins": logins})

@app.route("/api/tools/friends")
@login_required
def tool_friends():
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    friends, info = get_friend_list_from_jwt(jwt)
    if friends is None:
        return jsonify({"ok": False, "msg": str(info)})
    return jsonify({"ok": True, "friends": friends, "my_info": info})

@app.route("/api/tools/profile-items", methods=["POST"])
@login_required
def tool_profile_items():
    data = request.get_json(silent=True) or {}
    items = (data.get("items") or "").strip()
    if not items:
        items = PROFILE_DEFAULT_ITEMS
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    ok, msg = add_profile_items(jwt, items)
    return jsonify({"ok": ok, "msg": msg})

@app.route("/api/tools/wishlist", methods=["POST"])
@login_required
def tool_wishlist():
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    results = add_wishlist_batch(jwt, WISHLIST_ITEMS, max_workers=50)
    return jsonify({
        "ok": True,
        "success_count": len(results["success"]),
        "fail_count": len(results["failed"]),
        "failed_items": results["failed"][:10]
    })

@app.route("/api/tools/craftland/subscribe", methods=["POST"])
@login_required
def tool_craft_subscribe():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    region = (data.get("region") or "BD").strip()
    if not code:
        return jsonify({"ok": False, "msg": "Map code required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    ok, msg = subscribe_craftland(jwt, code, region)
    return jsonify({"ok": ok, "msg": msg})

@app.route("/api/tools/craftland/info")
@login_required
def tool_craft_info():
    code = (request.args.get("code") or "").strip()
    region = (request.args.get("region") or "BD").strip()
    if not code:
        return jsonify({"ok": False, "msg": "Map code required."})
    info, err = get_craftland_info(code, region)
    if err:
        return jsonify({"ok": False, "msg": err})
    return jsonify({"ok": True, "info": info})

@app.route("/api/tools/player-info")
@login_required
def tool_player_info():
    target_uid = (request.args.get("uid") or "").strip()
    if not target_uid:
        return jsonify({"ok": False, "msg": "UID required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    info, region = get_player_info(jwt, target_uid)
    if info is None:
        return jsonify({"ok": False, "msg": region})
    return jsonify({"ok": True, "info": info, "region": region})

@app.route("/api/tools/bio", methods=["POST"])
@login_required
def tool_bio():
    data = request.get_json(silent=True) or {}
    bio = (data.get("bio") or "").strip()
    if not bio:
        return jsonify({"ok": False, "msg": "Bio text required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    ok, msg = change_bio(jwt, bio)
    return jsonify({"ok": ok, "msg": msg})

@app.route("/api/tools/friend/add", methods=["POST"])
@login_required
def tool_friend_add():
    data = request.get_json(silent=True) or {}
    target = (data.get("target_uid") or "").strip()
    if not target:
        return jsonify({"ok": False, "msg": "Target UID required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    ok, msg = send_friend_request(jwt, target)
    return jsonify({"ok": ok, "msg": msg})

@app.route("/api/tools/friend/remove", methods=["POST"])
@login_required
def tool_friend_remove():
    data = request.get_json(silent=True) or {}
    target = (data.get("target_uid") or "").strip()
    if not target:
        return jsonify({"ok": False, "msg": "Target UID required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    ok, msg = remove_friend(jwt, target)
    return jsonify({"ok": ok, "msg": msg})

@app.route("/api/tools/guild/join", methods=["POST"])
@login_required
def tool_guild_join():
    data = request.get_json(silent=True) or {}
    clan_id = (data.get("clan_id") or "").strip()
    region = (data.get("region") or "BD").strip()
    if not clan_id:
        return jsonify({"ok": False, "msg": "Clan ID required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    ok, msg = join_guild(jwt, clan_id, region)
    return jsonify({"ok": ok, "msg": msg})

@app.route("/api/tools/guild/leave", methods=["POST"])
@login_required
def tool_guild_leave():
    data = request.get_json(silent=True) or {}
    clan_id = (data.get("clan_id") or "").strip()
    region = (data.get("region") or "BD").strip()
    if not clan_id:
        return jsonify({"ok": False, "msg": "Clan ID required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    ok, msg = leave_guild(jwt, clan_id, region)
    return jsonify({"ok": ok, "msg": msg})

@app.route("/api/tools/guild/info")
@login_required
def tool_guild_info():
    clan_id = (request.args.get("clan_id") or "").strip()
    region = (request.args.get("region") or "BD").strip()
    if not clan_id:
        return jsonify({"ok": False, "msg": "Clan ID required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    info, emsg = get_clan_info_sync(jwt, clan_id, region)
    if info is None:
        return jsonify({"ok": False, "msg": emsg})
    str_info = {k: str(v) for k, v in info.items()}
    return jsonify({"ok": True, "info": str_info})

@app.route("/api/tools/guild/members")
@login_required
def tool_guild_members():
    clan_id = (request.args.get("clan_id") or "").strip()
    region = (request.args.get("region") or "BD").strip()
    if not clan_id:
        return jsonify({"ok": False, "msg": "Clan ID required."})
    jwt, err = _ensure_jwt()
    if err:
        return jsonify({"ok": False, "msg": err})
    members, emsg = get_clan_members_sync(jwt, clan_id, region)
    if members is None:
        return jsonify({"ok": False, "msg": emsg})
    return jsonify({"ok": True, "members": members})


# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN PAGES & API
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin", methods=["GET"])
def admin_root():
    if session.get("is_admin"):
        return render_template_string(ADMIN_HTML)
    body = """
    <div class="auth-card fade-in">
      <h2>&#128737; Admin Login</h2>
      <div id="flash"></div>
      <div class="field"><label>USERNAME</label><input id="au" type="text" placeholder="@rizer"></div>
      <div class="field"><label>PASSWORD</label><input id="ap" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;"></div>
      <button class="btn" style="width:100%" onclick="doAdmin()">Access Admin &rarr;</button>
    </div>
    <script>
    async function doAdmin(){
      const u=document.getElementById('au').value.trim();
      const p=document.getElementById('ap').value;
      const res=await fetch('/admin/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
      const d=await res.json();
      if(d.ok) location.reload();
      else document.getElementById('flash').innerHTML='<div class="flash flash-err">'+d.msg+'</div>';
    }
    document.addEventListener('keydown',e=>{if(e.key==='Enter')doAdmin()});
    </script>
    """
    return render_auth("Admin", body)

@app.route("/admin/login")
def admin_login_page():
    return redirect("/admin")

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("is_admin", None)
    return jsonify({"ok": True})

@app.route("/admin/api/login", methods=["POST"])
def admin_api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not isinstance(username, str):
        username = str(username) if username else ""
    if not isinstance(password, str):
        password = str(password) if password else ""
    if username == ADMIN_USER and password == ADMIN_PASS:
        session.permanent = True
        session["is_admin"] = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Invalid admin credentials."})

@app.route("/admin/api/users")
@admin_required
def admin_users():
    with get_db() as db:
        rows = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    users = []
    for u in rows:
        ud = dict(u)
        ud["process"] = process_status(u["username"])
        users.append(ud)
    return jsonify({"ok": True, "users": users})

@app.route("/admin/api/user-action", methods=["POST"])
@admin_required
def admin_user_action():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    action = data.get("action", "")

    if not username:
        return jsonify({"ok": False, "msg": "Username required."})

    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u:
        return jsonify({"ok": False, "msg": "User not found."})

    if action == "block":
        with get_db() as db:
            db.execute("UPDATE users SET is_blocked=1 WHERE username=?", (username,))
        return jsonify({"ok": True, "msg": f"{username} blocked."})

    elif action == "unblock":
        with get_db() as db:
            db.execute("UPDATE users SET is_blocked=0 WHERE username=?", (username,))
        return jsonify({"ok": True, "msg": f"{username} unblocked."})

    elif action == "ban":
        with get_db() as db:
            db.execute("UPDATE users SET is_banned=1, is_blocked=0 WHERE username=?", (username,))
        stop_user_process(username, force=True)
        return jsonify({"ok": True, "msg": f"{username} banned and session stopped."})

    elif action == "unban":
        with get_db() as db:
            db.execute("UPDATE users SET is_banned=0 WHERE username=?", (username,))
        return jsonify({"ok": True, "msg": f"{username} unbanned."})

    elif action == "stop_session":
        ok, msg = stop_user_process(username, force=True)
        return jsonify({"ok": True, "msg": f"Session stopped for {username}: {msg}"})

    elif action == "remove":
        stop_user_process(username, force=True)
        dest = DATA_DIR / username
        if dest.exists():
            shutil.rmtree(dest)
        with get_db() as db:
            db.execute("DELETE FROM users WHERE username=?", (username,))
            db.execute("DELETE FROM credentials WHERE username=?", (username,))
        jwt_cache.pop(username, None)
        return jsonify({"ok": True, "msg": f"{username} removed completely."})

    return jsonify({"ok": False, "msg": "Unknown action."})

@app.route("/admin/api/broadcast", methods=["POST"])
@admin_required
def admin_broadcast():
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"ok": False, "msg": "Content required."})
    broadcasts.append({"content": content, "ts": datetime.utcnow().isoformat()})
    while len(broadcasts) > 20:
        broadcasts.pop(0)
    return jsonify({"ok": True, "msg": "Broadcast sent."})

@app.route("/admin/api/broadcast/clear", methods=["POST"])
@admin_required
def admin_broadcast_clear():
    broadcasts.clear()
    return jsonify({"ok": True, "msg": "Broadcasts cleared."})

@app.route("/admin/api/broadcasts")
@admin_required
def admin_get_broadcasts():
    return jsonify({"ok": True, "messages": broadcasts})

@app.route("/admin/api/smtp", methods=["GET", "POST"])
@admin_required
def admin_smtp():
    global _admin_smtp, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
    if request.method == "GET":
        safe = {k: v for k, v in _admin_smtp.items() if k != "pass"}
        return jsonify({"ok": True, "config": safe})
    data = request.get_json(silent=True) or {}
    _admin_smtp = {
        "host": data.get("host", SMTP_HOST),
        "port": int(data.get("port", SMTP_PORT)),
        "user": data.get("user", SMTP_USER),
        "pass": data.get("pass", SMTP_PASS),
        "from": data.get("from", SMTP_FROM),
    }
    SMTP_HOST = _admin_smtp["host"]
    SMTP_PORT = _admin_smtp["port"]
    SMTP_USER = _admin_smtp["user"]
    SMTP_PASS = _admin_smtp["pass"]
    SMTP_FROM = _admin_smtp["from"]
    return jsonify({"ok": True, "msg": "SMTP settings saved."})

@app.route("/admin/api/smtp/test", methods=["POST"])
@admin_required
def admin_smtp_test():
    data = request.get_json(silent=True) or {}
    to = (data.get("to") or "").strip()
    if not to:
        return jsonify({"ok": False, "msg": "Test email address required."})
    ok = send_email(to, "Vhaw_X_limon SMTP Test", "<h2>SMTP is working &#9989;</h2><p>Sent from Vhaw_X_limon Panel.</p>")
    return jsonify({"ok": ok, "msg": "Test email sent." if ok else "Email failed -- check SMTP settings."})

@app.route("/admin/api/maintenance", methods=["GET", "POST"])
@admin_required
def admin_maintenance():
    global maintenance_mode
    if request.method == "POST":
        maintenance_mode = not maintenance_mode
        return jsonify({"ok": True, "maintenance": maintenance_mode,
                        "msg": f"Maintenance mode {'ON' if maintenance_mode else 'OFF'}."})
    return jsonify({"ok": True, "maintenance": maintenance_mode})

@app.route("/admin/api/stop-all", methods=["POST"])
@admin_required
def admin_stop_all():
    stopped = []
    for username in list(user_processes.keys()):
        stop_user_process(username, force=True)
        stopped.append(username)
    return jsonify({"ok": True, "msg": f"Stopped {len(stopped)} session(s): {', '.join(stopped) or 'none'}."})

@app.route("/admin/api/shutdown", methods=["POST"])
@admin_required
def admin_shutdown():
    def _shutdown():
        time.sleep(1)
        os.kill(os.getpid(), 15)
    threading.Thread(target=_shutdown, daemon=True).start()
    return jsonify({"ok": True, "msg": "Server shutting down."})

# ══════════════════════════════════════════════════════════════════════════════
#  ENHANCED LOGGING & ERROR RECOVERY
# ══════════════════════════════════════════════════════════════════════════════
def log_system_event(event_type: str, details: str, username: str = None):
    """Log a system event with structured data."""
    user_info = f" [user={username}]" if username else ""
    log.info(f"[SYS:{event_type}]{user_info} {details}")

def safe_json_response(data: dict, status_code: int = 200):
    """Safely return a JSON response with proper headers."""
    response = jsonify(data)
    response.status_code = status_code
    response.headers['Content-Type'] = 'application/json'
    return response


def handle_graceful_shutdown(signum, frame):
    """Handle shutdown signals gracefully."""
    log.info("Received shutdown signal. Stopping all user processes...")
    for username in list(user_processes.keys()):
        try:
            stop_user_process(username, force=True)
        except Exception as e:
            log.error(f"Error stopping {username}: {e}")
    log.info("All processes stopped. Exiting.")
    sys.exit(0)

# Register signal handlers for graceful shutdown
import signal
try:
    signal.signal(signal.SIGTERM, handle_graceful_shutdown)
    signal.signal(signal.SIGINT, handle_graceful_shutdown)
except Exception:
    pass  # Signal handling may not work on all platforms


# ══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL ADMIN FEATURES
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/api/user-detail/<username>")
@admin_required
def admin_user_detail(username):
    """Get detailed information about a specific user."""
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        creds = db.execute("SELECT * FROM credentials WHERE username=?", (username,)).fetchone()
    if not u:
        return jsonify({"ok": False, "msg": "User not found."})
    user_data = dict(u)
    user_data["process_status"] = process_status(username)
    user_data["has_creds"] = creds is not None
    if creds:
        user_data["has_uid"] = bool(creds.get("uid"))
        user_data["has_password"] = bool(creds.get("password"))
        user_data["creds_updated"] = creds.get("updated_at")
    else:
        user_data["has_uid"] = False
        user_data["has_password"] = False
        user_data["creds_updated"] = None
    return jsonify({"ok": True, "user": user_data})


@app.route("/admin/api/send-email", methods=["POST"])
@admin_required
def admin_send_email():
    """Send an email to a specific user or all users."""
    data = request.get_json(silent=True) or {}
    to = (data.get("to") or "").strip()
    subject = (data.get("subject") or "").strip()
    html_body = (data.get("html") or "").strip()
    if not to or not subject or not html_body:
        return jsonify({"ok": False, "msg": "To, subject, and HTML body are required."})
    ok = send_email(to, subject, html_body)
    return jsonify({"ok": ok, "msg": "Email sent." if ok else "Email failed."})


@app.route("/admin/api/user-count")
@admin_required
def admin_user_count():
    """Get user counts by status."""
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        active = db.execute("SELECT COUNT(*) as c FROM users WHERE is_banned=0 AND is_blocked=0").fetchone()["c"]
        banned = db.execute("SELECT COUNT(*) as c FROM users WHERE is_banned=1").fetchone()["c"]
        blocked = db.execute("SELECT COUNT(*) as c FROM users WHERE is_blocked=1").fetchone()["c"]
    return jsonify({"ok": True, "counts": {"total": total, "active": active, "banned": banned, "blocked": blocked}})


@app.route("/admin/api/list-sessions")
@admin_required
def admin_list_sessions():
    """List all active user sessions/processes."""
    sessions = []
    for username, proc in user_processes.items():
        is_running = proc.poll() is None
        sessions.append({
            "username": username,
            "running": is_running,
            "pid": proc.pid if hasattr(proc, 'pid') else None
        })
    return jsonify({"ok": True, "sessions": sessions, "count": len(sessions)})


@app.route("/admin/api/restart-user/<username>", methods=["POST"])
@admin_required
def admin_restart_user(username):
    """Restart a specific user's process."""
    ok, msg = restart_user_process(username)
    return jsonify({"ok": ok, "msg": msg})


@app.route("/admin/api/clear-jwt/<username>", methods=["POST"])
@admin_required
def admin_clear_jwt(username):
    """Clear JWT token cache for a user."""
    clear_jwt_token(username)
    return jsonify({"ok": True, "msg": f"JWT cache cleared for {username}."})


# ══════════════════════════════════════════════════════════════════════════════
#  REQUEST LOGGING MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════════════
@app.after_request
def after_request(response):
    """Log all requests for monitoring."""
    if not request.path.startswith('/static/'):
        log.debug(f"{request.remote_addr} - {request.method} {request.path} - {response.status_code}")
    return response




# ══════════════════════════════════════════════════════════════════════════════
#  JWT AUTO-REFRESH BACKGROUND THREAD (Every 6 hours)
# ══════════════════════════════════════════════════════════════════════════════
def jwt_refresh_worker():
    while True:
        time.sleep(21600)  # 6 hours
        try:
            with get_db() as db:
                rows = db.execute("SELECT username, uid, password FROM credentials WHERE uid IS NOT NULL AND password IS NOT NULL").fetchall()
            for row in rows:
                username = row["username"]
                uid = row["uid"]
                pwd = row["password"]
                try:
                    ok, _, jwt = _process_credentials_internal(uid, pwd)
                    if ok and jwt:
                        save_jwt_token(username, jwt)
                        log.info(f"Auto-refreshed JWT for {username}")
                except Exception as e:
                    log.error(f"JWT refresh failed for {username}: {e}")
        except Exception as e:
            log.error(f"JWT refresh worker error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK ENDPOINT (for Railway/proxy monitoring)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/health")
def health_check():
    """Health check endpoint for Railway and load balancers."""
    return jsonify({
        "ok": True,
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "maintenance": maintenance_mode,
        "users_online": len(user_processes),
        "version": "2.1.0"
    })

@app.route("/ping")
def ping():
    """Simple ping endpoint."""
    return jsonify({"ok": True, "pong": True})


# ══════════════════════════════════════════════════════════════════════════════
#  USER DATA BACKUP / RESTORE API (Admin only)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/api/backup/<username>", methods=["POST"])
@admin_required
def admin_backup_user(username):
    """Create a zip backup of a user's data directory."""
    import zipfile
    dest = DATA_DIR / username
    if not dest.exists():
        return jsonify({"ok": False, "msg": "User data not found."})
    try:
        backup_path = DATA_DIR / f"{username}_backup.zip"
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for item in dest.rglob("*"):
                if item.is_file():
                    zf.write(item, item.relative_to(dest.parent))
        return jsonify({"ok": True, "msg": f"Backup created: {backup_path.name}"})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})

@app.route("/admin/api/stats")
@admin_required
def admin_stats():
    """Get server statistics."""
    with get_db() as db:
        total_users = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        banned_users = db.execute("SELECT COUNT(*) as c FROM users WHERE is_banned=1").fetchone()["c"]
        blocked_users = db.execute("SELECT COUNT(*) as c FROM users WHERE is_blocked=1").fetchone()["c"]
    return jsonify({
        "ok": True,
        "stats": {
            "total_users": total_users,
            "banned_users": banned_users,
            "blocked_users": blocked_users,
            "online_processes": len(user_processes),
            "maintenance_mode": maintenance_mode,
            "broadcast_count": len(broadcasts),
            "db_path": str(DB_PATH),
            "data_dir": str(DATA_DIR),
            "tcp_dir": str(TCP_DIR)
        }
    })


# ══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL ADMIN: Close / Remove All Sessions
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/api/close-all", methods=["POST"])
@admin_required
def admin_close_all():
    """Close all user sessions (stop all processes) and optionally clear data."""
    data = request.get_json(silent=True) or {}
    also_remove_data = bool(data.get("also_remove_data", False))
    stopped = []
    errors = []
    for username in list(user_processes.keys()):
        try:
            stop_user_process(username, force=True)
            stopped.append(username)
            if also_remove_data:
                dest = DATA_DIR / username
                if dest.exists():
                    shutil.rmtree(dest)
        except Exception as e:
            errors.append(f"{username}: {e}")
    msg = f"Stopped {len(stopped)} session(s)"
    if also_remove_data:
        msg += " and removed data"
    if errors:
        msg += f". Errors: {len(errors)}"
    return jsonify({"ok": True, "msg": msg, "stopped": stopped, "errors": errors})


# ══════════════════════════════════════════════════════════════════════════════
#  RAILWAY COMPATIBILITY: Bind to PORT env var
# ══════════════════════════════════════════════════════════════════════════════
def get_railway_port():
    """Get the port from Railway environment or default."""
    return int(os.getenv("PORT", os.getenv("RAILWAY_PORT", "5000")))


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    DATA_DIR.mkdir(exist_ok=True)
    TCP_DIR.mkdir(exist_ok=True)
    init_db()

    # Start JWT auto-refresh thread
    t = threading.Thread(target=jwt_refresh_worker, daemon=True)
    t.start()

    log.info("=" * 60)
    log.info("  Vhaw_X_limon PANEL -- All-in-One Edition Starting")
    log.info(f"  DB        : {DB_PATH}")
    log.info(f"  TCP src   : {TCP_DIR.resolve()}")
    log.info(f"  DATA dir  : {DATA_DIR.resolve()}")
    log.info(f"  Admin     : GET /admin  ({ADMIN_USER} / {ADMIN_PASS})")
    log.info(f"  Tools     : 13 gay.py features via API")
    log.info(f"  JWT       : Auto-save to token.txt, refresh every 6h")
    log.info(f"  Mobile    : Hamburger 3-line menu, fullscreen support")
    log.info("=" * 60)

    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
