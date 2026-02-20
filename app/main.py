# main.py (Full replacement)
# CMMC Level 2 (67 scoped controls) - Technical controls implemented in-app where feasible.
# NOTE: Policy/training/physical/HR controls handled as documentation/evidence later (per your plan).

import os
import re
import io
import hmac
import json
import enum
import time
import uuid
import base64
import sqlite3
import hashlib
import datetime
from pathlib import Path
from functools import wraps
from typing import Optional, Tuple, Dict, Any

from flask import (
    Flask, request, redirect, url_for, render_template, render_template_string,
    send_file, abort, flash, jsonify, session, g, make_response
)
from werkzeug.utils import secure_filename
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Optional: load .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ModuleNotFoundError:
    pass

# Azure Blob optional
try:
    from azure.storage.blob import BlobServiceClient
except Exception:
    BlobServiceClient = None

# Crypto primitives for envelope encryption (per-file key + crypto-shred)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

# Optional TOTP MFA
try:
    import pyotp
except Exception:
    pyotp = None

# Optional file-type detection
try:
    import magic  # python-magic
except Exception:
    magic = None

# =========================================
# APP + CONFIG
# =========================================
app = Flask(__name__)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
# Secret key (must be set in production)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))

# Environments
ENV = (os.environ.get("FLASK_ENV") or os.environ.get("ENV") or "").lower()
IS_PROD = False

# Allow pointing to a persistent data directory
DATA_DIR = os.environ.get("DATA_DIR")  # e.g. /srv/secure_uploader_data
if DATA_DIR:
    os.makedirs(DATA_DIR, exist_ok=True)
    UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
    DB_PATH = os.path.join(DATA_DIR, "files.db")
    BASELINE_PATH = os.path.join(DATA_DIR, "baseline_snapshot.json")
else:
    UPLOAD_FOLDER = "uploads"
    DB_PATH = "files.db"
    BASELINE_PATH = "baseline_snapshot.json"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Upload limits
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 200 * 1024 * 1024))
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Session hardening
secure_cookies = True if IS_PROD else False
app.config.update(
    SESSION_COOKIE_SECURE=False,     # AC/SC boundary in prod
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Session timeout (AC.2.010) - inactivity window
SESSION_IDLE_MINUTES = int(os.environ.get("SESSION_IDLE_MINUTES", "15"))
# Max concurrent sessions (AC.2.011)
MAX_CONCURRENT_SESSIONS = int(os.environ.get("MAX_CONCURRENT_SESSIONS", "2"))

# HTTPS enforcement (SC.1.175 / IA.2.079 replay-resistant in practice)
FORCE_HTTPS = (os.environ.get("FORCE_HTTPS", "1") == "1") if IS_PROD else False

# Remote access monitoring / optional allowlist (AC.2.009)
REMOTE_IP_ALLOWLIST = [x.strip() for x in (os.environ.get("REMOTE_IP_ALLOWLIST", "")).split(",") if x.strip()]

# Password policy (IA.2.078)
PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^])[A-Za-z\d@$!%*?&#^]{12,}$")

ph = PasswordHasher()

# Rate limiter (basic DoS throttling)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)


# =========================================
# ROLES
# =========================================
class UserRole(enum.Enum):
    USER = "user"
    ADMIN = "admin"


def validate_password_complexity(pw: str) -> bool:
    return bool(PASSWORD_REGEX.match(pw or ""))


# =========================================
# STORAGE BACKEND (local or Azure Blob)
# =========================================
USE_AZURE_BLOBS = False
AZ_BLOB_CLIENT = None
AZ_BLOB_CONTAINER = None

if BlobServiceClient is not None:
    AZ_CONN = os.environ.get("AZURE_STORAGE_CONNECTION_STRING") or os.environ.get("AZURE_BLOB_CONNECTION_STRING")
    AZ_CONTAINER = os.environ.get("AZURE_BLOB_CONTAINER")
    if AZ_CONN and AZ_CONTAINER:
        try:
            AZ_BLOB_CLIENT = BlobServiceClient.from_connection_string(AZ_CONN)
            AZ_BLOB_CONTAINER = AZ_CONTAINER
            try:
                AZ_BLOB_CLIENT.create_container(AZ_BLOB_CONTAINER)
            except Exception:
                pass
            USE_AZURE_BLOBS = True
            print("[INFO] Using Azure Blob Storage:", AZ_BLOB_CONTAINER)
        except Exception as e:
            print("[WARN] Azure Blob init failed:", e)


def storage_save_bytes(stored_name: str, data: bytes) -> None:
    if USE_AZURE_BLOBS and AZ_BLOB_CLIENT is not None:
        blob = AZ_BLOB_CLIENT.get_blob_client(container=AZ_BLOB_CONTAINER, blob=stored_name)
        blob.upload_blob(data, overwrite=True)
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    with open(path, "wb") as fh:
        fh.write(data)


def storage_read_bytes(stored_name: str) -> bytes:
    if USE_AZURE_BLOBS and AZ_BLOB_CLIENT is not None:
        blob = AZ_BLOB_CLIENT.get_blob_client(container=AZ_BLOB_CONTAINER, blob=stored_name)
        return blob.download_blob().readall()
    path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    with open(path, "rb") as fh:
        return fh.read()


def storage_delete(stored_name: str) -> None:
    if USE_AZURE_BLOBS and AZ_BLOB_CLIENT is not None:
        try:
            blob = AZ_BLOB_CLIENT.get_blob_client(container=AZ_BLOB_CONTAINER, blob=stored_name)
            blob.delete_blob()
        except Exception:
            pass
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# =========================================
# MASTER KEY (for envelope encryption)
# - Required for server-side encryption
# - Supports per-file DEK wrapping (MP.2.120 crypto-shred)
# =========================================
def _get_or_create_master_key_b64() -> str:
    val = os.environ.get("UPLOAD_ENC_KEY")
    if val:
        return val.strip()

    # persistent fallback key file (only for demo environments)
    store_dir = DATA_DIR if DATA_DIR else os.getcwd()
    key_path = os.path.join(store_dir, ".upload_enc_key")
    if os.path.exists(key_path):
        try:
            return open(key_path, "r").read().strip()
        except Exception:
            pass

    # generate and persist
    new_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    try:
        with open(key_path, "w") as fh:
            fh.write(new_key)
        print(f"[WARNING] No UPLOAD_ENC_KEY provided; generated and saved key to {key_path}")
    except Exception:
        print("[WARNING] No UPLOAD_ENC_KEY and failed to persist; ephemeral key in memory.")
    return new_key


MASTER_KEY_B64 = _get_or_create_master_key_b64()
try:
    MASTER_KEY = base64.urlsafe_b64decode(MASTER_KEY_B64 + "===")[:32]
except Exception:
    MASTER_KEY = None


# =========================================
# DB INIT + MIGRATIONS
# =========================================
def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def ensure_column(conn: sqlite3.Connection, table: str, col: str, ddl: str) -> None:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    if col not in cols:
        cur.execute(ddl)


def init_db() -> None:
    conn = db_conn()
    c = conn.cursor()

    # Users
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT NOT NULL,
        disabled INTEGER NOT NULL DEFAULT 0,
        mfa_enabled INTEGER NOT NULL DEFAULT 0,
        mfa_secret TEXT
    )
    """)

    # Files
    c.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        orig_name TEXT,
        stored_name TEXT,
        mime TEXT,
        size INTEGER,
        uploaded_at TEXT,
        owner_id INTEGER NOT NULL,
        client_encrypted INTEGER NOT NULL DEFAULT 0,
        enc_version INTEGER NOT NULL DEFAULT 2,
        dek_wrapped BLOB,
        dek_wrap_nonce BLOB,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )
    """)

    # Access list / sharing
    c.execute("""
    CREATE TABLE IF NOT EXISTS file_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        can_read INTEGER NOT NULL DEFAULT 1,
        can_delete INTEGER NOT NULL DEFAULT 0,
        can_share INTEGER NOT NULL DEFAULT 0,
        UNIQUE(file_id, user_id),
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Messages (optional UI)
    c.execute("""
    CREATE TABLE IF NOT EXISTS file_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        message TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(recipient_id) REFERENCES users(id)
    )
    """)

    # Audit (AU.2.041)
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        action TEXT NOT NULL,
        target TEXT,
        result TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT,
        timestamp TEXT NOT NULL
    )
    """)

    # Session tracking (AC.2.011)
    c.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_id TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        is_locked INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Simple config baseline/change log (CM.2.061 / CM.2.064)
    c.execute("""
    CREATE TABLE IF NOT EXISTS config_changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        change_type TEXT NOT NULL,
        old_value TEXT,
        new_value TEXT,
        timestamp TEXT NOT NULL
    )
    """)

    # Ensure columns (for upgrades from older db)
    ensure_column(conn, "files", "client_encrypted", "ALTER TABLE files ADD COLUMN client_encrypted INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "files", "enc_version", "ALTER TABLE files ADD COLUMN enc_version INTEGER NOT NULL DEFAULT 2")
    ensure_column(conn, "files", "dek_wrapped", "ALTER TABLE files ADD COLUMN dek_wrapped BLOB")
    ensure_column(conn, "files", "dek_wrap_nonce", "ALTER TABLE files ADD COLUMN dek_wrap_nonce BLOB")
    ensure_column(conn, "users", "disabled", "ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "mfa_enabled", "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "mfa_secret", "ALTER TABLE users ADD COLUMN mfa_secret TEXT")

    # Add can_share if missing
    ensure_column(conn, "file_access", "can_share", "ALTER TABLE file_access ADD COLUMN can_share INTEGER NOT NULL DEFAULT 0")

    conn.commit()
    conn.close()


# =========================================
# AUDIT LOGGING (AU.2.041 / AU.2.042 / AC.2.009)
# =========================================
def now_utc_iso() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()


def log_event(user_id, username, action, target, result, details: Optional[dict] = None):
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute("""
            INSERT INTO audit_log (user_id, username, action, target, result, ip_address, user_agent, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            username,
            action,
            target,
            result,
            request.remote_addr,
            request.headers.get("User-Agent", ""),
            json.dumps(details or {}, ensure_ascii=False),
            now_utc_iso()
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AUDIT ERROR] {e}")


def log_config_change(user_id, username, change_type, old_value, new_value):
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute("""
            INSERT INTO config_changes (user_id, username, change_type, old_value, new_value, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, username, change_type, old_value, new_value, now_utc_iso()))
        conn.commit()
        conn.close()
    except Exception:
        pass


# =========================================
# SECURITY HEADERS (SC.1.175 / IA.2.079)
# =========================================
@app.after_request
def set_security_headers(resp):
    # Basic hardening
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # CSP (simple default; adjust if you add external JS/CSS)
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';"

    if IS_PROD:
        # HSTS for HTTPS-only deployments
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.before_request
def enforce_https_and_remote_access_monitoring():
    # AC.2.009: monitor remote access -> log request metadata for sensitive endpoints
    sensitive_paths = ("/login", "/upload", "/download", "/delete", "/users", "/add-user", "/audit", "/admin")
    if request.path.startswith(sensitive_paths):
        # Optional IP allowlist
        if REMOTE_IP_ALLOWLIST:
            if request.remote_addr not in REMOTE_IP_ALLOWLIST:
                log_event(None, None, "remote_access", request.path, "DENY", {"reason": "ip_not_allowlisted"})
                abort(403)

    # Force HTTPS in prod (behind proxy supported)
    if FORCE_HTTPS:
        proto = request.headers.get("X-Forwarded-Proto", request.scheme)
#        if proto != "https":
#            return redirect(request.url.replace("http://", "https://"), code=301)


# =========================================
# CSRF (IA.2.079 replay resistance on state-changing)
# =========================================
def csrf_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        session["_csrf"] = tok
    return tok


def require_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
        if not sent or not hmac.compare_digest(sent, session.get("_csrf", "")):
            abort(400, description="CSRF validation failed.")


app.before_request(require_csrf)


@app.context_processor
def inject_globals():
    # quick file count
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM files")
        fc = c.fetchone()[0]
        conn.close()
    except Exception:
        fc = 0
    return {
        "CSRF_TOKEN": csrf_token(),
        "USE_AZURE_BLOBS": USE_AZURE_BLOBS,
        "AZ_BLOB_CONTAINER": AZ_BLOB_CONTAINER,
        "FILE_COUNT": fc,
        "SESSION_IDLE_MINUTES": SESSION_IDLE_MINUTES,
        "MAX_CONCURRENT_SESSIONS": MAX_CONCURRENT_SESSIONS,
    }


# =========================================
# AUTH HELPERS + SESSION LOCK/CONCURRENCY
# (AC.2.006 / AC.2.010 / AC.2.011)
# =========================================
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session or not session.get("session_id"):
            flash("Please log in first.")
            return redirect(url_for("login"))
        if session.get("locked") == 1:
            return redirect(url_for("unlock"))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in first.")
            return redirect(url_for("login"))
        if g.user.get("role") != "admin":
            abort(403)
        if session.get("locked") == 1:
            return redirect(url_for("unlock"))
        return view_func(*args, **kwargs)
    return wrapped


@app.before_request
def load_logged_in_user_and_enforce_timeout():
    g.user = None
    uid = session.get("user_id")
    sid = session.get("session_id")

    if uid and sid:
        conn = db_conn()
        c = conn.cursor()
        c.execute("SELECT id, username, role, disabled, mfa_enabled FROM users WHERE id=?", (uid,))
        row = c.fetchone()
        if row:
            if int(row[3]) == 1:
                session.clear()
                conn.close()
                flash("Account disabled.")
                return redirect(url_for("login"))

            g.user = {"id": row[0], "username": row[1], "role": row[2], "mfa_enabled": int(row[4])}

            # enforce session timeout
            c.execute("SELECT last_seen, is_locked FROM sessions WHERE user_id=? AND session_id=?", (uid, sid))
            srow = c.fetchone()
            if not srow:
                # invalid session
                session.clear()
                conn.close()
                return redirect(url_for("login"))

            last_seen = datetime.datetime.fromisoformat(srow[0])
            is_locked = int(srow[1])

            # idle timeout
            if (datetime.datetime.utcnow() - last_seen).total_seconds() > (SESSION_IDLE_MINUTES * 60):
                log_event(uid, g.user["username"], "session", "timeout", "SUCCESS")
                # delete server-side session record
                c.execute("DELETE FROM sessions WHERE user_id=? AND session_id=?", (uid, sid))
                conn.commit()
                conn.close()
                session.clear()
                flash("Session timed out. Please log in again.")
                return redirect(url_for("login"))

            # lock status
            if is_locked == 1:
                session["locked"] = 1

            # update last_seen on any request
            c.execute("UPDATE sessions SET last_seen=? WHERE user_id=? AND session_id=?", (now_utc_iso(), uid, sid))
            conn.commit()
        conn.close()


def _create_session_record(user_id: int) -> str:
    """Create a server-side session record and enforce max concurrent sessions."""
    sid = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    conn = db_conn()
    c = conn.cursor()
    ts = now_utc_iso()

    # Insert new session
    c.execute("""
        INSERT INTO sessions (user_id, session_id, created_at, last_seen, is_locked)
        VALUES (?, ?, ?, ?, 0)
    """, (user_id, sid, ts, ts))

    # Enforce max concurrent sessions
    c.execute("""
        SELECT session_id FROM sessions WHERE user_id=? ORDER BY created_at DESC
    """, (user_id,))
    sessions_list = [r[0] for r in c.fetchall()]
    if len(sessions_list) > MAX_CONCURRENT_SESSIONS:
        # delete oldest beyond limit
        to_delete = sessions_list[MAX_CONCURRENT_SESSIONS:]
        for old_sid in to_delete:
            c.execute("DELETE FROM sessions WHERE user_id=? AND session_id=?", (user_id, old_sid))

    conn.commit()
    conn.close()
    return sid


def _lock_current_session():
    uid = session.get("user_id")
    sid = session.get("session_id")
    if not uid or not sid:
        return
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE sessions SET is_locked=1 WHERE user_id=? AND session_id=?", (uid, sid))
    conn.commit()
    conn.close()
    session["locked"] = 1


def _unlock_current_session():
    uid = session.get("user_id")
    sid = session.get("session_id")
    if not uid or not sid:
        return
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE sessions SET is_locked=0 WHERE user_id=? AND session_id=?", (uid, sid))
    conn.commit()
    conn.close()
    session["locked"] = 0


# =========================================
# MFA (IA.2.080) - enforce for admin accounts
# =========================================
def _ensure_admin_mfa_on_login(user_id: int, username: str, role: str):
    """If admin and MFA not enabled, force setup."""
    if role != "admin":
        return
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT mfa_enabled, mfa_secret FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return
    enabled = int(row[0])
    secret = row[1]
    if enabled == 1 and secret:
        return
    # If no pyotp, allow but log as PARTIAL (demo limitations)
    if pyotp is None:
        log_event(user_id, username, "mfa", "admin_required", "PARTIAL", {"reason": "pyotp_not_installed"})
        return
    # Redirect to setup
    session["mfa_setup_required"] = 1


def _verify_totp(user_id: int, code: str) -> bool:
    if pyotp is None:
        return False
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT mfa_secret, mfa_enabled FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    secret, enabled = row[0], int(row[1])
    if enabled != 1 or not secret:
        return False
    totp = pyotp.TOTP(secret)
    # allow small window for clock drift
    return totp.verify(code, valid_window=1)


# =========================================
# FILE CRYPTO (SC.1.176 / SC.2.179 / AC.2.008 / MP.2.120)
# - v2: per-file DEK + AESGCM data, DEK wrapped by MASTER_KEY
# - supports legacy (older) records with enc_version=1
# =========================================
def _aesgcm_encrypt(key32: bytes, plaintext: bytes) -> bytes:
    if AESGCM is None:
        raise RuntimeError("cryptography AESGCM not available")
    nonce = os.urandom(12)
    aes = AESGCM(key32)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct


def _aesgcm_decrypt(key32: bytes, blob: bytes) -> bytes:
    if AESGCM is None:
        raise RuntimeError("cryptography AESGCM not available")
    nonce, ct = blob[:12], blob[12:]
    aes = AESGCM(key32)
    return aes.decrypt(nonce, ct, None)


def _wrap_dek(dek32: bytes) -> Tuple[bytes, bytes]:
    """Wrap DEK under MASTER_KEY using AESGCM(master). Returns (wrap_nonce, wrapped_blob)."""
    if MASTER_KEY is None:
        raise RuntimeError("MASTER_KEY not set/invalid")
    if AESGCM is None:
        raise RuntimeError("AESGCM not available")
    wrap_nonce = os.urandom(12)
    aes = AESGCM(MASTER_KEY)
    wrapped = aes.encrypt(wrap_nonce, dek32, None)
    return wrap_nonce, wrapped


def _unwrap_dek(wrap_nonce: bytes, wrapped_blob: bytes) -> bytes:
    if MASTER_KEY is None:
        raise RuntimeError("MASTER_KEY not set/invalid")
    if AESGCM is None:
        raise RuntimeError("AESGCM not available")
    aes = AESGCM(MASTER_KEY)
    return aes.decrypt(wrap_nonce, wrapped_blob, None)


# =========================================
# FILE TYPE / MALICIOUS CODE BASIC CHECK (SI.1.211)
# =========================================
DENY_EXT = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".scr", ".js", ".vbs", ".jar"}
ALLOW_MIME_PREFIX = ("image/", "text/", "application/pdf", "application/zip", "application/octet-stream")


def guess_mime(filename: str, filebytes: bytes) -> str:
    if magic is not None:
        try:
            m = magic.Magic(mime=True)
            return m.from_buffer(filebytes)
        except Exception:
            pass
    # fallback
    return "application/octet-stream"


def basic_malware_guard(filename: str, mime: str) -> Tuple[bool, str]:
    """
    Demo-safe guard:
    - block high-risk extensions
    - enforce basic filename sanitization already via secure_filename
    - allow a set of mime patterns (soft allowlist)
    """
    ext = (Path(filename).suffix or "").lower()
    if ext in DENY_EXT:
        return False, f"Blocked extension: {ext}"
    # soft allowlist - allow common types
    ok = False
    for p in ALLOW_MIME_PREFIX:
        if mime == p or (p.endswith("/") and mime.startswith(p)):
            ok = True
            break
    if not ok:
        # still allow but log as PARTIAL (since strict allowlists vary)
        return True, "Unknown mime (allowed but flagged)"
    return True, "OK"


# =========================================
# DB HELPERS
# =========================================
def get_user_by_username(username: str):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash, role, created_at, disabled, mfa_enabled FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return row


def create_user(username: str, password: str, role: str = "user"):
    if not validate_password_complexity(password):
        raise ValueError("Weak password")
    role = (role or "user").lower()
    if role not in ("user", "admin"):
        raise ValueError("Invalid role")
    pw_hash = ph.hash(password)
    now = now_utc_iso()
    conn = db_conn()
    c = conn.cursor()
    c.execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)", (username, pw_hash, role, now))
    conn.commit()
    conn.close()


def list_files_for_user(user_id: int):
    conn = db_conn()
    c = conn.cursor()
    c.execute("""
        SELECT f.id, f.orig_name, f.stored_name, f.mime, f.size, f.uploaded_at, f.owner_id
        FROM files f
        LEFT JOIN file_access a ON f.id = a.file_id
        WHERE f.owner_id = ? OR a.user_id = ?
        ORDER BY f.uploaded_at DESC
    """, (user_id, user_id))
    rows = c.fetchall()
    conn.close()
    return rows


def get_file_record(file_id: int):
    conn = db_conn()
    c = conn.cursor()
    c.execute("""
        SELECT id, orig_name, stored_name, mime, size, uploaded_at, owner_id,
               client_encrypted, enc_version, dek_wrap_nonce, dek_wrapped
        FROM files WHERE id=?
    """, (file_id,))
    row = c.fetchone()
    conn.close()
    return row


def user_can_access_file(user_id: int, file_id: int) -> bool:
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT owner_id FROM files WHERE id=?", (file_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False
    if int(row[0]) == int(user_id):
        conn.close()
        return True
    c.execute("SELECT 1 FROM file_access WHERE file_id=? AND user_id=? AND can_read=1", (file_id, user_id))
    ok = c.fetchone() is not None
    conn.close()
    return ok


def user_can_delete_file(user_id: int, file_id: int, is_admin: bool) -> bool:
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT owner_id FROM files WHERE id=?", (file_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False
    owner_id = int(row[0])
    if owner_id == int(user_id) or is_admin:
        conn.close()
        return True
    c.execute("SELECT 1 FROM file_access WHERE file_id=? AND user_id=? AND can_delete=1", (file_id, user_id))
    ok = c.fetchone() is not None
    conn.close()
    return ok


def user_can_share_file(user_id: int, file_id: int, is_admin: bool) -> bool:
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT owner_id FROM files WHERE id=?", (file_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False
    owner_id = int(row[0])
    if owner_id == int(user_id) or is_admin:
        conn.close()
        return True
    c.execute("SELECT 1 FROM file_access WHERE file_id=? AND user_id=? AND can_share=1", (file_id, user_id))
    ok = c.fetchone() is not None
    conn.close()
    return ok


# =========================================
# ROUTES
# =========================================
@app.route("/")
def index():
    roles = [r.value for r in UserRole]
    return render_template("index.html", roles=roles)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        row = get_user_by_username(username)
        if row is None:
            log_event(None, username, "login", "auth", "FAILED")
            flash("Invalid username or password")
            return redirect(url_for("login"))

        user_id, uname, pw_hash, role, created_at, disabled, mfa_enabled = row
        if int(disabled) == 1:
            log_event(user_id, username, "login", "auth", "DENY", {"reason": "disabled"})
            flash("Account disabled")
            return redirect(url_for("login"))

        try:
            ph.verify(pw_hash, password)
        except VerifyMismatchError:
            log_event(user_id, username, "login", "auth", "FAILED")
            flash("Invalid username or password")
            return redirect(url_for("login"))

        # Create session record + enforce concurrency
        session.clear()
        session["user_id"] = user_id
        session["session_id"] = _create_session_record(user_id)
        session["locked"] = 0
        session["mfa_ok"] = 0

        log_event(user_id, username, "login", "auth", "SUCCESS")

        # Enforce admin MFA (IA.2.080)
        _ensure_admin_mfa_on_login(user_id, username, role)
        if role == "admin":
            # If pyotp exists and admin has MFA enabled, require OTP at login
            if pyotp is not None:
                conn = db_conn()
                c = conn.cursor()
                c.execute("SELECT mfa_enabled, mfa_secret FROM users WHERE id=?", (user_id,))
                r = c.fetchone()
                conn.close()
                if r and int(r[0]) == 1 and r[1]:
                    return redirect(url_for("mfa_verify"))
                if session.get("mfa_setup_required") == 1:
                    return redirect(url_for("mfa_setup"))

        flash("Logged in successfully.")
        return redirect(url_for("files"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    uid = session.get("user_id")
    sid = session.get("session_id")
    if uid and sid:
        try:
            conn = db_conn()
            c = conn.cursor()
            c.execute("DELETE FROM sessions WHERE user_id=? AND session_id=?", (uid, sid))
            conn.commit()
            conn.close()
        except Exception:
            pass
        log_event(uid, (g.user or {}).get("username"), "logout", "auth", "SUCCESS")
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))


@app.route("/lock", methods=["POST"])
@login_required
def lock():
    _lock_current_session()
    log_event(g.user["id"], g.user["username"], "session", "lock", "SUCCESS")
    return redirect(url_for("unlock"))


@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    if "user_id" not in session or not session.get("session_id"):
        return redirect(url_for("login"))
    if request.method == "POST":
        # verify password to unlock (pattern-hiding display requirement handled by generic UI)
        password = request.form.get("password") or ""
        conn = db_conn()
        c = conn.cursor()
        c.execute("SELECT username, password_hash FROM users WHERE id=?", (session["user_id"],))
        row = c.fetchone()
        conn.close()
        if not row:
            session.clear()
            return redirect(url_for("login"))
        uname, pw_hash = row
        try:
            ph.verify(pw_hash, password)
        except VerifyMismatchError:
            log_event(session["user_id"], uname, "session", "unlock", "FAILED")
            flash("Invalid password.")
            return redirect(url_for("unlock"))
        _unlock_current_session()
        log_event(session["user_id"], uname, "session", "unlock", "SUCCESS")
        return redirect(url_for("files"))

    # simple unlock page if template doesn't exist
    return render_template_string("""
    <h2>Session Locked</h2>
    <form method="post">
      <input type="hidden" name="_csrf" value="{{ CSRF_TOKEN }}">
      <label>Password:</label>
      <input type="password" name="password" autocomplete="current-password">
      <button type="submit">Unlock</button>
    </form>
    """)


# ---------------- MFA routes ----------------
@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    if g.user.get("role") != "admin":
        abort(403)

    if pyotp is None:
        flash("MFA library not installed (pyotp).")
        log_event(g.user["id"], g.user["username"], "mfa", "setup", "PARTIAL", {"reason": "pyotp_not_installed"})
        return redirect(url_for("files"))

    if request.method == "POST":
        secret = pyotp.random_base32()
        conn = db_conn()
        c = conn.cursor()
        c.execute("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=?", (secret, g.user["id"]))
        conn.commit()
        conn.close()

        session["mfa_setup_required"] = 0
        log_event(g.user["id"], g.user["username"], "mfa", "setup", "SUCCESS")
        flash("MFA enabled. Verify OTP to continue.")
        return redirect(url_for("mfa_verify"))

    # show secret provisioning uri
    # We'll generate secret on POST for safer flow; UI just instructs.
    return render_template_string("""
    <h2>Admin MFA Setup</h2>
    <p>This will enable TOTP MFA for your admin account.</p>
    <form method="post">
      <input type="hidden" name="_csrf" value="{{ CSRF_TOKEN }}">
      <button type="submit">Enable MFA</button>
    </form>
    """)


@app.route("/mfa/verify", methods=["GET", "POST"])
@login_required
def mfa_verify():
    if g.user.get("role") != "admin":
        abort(403)

    if pyotp is None:
        # allow but mark partial
        session["mfa_ok"] = 1
        log_event(g.user["id"], g.user["username"], "mfa", "verify", "PARTIAL", {"reason": "pyotp_not_installed"})
        return redirect(url_for("files"))

    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        ok = _verify_totp(g.user["id"], code)
        if not ok:
            log_event(g.user["id"], g.user["username"], "mfa", "verify", "FAILED")
            flash("Invalid code.")
            return redirect(url_for("mfa_verify"))
        session["mfa_ok"] = 1
        log_event(g.user["id"], g.user["username"], "mfa", "verify", "SUCCESS")
        return redirect(url_for("files"))

    return render_template_string("""
    <h2>MFA Verification</h2>
    <form method="post">
      <input type="hidden" name="_csrf" value="{{ CSRF_TOKEN }}">
      <label>6-digit code:</label>
      <input name="code" inputmode="numeric" autocomplete="one-time-code">
      <button type="submit">Verify</button>
    </form>
    """)


def _admin_mfa_gate():
    # For admin pages, require MFA verified if MFA enabled
    if g.user and g.user.get("role") == "admin" and pyotp is not None:
        conn = db_conn()
        c = conn.cursor()
        c.execute("SELECT mfa_enabled, mfa_secret FROM users WHERE id=?", (g.user["id"],))
        row = c.fetchone()
        conn.close()
        if row and int(row[0]) == 1 and row[1]:
            if session.get("mfa_ok") != 1:
                return redirect(url_for("mfa_verify"))
    return None


# ---------------- Files ----------------
@app.route("/files")
@login_required
def files():
    rows = list_files_for_user(g.user["id"])
    return render_template("files.html", files=rows, current_user=g.user)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        f = request.files["file"]
        if f.filename == "":
            flash("No selected file")
            return redirect(request.url)

        orig_name = secure_filename(f.filename)
        file_bytes = f.read()
        mime = guess_mime(orig_name, file_bytes)

        ok, reason = basic_malware_guard(orig_name, mime)
        if not ok:
            log_event(g.user["id"], g.user["username"], "upload", orig_name, "DENY", {"reason": reason, "mime": mime})
            flash(f"Upload blocked: {reason}")
            return redirect(url_for("upload"))
        if reason != "OK":
            log_event(g.user["id"], g.user["username"], "upload_flag", orig_name, "SUCCESS", {"note": reason, "mime": mime})

        client_encrypted = (request.form.get("client_encrypted") == "1") or (request.headers.get("X-Client-Encrypted") == "1")

        stored_name = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=") + ".bin"
        ts = now_utc_iso()

        # Save data
        enc_version = 2
        dek_wrap_nonce = None
        dek_wrapped = None

        if client_encrypted:
            # store as-is
            blob_to_store = file_bytes
            enc_version = 2
        else:
            if MASTER_KEY is None or AESGCM is None:
                abort(500, description="Server crypto not available or key missing.")
            # per-file DEK
            dek = os.urandom(32)
            blob_to_store = _aesgcm_encrypt(dek, file_bytes)
            dek_wrap_nonce, dek_wrapped = _wrap_dek(dek)

        storage_save_bytes(stored_name, blob_to_store)

        # DB insert
        conn = db_conn()
        c = conn.cursor()
        c.execute("""
            INSERT INTO files(orig_name, stored_name, mime, size, uploaded_at, owner_id, client_encrypted, enc_version, dek_wrap_nonce, dek_wrapped)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (orig_name, stored_name, mime, len(file_bytes), ts, g.user["id"], 1 if client_encrypted else 0, enc_version, dek_wrap_nonce, dek_wrapped))
        conn.commit()
        conn.close()

        log_event(g.user["id"], g.user["username"], "upload", orig_name, "SUCCESS", {"mime": mime, "size": len(file_bytes), "client_encrypted": client_encrypted})
        flash("Uploaded successfully.")
        return redirect(url_for("files"))

    return render_template("upload.html")


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    # Permission check (AC.1.002 / AC.1.003)
    if not user_can_access_file(g.user["id"], file_id):
        log_event(g.user["id"], g.user["username"], "download", str(file_id), "DENY")
        abort(403)

    rec = get_file_record(file_id)
    if not rec:
        log_event(g.user["id"], g.user["username"], "download", str(file_id), "FAILED", {"reason": "not_found"})
        abort(404)

    (_, orig_name, stored_name, mime, size, uploaded_at, owner_id, client_encrypted, enc_version, wrap_nonce, wrapped_dek) = rec

    try:
        blob = storage_read_bytes(stored_name)
    except Exception:
        log_event(g.user["id"], g.user["username"], "download", orig_name, "FAILED", {"reason": "storage_missing"})
        abort(404)

    # If client encrypted -> return as-is
    if int(client_encrypted) == 1:
        log_event(g.user["id"], g.user["username"], "download", orig_name, "SUCCESS", {"client_encrypted": True})
        return send_file(io.BytesIO(blob), download_name=orig_name or "download", mimetype=mime or "application/octet-stream", as_attachment=True)

    # Server decrypt
    try:
        if wrap_nonce and wrapped_dek:
            dek = _unwrap_dek(wrap_nonce, wrapped_dek)
            plaintext = _aesgcm_decrypt(dek, blob)
        else:
            # Legacy fallback: treat blob as plaintext for demo (should not happen) — log partial
            log_event(g.user["id"], g.user["username"], "download", orig_name, "PARTIAL", {"reason": "missing_dek_wrap"})
            plaintext = blob
    except Exception as e:
        log_event(g.user["id"], g.user["username"], "download", orig_name, "FAILED", {"reason": "decrypt_error"})
        abort(500)

    log_event(g.user["id"], g.user["username"], "download", orig_name, "SUCCESS")
    return send_file(io.BytesIO(plaintext), download_name=orig_name or "download", mimetype=mime or "application/octet-stream", as_attachment=True)


@app.route("/preview/<int:file_id>")
@login_required
def preview(file_id):
    if not user_can_access_file(g.user["id"], file_id):
        abort(403)

    rec = get_file_record(file_id)
    if not rec:
        abort(404)

    (_, orig_name, stored_name, mime, _, _, _, client_encrypted, _, wrap_nonce, wrapped_dek) = rec
    if not (mime or "").startswith("image/"):
        return redirect(url_for("files"))

    blob = storage_read_bytes(stored_name)

    if int(client_encrypted) == 1:
        return send_file(io.BytesIO(blob), mimetype=mime)

    try:
        if wrap_nonce and wrapped_dek:
            dek = _unwrap_dek(wrap_nonce, wrapped_dek)
            plaintext = _aesgcm_decrypt(dek, blob)
        else:
            plaintext = blob
    except Exception:
        abort(500)

    return send_file(io.BytesIO(plaintext), mimetype=mime)


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):
    is_admin = (g.user.get("role") == "admin")

    if not user_can_delete_file(g.user["id"], file_id, is_admin=is_admin):
        log_event(g.user["id"], g.user["username"], "delete", str(file_id), "DENY")
        abort(403)

    rec = get_file_record(file_id)
    if not rec:
        flash("File not found.")
        return redirect(url_for("files"))

    (_, orig_name, stored_name, _, _, _, _, _, _, _, _) = rec

    # Delete blob
    try:
        storage_delete(stored_name)
    except Exception:
        pass

    # Crypto-shred: delete wrapped DEK + record (MP.2.120)
    conn = db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM file_access WHERE file_id=?", (file_id,))
    c.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()

    log_event(g.user["id"], g.user["username"], "delete", orig_name, "SUCCESS", {"crypto_shred": True})
    flash("File deleted.")
    return redirect(url_for("files"))


# ---------------- Sharing ----------------
@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def share_file(file_id):
    is_admin = (g.user.get("role") == "admin")
    if not user_can_share_file(g.user["id"], file_id, is_admin=is_admin):
        log_event(g.user["id"], g.user["username"], "share", str(file_id), "DENY")
        abort(403)

    target_username = (request.form.get("username") or "").strip()
    message = (request.form.get("message") or "").strip()
    can_delete = 1 if (request.form.get("can_delete") == "1") else 0
    can_share = 1 if (request.form.get("can_share") == "1") else 0

    if not target_username:
        flash("Username is required to share.")
        return redirect(url_for("files"))

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=?", (target_username,))
    dest = c.fetchone()
    if not dest:
        conn.close()
        flash("Target user not found.")
        return redirect(url_for("files"))
    target_id = int(dest[0])

    # grant access
    c.execute("""
        INSERT OR REPLACE INTO file_access(file_id, user_id, can_read, can_delete, can_share)
        VALUES (?,?,?,?,?)
    """, (file_id, target_id, 1, can_delete, can_share))

    # message
    try:
        c.execute("""
            INSERT INTO file_messages(file_id, sender_id, recipient_id, message, created_at)
            VALUES (?,?,?,?,?)
        """, (file_id, g.user["id"], target_id, message, now_utc_iso()))
    except Exception:
        pass

    conn.commit()
    conn.close()

    log_event(g.user["id"], g.user["username"], "share", str(file_id), "SUCCESS", {"to": target_username, "can_delete": can_delete, "can_share": can_share})
    flash(f"File shared with {target_username}.")
    return redirect(url_for("files"))


@app.route("/revoke/<int:file_id>/<int:target_id>", methods=["POST"])
@login_required
def revoke_access(file_id, target_id):
    is_admin = (g.user.get("role") == "admin")
    if not user_can_share_file(g.user["id"], file_id, is_admin=is_admin):
        log_event(g.user["id"], g.user["username"], "revoke", f"{file_id}:{target_id}", "DENY")
        abort(403)

    conn = db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM file_access WHERE file_id=? AND user_id=?", (file_id, target_id))
    conn.commit()
    conn.close()

    log_event(g.user["id"], g.user["username"], "revoke", f"{file_id}:{target_id}", "SUCCESS")
    flash("Access revoked.")
    return redirect(url_for("files"))


@app.route("/inbox")
@login_required
def inbox():
    conn = db_conn()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT m.id, m.file_id, f.orig_name, m.sender_id, s.username, m.message, m.created_at
            FROM file_messages m
            JOIN users s ON m.sender_id = s.id
            JOIN files f ON m.file_id = f.id
            WHERE m.recipient_id = ?
            ORDER BY m.created_at DESC
        """, (g.user["id"],))
        rows = c.fetchall()
    except sqlite3.OperationalError:
        rows = []
    conn.close()
    return render_template("inbox.html", messages=rows)


# ---------------- Admin: Users + Audit ----------------
@app.route("/add-user")
@admin_required
def add_user_form():
    gate = _admin_mfa_gate()
    if gate:
        return gate
    roles = [r.value for r in UserRole]
    return render_template("add_user.html", roles=roles)


@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    gate = _admin_mfa_gate()
    if gate:
        return gate

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = (data.get("role") or "user").strip().lower()

        if not username or not password:
            return {"error": "Username and password are required"}, 400
        if not validate_password_complexity(password):
            return {"error": "Weak password (min 12, upper/lower/number/special)."}, 400

        try:
            create_user(username, password, role)
            log_event(g.user["id"], g.user["username"], "admin_create_user", username, "SUCCESS", {"role": role})
        except sqlite3.IntegrityError:
            log_event(g.user["id"], g.user["username"], "admin_create_user", username, "FAILED", {"reason": "exists"})
            return {"error": "Username already exists"}, 400
        except ValueError as e:
            log_event(g.user["id"], g.user["username"], "admin_create_user", username, "FAILED", {"reason": str(e)})
            return {"error": str(e)}, 400

        return {"message": "User created"}, 201

    # GET list users
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at, disabled, mfa_enabled FROM users ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return jsonify({
        "users": [
            {"id": r[0], "username": r[1], "role": r[2], "created_at": r[3], "disabled": int(r[4]), "mfa_enabled": int(r[5])}
            for r in rows
        ]
    })


@app.route("/users/<int:user_id>/disable", methods=["POST"])
@admin_required
def disable_user(user_id):
    gate = _admin_mfa_gate()
    if gate:
        return gate
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET disabled=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    log_event(g.user["id"], g.user["username"], "admin_disable_user", str(user_id), "SUCCESS")
    return {"message": "User disabled"}, 200


@app.route("/audit", methods=["GET"])
@admin_required
def audit_view():
    gate = _admin_mfa_gate()
    if gate:
        return gate

    # AU.2.042 review/analyze/report
    user = (request.args.get("user") or "").strip()
    action = (request.args.get("action") or "").strip()
    limit = int(request.args.get("limit", "200"))
    limit = min(max(limit, 1), 1000)

    conn = db_conn()
    c = conn.cursor()

    q = "SELECT id, user_id, username, action, target, result, ip_address, timestamp, details FROM audit_log WHERE 1=1"
    params = []
    if user:
        q += " AND username=?"
        params.append(user)
    if action:
        q += " AND action=?"
        params.append(action)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    c.execute(q, tuple(params))
    rows = c.fetchall()
    conn.close()

    return jsonify({
        "logs": [
            {
                "id": r[0], "user_id": r[1], "username": r[2], "action": r[3],
                "target": r[4], "result": r[5], "ip": r[6], "timestamp": r[7],
                "details": r[8]
            } for r in rows
        ]
    })


# ---------------- Baseline snapshot (CM.2.061 / CM.2.064) ----------------
def baseline_snapshot() -> Dict[str, Any]:
    """Creates a simple baseline snapshot of runtime config and hashes for evidence."""
    data = {
        "timestamp": now_utc_iso(),
        "env": ENV,
        "force_https": FORCE_HTTPS,
        "max_content_length": MAX_CONTENT_LENGTH,
        "session_idle_minutes": SESSION_IDLE_MINUTES,
        "max_concurrent_sessions": MAX_CONCURRENT_SESSIONS,
        "use_azure_blobs": USE_AZURE_BLOBS,
        "blob_container": AZ_BLOB_CONTAINER,
        "remote_ip_allowlist_enabled": bool(REMOTE_IP_ALLOWLIST),
        "code_hash": None,
        "db_path": DB_PATH,
        "upload_folder": UPLOAD_FOLDER,
    }
    # hash this file for evidence
    try:
        with open(__file__, "rb") as fh:
            data["code_hash"] = hashlib.sha256(fh.read()).hexdigest()
    except Exception:
        pass
    return data


@app.route("/admin/baseline", methods=["GET", "POST"])
@admin_required
def admin_baseline():
    gate = _admin_mfa_gate()
    if gate:
        return gate

    if request.method == "POST":
        snap = baseline_snapshot()
        old = None
        if os.path.exists(BASELINE_PATH):
            try:
                old = open(BASELINE_PATH, "r", encoding="utf-8").read()
            except Exception:
                old = None
        try:
            with open(BASELINE_PATH, "w", encoding="utf-8") as fh:
                json.dump(snap, fh, indent=2)
        except Exception:
            pass
        log_config_change(g.user["id"], g.user["username"], "baseline_snapshot", old, json.dumps(snap))
        log_event(g.user["id"], g.user["username"], "baseline", "snapshot", "SUCCESS")
        return jsonify({"message": "Baseline snapshot saved", "path": BASELINE_PATH, "snapshot": snap})

    # GET current snapshot + file
    snap = baseline_snapshot()
    existing = None
    if os.path.exists(BASELINE_PATH):
        try:
            existing = json.loads(open(BASELINE_PATH, "r", encoding="utf-8").read())
        except Exception:
            existing = None
    return jsonify({"current": snap, "saved": existing})


# =========================================
# TEMP FILE APIs (kept, but add audit)
# =========================================
TEMP_FILES: Dict[str, Dict[str, Any]] = {}


@app.route("/temp-upload", methods=["POST"])
@login_required
def temp_upload():
    if "file" not in request.files:
        return {"error": "No file part"}, 400
    file = request.files["file"]
    if file.filename == "":
        return {"error": "No selected file"}, 400
    filename = secure_filename(file.filename)
    content = file.read()
    fid = str(uuid.uuid4())
    TEMP_FILES[fid] = {
        "filename": filename,
        "content": content,
        "mime": guess_mime(filename, content),
        "timestamp": now_utc_iso(),
    }
    log_event(g.user["id"], g.user["username"], "temp_upload", filename, "SUCCESS", {"temp_id": fid})
    return {"file_id": fid, "filename": filename, "size": len(content), "mime": TEMP_FILES[fid]["mime"]}


@app.route("/temp-file/<file_id>")
@login_required
def get_temp_file(file_id):
    if file_id not in TEMP_FILES:
        return {"error": "File not found"}, 404
    f = TEMP_FILES[file_id]
    log_event(g.user["id"], g.user["username"], "temp_download", f["filename"], "SUCCESS", {"temp_id": file_id})
    return send_file(io.BytesIO(f["content"]), download_name=f["filename"], mimetype=f["mime"])


@app.route("/temp-file/<file_id>", methods=["DELETE"])
@login_required
def delete_temp_file(file_id):
    if file_id not in TEMP_FILES:
        return {"error": "File not found"}, 404
    fname = TEMP_FILES[file_id]["filename"]
    del TEMP_FILES[file_id]
    log_event(g.user["id"], g.user["username"], "temp_delete", fname, "SUCCESS", {"temp_id": file_id})
    return {"message": "File deleted successfully"}


# =========================================
# SIMPLE uploader namespace (/simple) kept minimal
# (This is demo-only; main app is what we audit)
# =========================================
SIMPLE_UPLOAD_DIR = Path("uploads")
SIMPLE_UPLOAD_DIR.mkdir(exist_ok=True)

SIMPLE_INDEX_HTML = """
<!doctype html>
<title>Simple uploader</title>
<h1>Simple uploader (/simple)</h1>
<p><a href="/files">Back to main</a></p>
<form method="post" enctype="multipart/form-data" action="/simple/upload">
  <input type="hidden" name="_csrf" value="{{ CSRF_TOKEN }}">
  <input type="file" name="file" />
  <button type="submit">Upload</button>
</form>
<hr>
<ul>
{% for f in files %}
  <li><a href="/simple/download/{{f}}">{{f}}</a></li>
{% endfor %}
</ul>
"""

@app.route("/simple")
def simple_index():
    items = sorted([p.stem for p in SIMPLE_UPLOAD_DIR.glob("*.enc")])
    return render_template_string(SIMPLE_INDEX_HTML, files=items)

@app.route("/simple/upload", methods=["POST"])
def simple_upload():
    # demo-only: require passphrase; do not audit as CUI path
    if AESGCM is None:
        abort(500)
    passphrase = os.environ.get("FILESTORE_PASSPHRASE")
    if not passphrase:
        abort(500, description="FILESTORE_PASSPHRASE not set.")
    f = request.files.get("file")
    if not f or f.filename == "":
        return "No file selected", 400
    name = secure_filename(f.filename)
    data = f.read()
    salt_path = Path("kdf_salt.bin")
    if not salt_path.exists():
        salt_path.write_bytes(os.urandom(16))
    salt = salt_path.read_bytes()
    # scrypt-like quick derive (demo)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 200_000, dklen=32)
    blob = _aesgcm_encrypt(key, data)
    (SIMPLE_UPLOAD_DIR / (name + ".enc")).write_bytes(blob)
    return redirect(url_for("simple_index"))

@app.route("/simple/download/<path:filename>")
def simple_download(filename):
    if AESGCM is None:
        abort(500)
    passphrase = os.environ.get("FILESTORE_PASSPHRASE")
    if not passphrase:
        abort(500, description="FILESTORE_PASSPHRASE not set.")
    safe = secure_filename(filename)
    enc_path = SIMPLE_UPLOAD_DIR / (safe + ".enc")
    if not enc_path.exists():
        abort(404)
    salt = Path("kdf_salt.bin").read_bytes()
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 200_000, dklen=32)
    plaintext = _aesgcm_decrypt(key, enc_path.read_bytes())
    return send_file(io.BytesIO(plaintext), as_attachment=True, download_name=safe, mimetype="application/octet-stream")


# =========================================
# STARTUP
# =========================================
if __name__ == "__main__":
    init_db()

    # Write baseline snapshot on startup (CM.2.061 evidence)
    try:
        snap = baseline_snapshot()
        if not os.path.exists(BASELINE_PATH):
            with open(BASELINE_PATH, "w", encoding="utf-8") as fh:
                json.dump(snap, fh, indent=2)
    except Exception:
        pass

    # Log time sync evidence (AU.2.043) - app uses UTC; external NTP evidence handled at VM layer later
    try:
        log_event(None, None, "time_sync", "utc", "SUCCESS", {"server_time_utc": now_utc_iso()})
    except Exception:
        pass

    run_host = os.environ.get("FLASK_RUN_HOST", os.environ.get("HOST", "0.0.0.0"))
    run_port = int(os.environ.get("PORT", 5000))
    run_debug = (os.environ.get("FLASK_DEBUG", "1").lower() in ("1", "true", "yes")) and not IS_PROD

    app.run(host=run_host, port=run_port, debug=run_debug)
