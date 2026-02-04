# main.py
import os
import sqlite3
import datetime
import io
import base64
import enum
from pathlib import Path
from io import BytesIO

# Optional: load .env only if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ModuleNotFoundError:
    # In production (Azure) we expect env vars to be set by App Service,
    # so it's OK if python-dotenv is not installed.
    pass


from functools import wraps
from flask import (
    Flask, request, redirect, url_for, render_template, render_template_string,
    send_file, abort, flash, jsonify, session, g
)
from werkzeug.utils import secure_filename
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re  # for password complexity
from app.crypto_utils import load_key_from_env, encrypt_bytes, decrypt_bytes
try:
    from azure.storage.blob import BlobServiceClient
except Exception:
    BlobServiceClient = None

# =========================================
# SHARED APP
# =========================================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))

# Security: ensure session cookie flags are set for production.
# Don't force Secure cookies in development over plain HTTP (they won't be sent).
secure_cookies = os.environ.get('FLASK_ENV', '').lower() == 'production'
app.config.update(
    SESSION_COOKIE_SECURE=secure_cookies,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Password hasher (Argon2)
ph = PasswordHasher()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)


# ------------------ user roles ------------------
class UserRole(enum.Enum):
    USER = "user"
    ADMIN = "admin"

PASSWORD_REGEX = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^])[A-Za-z\d@$!%*?&#^]{12,}$'
)

def validate_password_complexity(pw: str) -> bool:
    """At least 12 chars, upper, lower, number, special."""
    return bool(PASSWORD_REGEX.match(pw))


# --- auth helpers ---
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in first.")
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped


@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    if user_id is not None:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, username, role FROM users WHERE id=?', (user_id,))
        row = c.fetchone()
        conn.close()
        if row:
            g.user = {'id': row[0], 'username': row[1], 'role': row[2]}

# ------------------ config ------------------
# Allow pointing to a persistent data directory via DATA_DIR so uploads and DB
# can live outside the repo (useful for sharing between runs or teammates).
DATA_DIR = os.environ.get('DATA_DIR')  # e.g. /srv/secure_uploader_data
if DATA_DIR:
    os.makedirs(DATA_DIR, exist_ok=True)
    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
    DB_PATH = os.path.join(DATA_DIR, 'files.db')
else:
    UPLOAD_FOLDER = "uploads"
    DB_PATH = "files.db"
ALLOWED_EXTENSIONS = None
MAX_CONTENT_LENGTH = 200 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ------------------ encryption (original app.py) ------------------
# Load encryption key from env, or fall back to a persistent key file in DATA_DIR
# If none found, generate a new random key (warn) and persist it so subsequent
# runs can decrypt previously uploaded files.
ENC_KEY_B64 = os.environ.get("UPLOAD_ENC_KEY")
key_persist_path = None
if not ENC_KEY_B64:
    # try to load from a key file inside DATA_DIR (if set) or repo root
    store_dir = DATA_DIR if DATA_DIR else os.getcwd()
    key_persist_path = os.path.join(store_dir, ".upload_enc_key")
    try:
        if os.path.exists(key_persist_path):
            with open(key_persist_path, "r") as kf:
                ENC_KEY_B64 = kf.read().strip()
    except Exception:
        ENC_KEY_B64 = None

if not ENC_KEY_B64:
    # generate a new one and persist it (informative warning)
    import base64 as _base64
    new_key = _base64.urlsafe_b64encode(os.urandom(32)).decode()
    ENC_KEY_B64 = new_key
    try:
        if not key_persist_path:
            store_dir = DATA_DIR if DATA_DIR else os.getcwd()
            key_persist_path = os.path.join(store_dir, ".upload_enc_key")
        os.makedirs(os.path.dirname(key_persist_path), exist_ok=True)
        with open(key_persist_path, "w") as kf:
            kf.write(ENC_KEY_B64)
        print(f"[WARNING] No UPLOAD_ENC_KEY provided; generated and saved key to {key_persist_path}")
    except Exception:
        # best-effort: print warning but continue with in-memory key
        print("[WARNING] No UPLOAD_ENC_KEY provided and failed to persist key; using ephemeral key for this run.")

ENCKEY = load_key_from_env(ENC_KEY_B64)

# ------------------ temp files (original app.py) ------------------
TEMP_FILES = {}

# ------------------ storage backend (local filesystem or Azure Blob) ------------------
USE_AZURE_BLOBS = False
AZ_BLOB_CLIENT = None
AZ_BLOB_CONTAINER = None
if BlobServiceClient is not None:
    # prefer an explicit connection string from env
    AZ_CONN = os.environ.get('AZURE_STORAGE_CONNECTION_STRING') or os.environ.get('AZURE_BLOB_CONNECTION_STRING')
    AZ_CONTAINER = os.environ.get('AZURE_BLOB_CONTAINER')
    if AZ_CONN and AZ_CONTAINER:
        try:
            AZ_BLOB_CLIENT = BlobServiceClient.from_connection_string(AZ_CONN)
            AZ_BLOB_CONTAINER = AZ_CONTAINER
            # ensure container exists
            try:
                AZ_BLOB_CLIENT.create_container(AZ_BLOB_CONTAINER)
            except Exception:
                pass
            USE_AZURE_BLOBS = True
            print('[INFO] Using Azure Blob Storage container:', AZ_BLOB_CONTAINER)
        except Exception as e:
            print('[WARN] Failed to initialize Azure Blob client:', e)

def storage_save_bytes(stored_name: str, data: bytes) -> None:
    """Save bytes either locally or to Azure blob storage depending on config."""
    if USE_AZURE_BLOBS and AZ_BLOB_CLIENT is not None:
        blob = AZ_BLOB_CLIENT.get_blob_client(container=AZ_BLOB_CONTAINER, blob=stored_name)
        blob.upload_blob(data, overwrite=True)
    else:
        path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        with open(path, 'wb') as fh:
            fh.write(data)

def storage_read_bytes(stored_name: str) -> bytes:
    if USE_AZURE_BLOBS and AZ_BLOB_CLIENT is not None:
        blob = AZ_BLOB_CLIENT.get_blob_client(container=AZ_BLOB_CONTAINER, blob=stored_name)
        downloader = blob.download_blob()
        return downloader.readall()
    else:
        path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        with open(path, 'rb') as fh:
            return fh.read()

def storage_delete(stored_name: str) -> None:
    if USE_AZURE_BLOBS and AZ_BLOB_CLIENT is not None:
        try:
            blob = AZ_BLOB_CLIENT.get_blob_client(container=AZ_BLOB_CONTAINER, blob=stored_name)
            blob.delete_blob()
        except Exception:
            pass
    else:
        path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


# Make encryption + storage status available in templates
@app.context_processor
def inject_app_status():
    # provide file count (fast) for UI badges
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM files')
        fc = c.fetchone()[0]
        conn.close()
    except Exception:
        fc = 0
    return {
        'ENCRYPTION_AVAILABLE': ENCKEY is not None,
        'USE_AZURE_BLOBS': USE_AZURE_BLOBS,
        'AZ_BLOB_CONTAINER': AZ_BLOB_CONTAINER if 'AZ_BLOB_CONTAINER' in globals() else None,
        'FILE_COUNT': fc,
    }

# =========================================
# DB HELPERS (original app.py)
# =========================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Users
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    ''')

    # Files owned by a user
    c.execute('''
    CREATE TABLE IF NOT EXISTS files(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        orig_name TEXT,
        stored_name TEXT,
        mime TEXT,
        size INTEGER,
        uploaded_at TEXT,
        owner_id INTEGER NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )
    ''')

    # Sharing table: who else can access which file
    c.execute('''
    CREATE TABLE IF NOT EXISTS file_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        can_read INTEGER NOT NULL DEFAULT 1,
        can_delete INTEGER NOT NULL DEFAULT 0,
        UNIQUE(file_id, user_id),
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    # Messages/notifications created when a file is shared
    c.execute('''
    CREATE TABLE IF NOT EXISTS file_messages(
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
    ''')

    conn.commit()
    conn.close()

    # Ensure `client_encrypted` column exists on `files` table for marking client-side encrypted uploads
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("PRAGMA table_info(files)")
        cols = [r[1] for r in c.fetchall()]
        if 'client_encrypted' not in cols:
            c.execute('ALTER TABLE files ADD COLUMN client_encrypted INTEGER NOT NULL DEFAULT 0')
            conn.commit()
    except Exception:
        # best-effort: ignore if table missing (shouldn't happen) or ALTER not supported
        pass
    conn.close()

def add_file_record(orig_name, stored_name, mime, size, owner_id=None, client_encrypted: bool = False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    ts = datetime.datetime.utcnow().isoformat()
    try:
        # Preferred: include owner_id and client_encrypted
        c.execute(
            '''
            INSERT INTO files(orig_name, stored_name, mime, size, uploaded_at, owner_id, client_encrypted)
            VALUES (?,?,?,?,?,?,?)
            ''',
            (orig_name, stored_name, mime, size, ts, owner_id, 1 if client_encrypted else 0)
        )
    except sqlite3.OperationalError:
        # Older schema variants: try without client_encrypted, then without owner_id
        try:
            c.execute(
                '''
                INSERT INTO files(orig_name, stored_name, mime, size, uploaded_at, owner_id)
                VALUES (?,?,?,?,?,?)
                ''',
                (orig_name, stored_name, mime, size, ts, owner_id)
            )
        except sqlite3.OperationalError:
            c.execute(
                '''
                INSERT INTO files(orig_name, stored_name, mime, size, uploaded_at)
                VALUES (?,?,?,?,?)
                ''',
                (orig_name, stored_name, mime, size, ts)
            )
    conn.commit()
    conn.close()

def list_files():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, orig_name, stored_name, mime, size, uploaded_at FROM files ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    return rows

def get_file_record(file_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # include client_encrypted flag (added later to schema) so download can decide whether to decrypt
    c.execute('SELECT id, orig_name, stored_name, mime, size, uploaded_at, client_encrypted FROM files WHERE id=?', (file_id,))
    row = c.fetchone()
    conn.close()
    return row

def delete_file_record(file_id):
    rec = get_file_record(file_id)
    if not rec:
        return False
    stored_name = rec[2]
    # remove from storage (local or Azure Blob)
    try:
        storage_delete(stored_name)
    except Exception:
        pass
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM files WHERE id=?', (file_id,))
    conn.commit()
    conn.close()
    return True

def guess_mime(filename, filebytes):
    try:
        import magic
        m = magic.Magic(mime=True)
        return m.from_buffer(filebytes)
    except Exception:
        return "application/octet-stream"

def get_user_by_username(username: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, password_hash, role, created_at FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    return row

def create_user(username: str, password: str, role: str = "user"):
    if not validate_password_complexity(password):
        raise ValueError("Weak password")
    role = role.lower()
    if role not in ("user", "admin"):
        raise ValueError("Invalid role")
    pw_hash = ph.hash(password)
    now = datetime.datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)',
        (username, pw_hash, role, now)
    )
    conn.commit()
    conn.close()

def list_files_for_user(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
        SELECT f.id, f.orig_name, f.stored_name, f.mime, f.size, f.uploaded_at, f.owner_id
        FROM files f
        LEFT JOIN file_access a ON f.id = a.file_id
        WHERE f.owner_id = ? OR a.user_id = ?
        ORDER BY f.uploaded_at DESC
        ''', (user_id, user_id))
        rows = c.fetchall()
    except sqlite3.OperationalError:
        # Fallback for older schema without owner_id or file_access table: return all files
        c.execute('SELECT id, orig_name, stored_name, mime, size, uploaded_at FROM files ORDER BY uploaded_at DESC')
        base_rows = c.fetchall()
        # append None as owner_id to match expected tuple length
        rows = [r + (None,) for r in base_rows]
    conn.close()
    return rows

def user_can_access_file(user_id: int, file_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT owner_id FROM files WHERE id=?', (file_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False
    owner_id = row[0]
    if owner_id == user_id:
        conn.close()
        return True
    c.execute('SELECT 1 FROM file_access WHERE file_id=? AND user_id=? AND can_read=1', (file_id, user_id))
    shared = c.fetchone() is not None
    conn.close()
    return shared


@app.route('/')
def index():
    # main UI
    roles = [role.value for role in UserRole]
    return render_template('index.html', roles=roles)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        row = get_user_by_username(username)
        if row is None:
            flash("Invalid username or password")
            return redirect(url_for('login'))
        user_id, uname, pw_hash, role, created_at = row
        try:
            ph.verify(pw_hash, password)
        except VerifyMismatchError:
            flash("Invalid username or password")
            return redirect(url_for('login'))
        session.clear()
        session['user_id'] = user_id
        flash("Logged in successfully.")
        return redirect(url_for('files'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part")
            return redirect(request.url)
        f = request.files['file']
        if f.filename == '':
            flash("No selected file")
            return redirect(request.url)

        orig_name = secure_filename(f.filename)
        file_bytes = f.read()
        mime = guess_mime(orig_name, file_bytes)

        # If the client already encrypted the file (browser-side), it should include a flag
        client_encrypted = request.form.get('client_encrypted') == '1' or request.headers.get('X-Client-Encrypted') == '1'

        if client_encrypted:
            # store as-is; server will not attempt to decrypt these files
            enc_blob = file_bytes
        else:
            if ENCKEY is None:
                abort(500, description="Server encryption key not set.")
            enc_blob = encrypt_bytes(file_bytes, ENCKEY)

        stored_name = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip('=') + ".bin"
        # Save to configured storage (local filesystem or Azure Blob)
        try:
            storage_save_bytes(stored_name, enc_blob)
        except Exception:
            # fallback to local write
            path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
            with open(path, 'wb') as fh:
                fh.write(enc_blob)

        add_file_record(orig_name, stored_name, mime, len(file_bytes), g.user.get('id') if g.user else None, client_encrypted=client_encrypted)
        flash("Uploaded and encrypted successfully.")
        return redirect(url_for('files'))
    return render_template('upload.html')

@app.route('/files')
@login_required
def files():
    rows = list_files_for_user(g.user['id'])
    return render_template('files.html', files=rows, current_user=g.user)

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    rec = get_file_record(file_id)
    if not rec:
        abort(404)
    try:
        enc_blob = storage_read_bytes(rec[2])
    except Exception:
        abort(404)
    # rec includes client_encrypted at position 6 (0-based index)
    client_encrypted = False
    try:
        client_encrypted = bool(rec[6])
    except Exception:
        client_encrypted = False

    if client_encrypted:
        # Return the stored blob as-is; client is expected to decrypt locally
        return send_file(
            io.BytesIO(enc_blob),
            download_name=rec[1] or "download",
            mimetype=rec[3] or "application/octet-stream",
            as_attachment=True
        )

    if ENCKEY is None:
        abort(500, description="Server encryption key not set.")
    plaintext = decrypt_bytes(enc_blob, ENCKEY)
    return send_file(
        io.BytesIO(plaintext),
        download_name=rec[1] or "download",
        mimetype=rec[3] or "application/octet-stream",
        as_attachment=True
    )

@app.route('/preview/<int:file_id>')
@login_required
def preview(file_id):
    rec = get_file_record(file_id)
    if not rec:
        abort(404)
    if not (rec[3] or "").startswith("image/"):
        return redirect(url_for('files'))
    try:
        enc_blob = storage_read_bytes(rec[2])
    except Exception:
        abort(404)

    # if client-encrypted, return as-is (client should decrypt)
    client_encrypted = False
    try:
        client_encrypted = bool(rec[6])
    except Exception:
        client_encrypted = False

    if client_encrypted:
        return send_file(io.BytesIO(enc_blob), mimetype=rec[3])

    if ENCKEY is None:
        abort(500, description="Server encryption key not set.")
    plaintext = decrypt_bytes(enc_blob, ENCKEY)
    return send_file(io.BytesIO(plaintext), mimetype=rec[3])

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    # Only allow owner or admin to delete
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT owner_id FROM files WHERE id=?', (file_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("File not found.")
        return redirect(url_for('files'))
    owner_id = row[0]
    if owner_id != g.user['id'] and g.user.get('role') != 'admin':
        conn.close()
        abort(403)
    conn.close()
    ok = delete_file_record(file_id)
    flash("File deleted." if ok else "File not found.")
    return redirect(url_for('files'))


@app.route('/share/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id):
    target_username = request.form.get('username', '').strip()
    message = request.form.get('message', '').strip()
    if not target_username:
        flash("Username is required to share.")
        return redirect(url_for('files'))
    # Check that current user owns the file or is admin
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT owner_id FROM files WHERE id=?', (file_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        abort(404)
    owner_id = row[0]
    if owner_id != g.user['id'] and g.user['role'] != 'admin':
        conn.close()
        abort(403)
    # Find target user
    c.execute('SELECT id FROM users WHERE username=?', (target_username,))
    dest = c.fetchone()
    if not dest:
        conn.close()
        flash("Target user not found.")
        return redirect(url_for('files'))
    target_id = dest[0]
    # Grant read access
    c.execute('''
        INSERT OR IGNORE INTO file_access(file_id, user_id, can_read, can_delete)
        VALUES (?,?,1,0)
    ''', (file_id, target_id))
    # Insert a message/notification record for recipient
    try:
        ts = datetime.datetime.utcnow().isoformat()
        c.execute('''
            INSERT INTO file_messages(file_id, sender_id, recipient_id, message, created_at)
            VALUES (?,?,?,?,?)
        ''', (file_id, g.user['id'], target_id, message, ts))
    except Exception:
        # If table doesn't exist or other issue, ignore so sharing still works
        pass
    conn.commit()
    conn.close()
    flash(f"File shared with {target_username}.")
    return redirect(url_for('files'))


@app.route('/inbox')
@login_required
def inbox():
    # List messages sent to current user
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            SELECT m.id, m.file_id, f.orig_name, m.sender_id, s.username, m.message, m.created_at
            FROM file_messages m
            JOIN users s ON m.sender_id = s.id
            JOIN files f ON m.file_id = f.id
            WHERE m.recipient_id = ?
            ORDER BY m.created_at DESC
        ''', (g.user['id'],))
        rows = c.fetchall()
    except sqlite3.OperationalError:
        rows = []
    conn.close()
    return render_template('inbox.html', messages=rows)


@app.route('/revoke/<int:file_id>/<int:target_id>', methods=['POST'])
@login_required
def revoke_access(file_id, target_id):
    # Only owner or admin can revoke
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT owner_id FROM files WHERE id=?', (file_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("File not found.")
        return redirect(url_for('files'))
    owner_id = row[0]
    if owner_id != g.user['id'] and g.user.get('role') != 'admin':
        conn.close()
        abort(403)
    c.execute('DELETE FROM file_access WHERE file_id=? AND user_id=?', (file_id, target_id))
    conn.commit()
    conn.close()
    flash('Access revoked.')
    return redirect(url_for('files'))

# ---- temp file APIs ----
@app.route('/temp-upload', methods=['POST'])
def temp_upload():
    if 'file' not in request.files:
        return {'error': 'No file part'}, 400
    file = request.files['file']
    if file.filename == '':
        return {'error': 'No selected file'}, 400
    filename = secure_filename(file.filename)
    file_content = file.read()
    import uuid
    file_id = str(uuid.uuid4())
    TEMP_FILES[file_id] = {
        'filename': filename,
        'content': file_content,
        'mime': guess_mime(filename, file_content),
        'timestamp': datetime.datetime.utcnow().isoformat()
    }
    return {
        'file_id': file_id,
        'filename': filename,
        'size': len(file_content),
        'mime': TEMP_FILES[file_id]['mime']
    }

@app.route('/temp-file/<file_id>')
def get_temp_file(file_id):
    if file_id not in TEMP_FILES:
        return {'error': 'File not found'}, 404
    f = TEMP_FILES[file_id]
    return send_file(io.BytesIO(f['content']),
                     download_name=f['filename'],
                     mimetype=f['mime'])

@app.route('/temp-file/<file_id>', methods=['DELETE'])
def delete_temp_file(file_id):
    if file_id not in TEMP_FILES:
        return {'error': 'File not found'}, 404
    del TEMP_FILES[file_id]
    return {'message': 'File deleted successfully'}

# ---- users ----
@app.route('/add-user')
def add_user_form():
    roles = [role.value for role in UserRole]
    return render_template('add_user.html', roles=roles)

@app.route('/users', methods=['GET','POST'])
def users():
    if request.method == 'POST':
        data = request.json
        if not data:
            return {'error': 'No data provided'}, 400
        username = (data.get('username') or "").strip()
        password = data.get('password')
        role = data.get('role', 'user')
        if not username or not password:
            return {'error': 'Username and password are required'}, 400
        # enforce complexity (create_user also validates)
        if not validate_password_complexity(password):
            return {
                'error': 'Weak password. Must be at least 12 characters and include upper, lower, number, and special character.'
            }, 400
        try:
            create_user(username, password, role)
        except ValueError as e:
            return {'error': str(e)}, 400
        except sqlite3.IntegrityError:
            return {'error': 'Username already exists'}, 400

        row = get_user_by_username(username)
        if not row:
            return {'error': 'Failed to create user'}, 500
        user_id, uname, pw_hash, urole, created_at = row
        return jsonify({'username': uname, 'role': urole, 'created_at': created_at}), 201

    # GET: list users from DB (no password hashes)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username, role, created_at FROM users ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    return jsonify({'users': [{'username': r[0], 'role': r[1], 'created_at': r[2]} for r in rows]})

@app.route('/users/<username>')
def get_user(username):
    row = get_user_by_username(username)
    if not row:
        return {'error': 'User not found'}, 404
    user_id, uname, pw_hash, role, created_at = row
    return jsonify({'username': uname, 'role': role, 'created_at': created_at})

# =========================================
# SECOND (simple) uploader NAMESPACED
# from app_simple.py, but under /simple/*
# =========================================
# crypto parts
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import mimetypes, secrets
SIMPLE_UPLOAD_DIR = Path("uploads")
SIMPLE_UPLOAD_DIR.mkdir(exist_ok=True)

PASSPHRASE = os.environ.get("FILESTORE_PASSPHRASE")
# if you want it optional, comment this out:
# if not PASSPHRASE:
#     raise RuntimeError("Set FILESTORE_PASSPHRASE")

SALT_PATH = Path("kdf_salt.bin")
if not SALT_PATH.exists():
    SALT_PATH.write_bytes(secrets.token_bytes(16))
SALT = SALT_PATH.read_bytes()

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode())

SIMPLE_KEY = _derive_key(PASSPHRASE, SALT) if PASSPHRASE else None

def simple_encrypt(plaintext: bytes) -> bytes:
    aes = AESGCM(SIMPLE_KEY)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct

def simple_decrypt(blob: bytes) -> bytes:
    aes = AESGCM(SIMPLE_KEY)
    nonce, ct = blob[:12], blob[12:]
    return aes.decrypt(nonce, ct, None)

def simple_is_image(filename: str) -> bool:
    mtype, _ = mimetypes.guess_type(filename)
    return (mtype or "").startswith("image/")

SIMPLE_INDEX_HTML = """
<!doctype html>
<title>Simple AES-GCM uploader</title>
<h1>Simple uploader (/simple)</h1>
<form method="post" enctype="multipart/form-data" action="/simple/upload">
  <input type="file" name="file" />
  <button type="submit">Upload</button>
</form>
<hr>
<ul>
{% for f in files %}
  <li>
    <a href="/simple/download/{{f.name}}">{{f.name}}</a>
    {% if f.is_image %}
      <img src="/simple/preview/{{f.name}}" style="max-width:200px;">
    {% endif %}
  </li>
{% endfor %}
</ul>
"""

@app.route("/simple")
def simple_index():
    items = []
    for p in sorted([p for p in SIMPLE_UPLOAD_DIR.iterdir() if p.is_file() and p.suffix == ".enc"],
                    key=lambda x: x.name.lower()):
        original = p.stem
        items.append({"name": original, "is_image": simple_is_image(original)})
    return render_template_string(SIMPLE_INDEX_HTML, files=items)

@app.route("/simple/upload", methods=["POST"])
def simple_upload():
    if SIMPLE_KEY is None:
        abort(500, description="FILESTORE_PASSPHRASE not set.")
    f = request.files.get("file")
    if not f or f.filename == "":
        return "No file selected", 400
    original_name = secure_filename(f.filename)
    data = f.read()
    blob = simple_encrypt(data)
    enc_path = SIMPLE_UPLOAD_DIR / (original_name + ".enc")
    if enc_path.exists():
        i = 1
        base, ext = os.path.splitext(original_name)
        while True:
            candidate = SIMPLE_UPLOAD_DIR / f"{base}({i}){ext}.enc"
            if not candidate.exists():
                enc_path = candidate
                break
            i += 1
    enc_path.write_bytes(blob)
    return redirect(url_for("simple_index"))

@app.route("/simple/download/<path:filename>")
def simple_download(filename):
    if SIMPLE_KEY is None:
        abort(500, description="FILESTORE_PASSPHRASE not set.")
    safe_name = secure_filename(filename)
    enc_path = SIMPLE_UPLOAD_DIR / (safe_name + ".enc")
    if not enc_path.exists():
        abort(404)
    blob = enc_path.read_bytes()
    plaintext = simple_decrypt(blob)
    mtype, _ = mimetypes.guess_type(safe_name)
    bio = BytesIO(plaintext); bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=safe_name, mimetype=mtype or "application/octet-stream")

@app.route("/simple/preview/<path:filename>")
def simple_preview(filename):
    if SIMPLE_KEY is None:
        abort(500, description="FILESTORE_PASSPHRASE not set.")
    safe_name = secure_filename(filename)
    if not simple_is_image(safe_name):
        abort(400, description="Preview only supports images.")
    enc_path = SIMPLE_UPLOAD_DIR / (safe_name + ".enc")
    if not enc_path.exists():
        abort(404)
    blob = enc_path.read_bytes()
    plaintext = simple_decrypt(blob)
    mtype, _ = mimetypes.guess_type(safe_name)
    bio = BytesIO(plaintext); bio.seek(0)
    return send_file(bio, mimetype=mtype or "application/octet-stream")

# =========================================
if __name__ == "__main__":
    init_db()
    # Allow overriding the host/port via environment for easier local network testing or docker use.
    run_host = os.environ.get('FLASK_RUN_HOST', os.environ.get('HOST', '127.0.0.1'))
    run_port = int(os.environ.get('PORT', 5000))
    run_debug = os.environ.get('FLASK_DEBUG', '1').lower() in ('1', 'true', 'yes')
    app.run(host=run_host, port=run_port, debug=run_debug)
