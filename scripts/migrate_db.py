"""
Simple migration to ensure `files` table has owner_id column and `file_access` table exists.
Usage: python scripts/migrate_db.py
"""
import os
import sqlite3

DATA_DIR = os.environ.get('DATA_DIR')
ROOT = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, 'files.db') if DATA_DIR else os.path.join(ROOT, 'files.db')
print('Using DB at', DB_PATH)
if not os.path.exists(DB_PATH):
    print('DB file not found; nothing to migrate.')
    exit(0)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
# check files table columns
c.execute("PRAGMA table_info(files)")
cols = [r[1] for r in c.fetchall()]
if 'owner_id' not in cols:
    print('Adding owner_id column to files table')
    c.execute('ALTER TABLE files ADD COLUMN owner_id INTEGER DEFAULT 0')
else:
    print('owner_id already present')

# create file_access table if missing
c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file_access'")
if not c.fetchone():
    print('Creating file_access table')
    c.execute('''
    CREATE TABLE IF NOT EXISTS file_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        can_read INTEGER NOT NULL DEFAULT 1,
        can_delete INTEGER NOT NULL DEFAULT 0,
        UNIQUE(file_id, user_id)
    )
    ''')
else:
    print('file_access already present')

# try to set owner_id for existing files: if any user exists, set to first user's id where owner_id==0
c.execute("SELECT id FROM users ORDER BY id LIMIT 1")
user = c.fetchone()
if user:
    uid = user[0]
    print('Setting owner_id for existing files to user id', uid)
    c.execute('UPDATE files SET owner_id=? WHERE owner_id IS NULL OR owner_id=0', (uid,))

conn.commit()
conn.close()
print('Migration complete')
