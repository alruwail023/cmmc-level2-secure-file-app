"""
Export the SQLite DB and uploads folder into a zip for sharing.
Usage: python scripts/export_data.py [output.zip]
If DATA_DIR is set it will use that; otherwise uses repo-local files.db and uploads/.
"""
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.environ.get('DATA_DIR')
if DATA_DIR:
    db_path = os.path.join(DATA_DIR, 'files.db')
    uploads_dir = os.path.join(DATA_DIR, 'uploads')
else:
    db_path = os.path.join(ROOT, 'files.db')
    uploads_dir = os.path.join(ROOT, 'uploads')

out_name = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'secure_uploader_export.zip')

with zipfile.ZipFile(out_name, 'w', zipfile.ZIP_DEFLATED) as z:
    if os.path.exists(db_path):
        z.write(db_path, arcname=os.path.basename(db_path))
    else:
        print(f'Warning: DB not found at {db_path}', file=sys.stderr)
    if os.path.exists(uploads_dir):
        for root, dirs, files in os.walk(uploads_dir):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, os.path.dirname(uploads_dir))
                z.write(full, arcname=os.path.join('uploads', os.path.relpath(full, uploads_dir)))
    else:
        print(f'Warning: uploads dir not found at {uploads_dir}', file=sys.stderr)

print('Exported to', out_name)
