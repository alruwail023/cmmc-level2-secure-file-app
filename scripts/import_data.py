"""
Import an exported zip (created by export_data.py) into the current repo or DATA_DIR.
Usage: python scripts/import_data.py secure_uploader_export.zip
This will overwrite files.db and the uploads/ folder in the target location.
"""
import os
import sys
import zipfile
import shutil

ROOT = os.path.dirname(os.path.dirname(__file__))
if len(sys.argv) < 2:
    print('Usage: python scripts/import_data.py <archive.zip> [--to-data-dir]')
    sys.exit(2)

archive = sys.argv[1]
to_data_dir = '--to-data-dir' in sys.argv
DATA_DIR = os.environ.get('DATA_DIR') if to_data_dir else None

if DATA_DIR:
    target_db = os.path.join(DATA_DIR, 'files.db')
    target_uploads = os.path.join(DATA_DIR, 'uploads')
else:
    target_db = os.path.join(ROOT, 'files.db')
    target_uploads = os.path.join(ROOT, 'uploads')

if not os.path.exists(archive):
    print('Archive not found:', archive)
    sys.exit(1)

with zipfile.ZipFile(archive, 'r') as z:
    # Extract DB
    for name in z.namelist():
        if os.path.basename(name) == 'files.db':
            os.makedirs(os.path.dirname(target_db), exist_ok=True)
            z.extract(name, os.path.dirname(target_db))
            # move to exact target path
            extracted = os.path.join(os.path.dirname(target_db), name)
            shutil.move(extracted, target_db)
            print('Restored DB to', target_db)
        elif name.startswith('uploads/'):
            # extract into a temp dir then move
            z.extract(name, os.path.dirname(target_uploads))

# Move extracted uploads (zip writes uploads/... relative paths)
# The extraction put files under <parent_of_target_uploads>/uploads/..., so ensure target_uploads
extracted_root = os.path.join(os.path.dirname(target_uploads), 'uploads')
if os.path.exists(extracted_root):
    if os.path.exists(target_uploads):
        shutil.rmtree(target_uploads)
    shutil.move(extracted_root, target_uploads)
    print('Restored uploads to', target_uploads)

print('Import complete')
