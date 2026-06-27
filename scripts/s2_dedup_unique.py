import os, hashlib, json, shutil
from pathlib import Path

WORKFLOW_DIR = Path('D:/MS/Project/data/workflows')
OUTPUT_DIR   = Path('D:/MS/Project/data/Unique_Dataset')

all_hashes = {}
copied = 0
skipped_dup = 0
skipped_invalid = 0

for source in sorted(os.listdir(WORKFLOW_DIR)):
    source_path = WORKFLOW_DIR / source
    if not source_path.is_dir():
        continue
    out_source = OUTPUT_DIR / source
    out_source.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(source_path):
        for f in files:
            if not f.endswith('.json'):
                continue
            filepath = Path(root) / f
            try:
                content = filepath.read_bytes()
                md5 = hashlib.md5(content).hexdigest()
                if md5 in all_hashes:
                    skipped_dup += 1
                    continue
                try:
                    json.loads(content)
                except:
                    skipped_invalid += 1
                    continue
                all_hashes[md5] = str(filepath)
                shutil.copy2(filepath, out_source / f)
                copied += 1
            except Exception as e:
                print(f'ERROR: {filepath}: {e}')

print('=== UNIQUE DATASET COPY RESULTS ===')
print(f'Files copied:         {copied}')
print(f'Duplicates skipped:   {skipped_dup}')
print(f'Invalid JSON skipped: {skipped_invalid}')
print(f'Output directory:     {OUTPUT_DIR}')
print()
print('=== PER SOURCE COUNTS ===')
for source in sorted(os.listdir(OUTPUT_DIR)):
    p = OUTPUT_DIR / source
    if p.is_dir():
        n = len(list(p.glob('*.json')))
        print(f'  {source}: {n} files')
