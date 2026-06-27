import os, hashlib, json
from pathlib import Path
from collections import defaultdict

RAW_DIR    = Path('D:/MS/Project/data/workflows')
UNIQUE_DIR = Path('D:/MS/Project/data/Unique_Dataset')

print('=== INDEPENDENT DEDUP RE-VERIFICATION ===')
print()

# --- PART 1: Re-hash the RAW directory from scratch ---
raw_total = 0
raw_hashes = defaultdict(list)   # md5 -> list of filepaths
raw_invalid = []

for root, dirs, files in os.walk(RAW_DIR):
    # Skip the Unique_Dataset folder if it is inside data (it is not, but guard anyway)
    if 'Unique_Dataset' in root:
        continue
    for f in files:
        if not f.endswith('.json'):
            continue
        raw_total += 1
        fp = Path(root) / f
        content = fp.read_bytes()
        md5 = hashlib.md5(content).hexdigest()
        raw_hashes[md5].append(str(fp))
        try:
            json.loads(content)
        except:
            raw_invalid.append(str(fp))

unique_hashes = len(raw_hashes)
dup_count = raw_total - unique_hashes

print('--- RAW DIRECTORY ---')
print(f'Total raw .json files:       {raw_total}')
print(f'Distinct MD5 hashes:         {unique_hashes}')
print(f'Duplicate files:             {dup_count}')
print(f'Invalid JSON files:          {len(raw_invalid)}')
print(f'Unique valid (hashes-invalid_among_unique):')

# Count how many of the UNIQUE hashes are invalid
invalid_unique = 0
for md5, paths in raw_hashes.items():
    # use first occurrence as the representative
    rep = paths[0]
    try:
        json.loads(Path(rep).read_bytes())
    except:
        invalid_unique += 1
print(f'  Unique hashes that are invalid JSON: {invalid_unique}')
print(f'  Unique VALID files:                  {unique_hashes - invalid_unique}')

print()

# --- PART 2: Hash the UNIQUE_DATASET directory ---
uniq_total = 0
uniq_hashes = set()
uniq_invalid = []
uniq_dupes_within = 0

for root, dirs, files in os.walk(UNIQUE_DIR):
    for f in files:
        if not f.endswith('.json'):
            continue
        uniq_total += 1
        fp = Path(root) / f
        content = fp.read_bytes()
        md5 = hashlib.md5(content).hexdigest()
        if md5 in uniq_hashes:
            uniq_dupes_within += 1
        uniq_hashes.add(md5)
        try:
            json.loads(content)
        except:
            uniq_invalid.append(str(fp))

print('--- UNIQUE_DATASET DIRECTORY ---')
print(f'Total files in Unique_Dataset:    {uniq_total}')
print(f'Distinct MD5 hashes:              {len(uniq_hashes)}')
print(f'Duplicates WITHIN Unique_Dataset: {uniq_dupes_within}')
print(f'Invalid JSON in Unique_Dataset:   {len(uniq_invalid)}')

print()
print('--- CROSS CHECK ---')
print(f'Raw unique valid count:           {unique_hashes - invalid_unique}')
print(f'Unique_Dataset file count:        {uniq_total}')
print(f'Unique_Dataset distinct hashes:   {len(uniq_hashes)}')
match = (unique_hashes - invalid_unique) == uniq_total == len(uniq_hashes)
print(f'ALL THREE MATCH: {match}')

print()
print('--- DUPLICATE EXAMPLES (first 5 md5 with >1 file) ---')
shown = 0
for md5, paths in raw_hashes.items():
    if len(paths) > 1:
        print(f'  MD5 {md5[:12]}... appears {len(paths)} times:')
        for p in paths[:3]:
            print(f'      {p}')
        shown += 1
        if shown >= 5:
            break

print()
print('=== VERIFICATION COMPLETE ===')
