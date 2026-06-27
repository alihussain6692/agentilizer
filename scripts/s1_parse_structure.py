"""
RESEARCH STEP 2 — Workflow Structure Validation
Fresh research run — do not reference previous numbers
"""
import os, hashlib, json
from collections import defaultdict

WORKFLOW_DIR = 'D:/MS/Project/data/workflows'

# Collect unique valid files (same dedup logic as Step 1)
all_hashes = {}
unique_files = []

for source in os.listdir(WORKFLOW_DIR):
    source_path = os.path.join(WORKFLOW_DIR, source)
    if not os.path.isdir(source_path):
        continue
    for root, dirs, files in os.walk(source_path):
        for f in files:
            if not f.endswith('.json'):
                continue
            filepath = os.path.join(root, f)
            try:
                with open(filepath, 'rb') as fh:
                    content = fh.read()
                md5 = hashlib.md5(content).hexdigest()
                if md5 not in all_hashes:
                    try:
                        data = json.loads(content)
                        all_hashes[md5] = filepath
                        unique_files.append((filepath, data))
                    except:
                        pass
            except:
                pass

print(f'Unique valid files loaded: {len(unique_files)}')

# Analyse structure
has_nodes = 0
has_connections = 0
has_name = 0
total_nodes = 0
node_types = defaultdict(int)
min_nodes = float('inf')
max_nodes = 0
workflows_with_zero_nodes = 0
workflows_with_one_node = 0
workflows_usable = 0  # has nodes key AND at least 1 node

for filepath, data in unique_files:
    nodes = []
    if isinstance(data, dict):
        if 'nodes' in data:
            has_nodes += 1
            nodes = data['nodes'] if isinstance(data['nodes'], list) else []
        if 'connections' in data:
            has_connections += 1
        if 'name' in data:
            has_name += 1

    n = len(nodes)
    total_nodes += n
    if n == 0:
        workflows_with_zero_nodes += 1
    elif n == 1:
        workflows_with_one_node += 1

    if n >= 2:
        workflows_usable += 1
        min_nodes = min(min_nodes, n)
        max_nodes = max(max_nodes, n)

    for node in nodes:
        if isinstance(node, dict) and 'type' in node:
            node_types[node['type']] += 1

print()
print('=== WORKFLOW STRUCTURE ===')
print(f'Workflows with nodes key:      {has_nodes}')
print(f'Workflows with connections key: {has_connections}')
print(f'Workflows with name key:        {has_name}')
print(f'Workflows with 0 nodes:         {workflows_with_zero_nodes}')
print(f'Workflows with 1 node:          {workflows_with_one_node}')
print(f'Workflows with 2+ nodes:        {workflows_usable}')
print(f'Min nodes (2+ workflows):       {min_nodes}')
print(f'Max nodes:                      {max_nodes}')
print(f'Total node instances:           {total_nodes}')
print(f'Avg nodes per workflow:         {total_nodes/len(unique_files):.1f}')
print()
print('=== TOP 20 NODE TYPES ===')
for nt, cnt in sorted(node_types.items(), key=lambda x: -x[1])[:20]:
    print(f'  {cnt:6d}  {nt}')
print(f'\nTotal distinct node types: {len(node_types)}')

print()
print('=== SUMMARY ===')
print(f'Total unique valid workflows:   {len(unique_files)}')
print(f'Usable for analysis (2+ nodes): {workflows_usable}')
print(f'Excluded (0 or 1 node):         {len(unique_files) - workflows_usable}')