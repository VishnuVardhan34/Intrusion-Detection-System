"""
Convert FuzzDB attack patterns to CSV format.
Clone first: git clone https://github.com/fuzzdb-project/fuzzdb.git
"""
import csv
import os
import glob

def load_fuzzdb_patterns(fuzzdb_root, output_csv):
    """Load FuzzDB attack patterns and convert to CSV."""
    records = []
    record_id = 0
    
    # SQL Injection patterns
    sql_dirs = [
        'attack/sql-injection',
        'attack/sql-injection/detect',
    ]
    for sql_dir in sql_dirs:
        pattern = os.path.join(fuzzdb_root, sql_dir, '*.txt')
        for file_path in glob.glob(pattern):
            print(f"Loading SQL patterns from {file_path}...")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        records.append({
                            'id': f'fuzzdb_{record_id}',
                            'payload': line,
                            'label': 'sql_injection'
                        })
                        record_id += 1
    
    # XSS patterns
    xss_dirs = [
        'attack/xss',
    ]
    for xss_dir in xss_dirs:
        pattern = os.path.join(fuzzdb_root, xss_dir, '*.txt')
        for file_path in glob.glob(pattern):
            print(f"Loading XSS patterns from {file_path}...")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        records.append({
                            'id': f'fuzzdb_{record_id}',
                            'payload': line,
                            'label': 'xss'
                        })
                        record_id += 1
    
    # Command injection patterns
    cmd_dirs = [
        'attack/os-cmd-execution',
        'attack/os-dir-indexing',
    ]
    for cmd_dir in cmd_dirs:
        pattern = os.path.join(fuzzdb_root, cmd_dir, '*.txt')
        for file_path in glob.glob(pattern):
            print(f"Loading CMD patterns from {file_path}...")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        records.append({
                            'id': f'fuzzdb_{record_id}',
                            'payload': line,
                            'label': 'cmd_injection'
                        })
                        record_id += 1
    
    # Add benign samples (from generic patterns)
    benign_samples = [
        'SELECT * FROM users WHERE id = 1',
        'GET /api/users HTTP/1.1',
        '<div>Hello World</div>',
        'npm install express',
        'python manage.py runserver',
        'git clone https://github.com/user/repo',
        'docker run nginx',
        'UPDATE users SET last_login = NOW() WHERE id = 123',
        '<span class="user-name">John Doe</span>',
        'curl -I https://api.example.com/status',
    ]
    
    # Replicate benign samples to balance dataset
    attack_count = len(records)
    benign_count_needed = attack_count // 3  # 1:3 ratio (benign:attack)
    
    for i in range(benign_count_needed):
        sample = benign_samples[i % len(benign_samples)]
        records.append({
            'id': f'benign_{i}',
            'payload': sample,
            'label': 'benign'
        })
    
    # Write to CSV
    print(f"\nWriting {len(records)} records to {output_csv}...")
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['id', 'payload', 'label'])
        writer.writeheader()
        writer.writerows(records)
    
    # Print statistics
    label_counts = {}
    for rec in records:
        label = rec['label']
        label_counts[label] = label_counts.get(label, 0) + 1
    
    print(f"\n✓ Dataset created: {output_csv}")
    print("\nLabel distribution:")
    for label, count in sorted(label_counts.items()):
        print(f"  {label}: {count} samples")
    print(f"\nTotal: {len(records)} records")
    
    return len(records)

if __name__ == '__main__':
    fuzzdb_root = './fuzzdb'  # Update after cloning
    output_csv = 'fuzzdb_dataset.csv'
    
    if os.path.exists(fuzzdb_root):
        load_fuzzdb_patterns(fuzzdb_root, output_csv)
    else:
        print("ERROR: fuzzdb directory not found!")
        print("Clone FuzzDB first: git clone https://github.com/fuzzdb-project/fuzzdb.git")