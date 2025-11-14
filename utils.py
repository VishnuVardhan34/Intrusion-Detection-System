import csv
import os

def normalize_label(label):
    if not label:
        return "benign"
    l = label.lower().strip()
    mapping = {
        'sql injection': 'sql_injection',
        'sql_injection': 'sql_injection',
        'command injection': 'cmd_injection',
        'cmd_injection': 'cmd_injection',
        'cmd injection': 'cmd_injection',
        'xss attack': 'xss',
        'cross site scripting': 'xss',
        'xss': 'xss',
        'benign': 'benign'
    }
    return mapping.get(l, l.replace(' ', '_'))

def load_labeled_dataset(file_path):
    records = []
    if not os.path.isfile(file_path):
        return records
    with open(file_path, mode='r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append({
                'id': row.get('id', ''),
                'payload': row.get('payload', ''),
                'label': normalize_label(row.get('label', 'benign'))
            })
    return records