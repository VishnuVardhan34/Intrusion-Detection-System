"""
Convert CSIC 2010 dataset to CSV format compatible with your system.
Download from: http://www.isi.csic.es/dataset/
"""
import csv
import os
import re
from urllib.parse import unquote

def parse_csic_file(file_path, label):
    """Parse CSIC HTTP request file and extract payloads."""
    records = []
    with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
        content = f.read()
    
    # Split by request delimiter
    requests = content.split('\n\n')
    
    for i, req in enumerate(requests):
        if not req.strip():
            continue
        
        # Extract URL and parameters
        lines = req.split('\n')
        if not lines:
            continue
        
        request_line = lines[0]
        
        # Get query string and POST data
        payload = request_line
        for line in lines[1:]:
            if line.strip():
                payload += ' ' + line.strip()
        
        # Classify based on patterns
        payload_lower = payload.lower()
        
        if label == 'anomalous':
            # Try to identify attack type
            if re.search(r'(?:union|select|insert|update|delete|drop|\'|--|;)', payload_lower):
                attack_type = 'sql_injection'
            elif re.search(r'(?:<script|javascript:|onerror=|onload=)', payload_lower):
                attack_type = 'xss'
            elif re.search(r'(?:[;&|`]|\.\.\/|\/etc\/|cmd\.exe)', payload_lower):
                attack_type = 'cmd_injection'
            else:
                attack_type = 'other_attack'
        else:
            attack_type = 'benign'
        
        records.append({
            'id': f'csic_{label}_{i}',
            'payload': payload[:500],  # Limit length
            'label': attack_type
        })
    
    return records

def convert_csic_to_csv(normal_file, anomalous_file, output_csv):
    """Convert CSIC dataset to CSV format."""
    all_records = []
    
    print(f"Processing normal traffic from {normal_file}...")
    all_records.extend(parse_csic_file(normal_file, 'normal'))
    
    print(f"Processing anomalous traffic from {anomalous_file}...")
    all_records.extend(parse_csic_file(anomalous_file, 'anomalous'))
    
    print(f"Writing {len(all_records)} records to {output_csv}...")
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['id', 'payload', 'label'])
        writer.writeheader()
        writer.writerows(all_records)
    
    print(f"✓ Conversion complete: {output_csv}")
    return len(all_records)

if __name__ == '__main__':
    # Update these paths after downloading CSIC 2010
    normal_file = 'normalTrafficTraining.txt'
    anomalous_file = 'anomalousTrafficTest.txt'
    output_csv = 'csic2010_dataset.csv'
    
    if os.path.exists(normal_file) and os.path.exists(anomalous_file):
        convert_csic_to_csv(normal_file, anomalous_file, output_csv)
    else:
        print("Download CSIC 2010 dataset files first:")
        print("http://www.isi.csic.es/dataset/")