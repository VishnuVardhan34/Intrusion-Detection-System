# Intrusion Detection System Prototype

import re
import csv
import time
import html
from collections import defaultdict, Counter
from urllib.parse import unquote
from math import log2

class RateLimiter:
    def __init__(self, window=60, max_requests=100):
        self.window = window
        self.max_requests = max_requests
        self.requests = []

    def check(self):
        current_time = time.time()
        self.requests = [t for t in self.requests if current_time - t <= self.window]
        self.requests.append(current_time)
        return len(self.requests) <= self.max_requests

def load_patterns():
    """Enhanced detection patterns with improved accuracy"""
    return {
        "sql_injection": (  # Changed key to match normalized label
            r"(?i)"
            r"(?:"
            r"'.*?(?:or|and).*?(?:=|<|>).*?(?:'|\d+)|"  # Boolean-based
            r"union.*?select.*?(?:from|null|[0-9])|"     # Union-based
            r";\s*(?:select|insert|update|delete|drop)|"  # Stacked queries
            r"(?:--|#|\/\*.*?\*\/)|"                     # Comments
            r"(?:select|;)\s*(?:benchmark|sleep|wait)|"   # Time-based
            r"(?:into\s+(?:outfile|dumpfile))|"          # File ops
            r"(?:load_file|group_concat|concat_ws)|"      # Functions
            r"information_schema\.tables"                  # Meta
            r")"
        ),
        "cmd_injection": (  # Changed key to match normalized label
            r"(?i)"
            r"(?:"
            r"(?:[;&|`]|\|\||&&)\s*"                     # Command separators
            r"(?:"
            r"(?:cat|wget|curl|echo|rm|bash|chmod)\s+|"  # Common commands
            r"(?:\/bin\/|\/etc\/|\/tmp\/)|"              # Path traversal
            r"(?:ping\s+-[tc]\s*\d+)|"                   # ICMP
            r"(?:nc\s+-[elv]*\s*\d+)|"                   # Netcat
            r"(?:python\s+-c)|"                          # Python
            r"(?:[2>&1]|\d+>\&\d+)"                      # Redirection
            r")"
            r")"
        ),
        "xss": (  # Keep existing XSS pattern as it works well
            r"(?i)(?:"
            r"<[^>]*?(script|img|svg|iframe|embed|object|audio|video)[^>]*?>|"
            r"<[^>]*?\b(on\w+)\s*=|"
            r"\b(javascript|vbscript|data):\s*|"
            r"(document\.|window\.|eval|setTimeout|setInterval)|"
            r"(?:%3C|%3E|%22|%27|%3D|%7B|%7D)|"
            r"style\s*=\s*[\"`'][^`\"']*?(expression|url)\s*\("
            r")"
        )
    }

def check_entropy(text):
    """Calculate Shannon entropy to detect obfuscation"""
    if not text:
        return False
    entropy = 0
    text_len = len(text)
    for x in range(256):
        p_x = text.count(chr(x))/text_len
        if p_x > 0:
            entropy += - p_x * log2(p_x)
    return entropy > 5.0

def check_suspicious_chars(text):
    """Check for suspicious character sequences"""
    suspicious = re.compile(
        r'(?:%[0-9a-fA-F]{2}){2,}|'  # URL encoding
        r'&#[0-9]+;|'                 # HTML entities
        r'\\x[0-9a-fA-F]{2}|'        # Hex encoding
        r'\\u[0-9a-fA-F]{4}'         # Unicode encoding
    )
    return bool(suspicious.search(text))

def preprocess_payload(payload):
    """Enhanced preprocessing with multiple stages"""
    # URL decode (multiple passes for nested encoding)
    processed = payload
    while '%' in processed:
        decoded = unquote(processed)
        if decoded == processed:
            break
        processed = decoded

    # HTML entity decode
    processed = html.unescape(processed)
    
    # Normalize whitespace
    processed = ' '.join(processed.split())
    
    # Convert common evasion techniques
    processed = processed.replace('/*', ' ').replace('*/', ' ')
    processed = re.sub(r'\s+', ' ', processed)
    processed = re.sub(r'([;()])', r' \1 ', processed)
    
    return processed.strip()

def regex_to_dfa(pattern):
    """Convert regex pattern to DFA using Python's re module"""
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        print(f"Error compiling pattern: {e}")
        return None

def display_dfa(dfa):
    """Display information about the compiled regex pattern"""
    if dfa:
        print(f"Pattern: {dfa.pattern}")
        print("Flags:", ", ".join(flag.name for flag in re.RegexFlag 
              if dfa.flags & flag))
        print()

def check_intrusion(input_str, dfas):
    """Improved intrusion detection with better context handling"""
    processed = preprocess_payload(input_str)
    
    # More specific context detection
    is_sql = bool(re.search(r'\b(?:select|insert|update|delete|union|drop)\b', processed, re.I))
    is_cmd = bool(re.search(r'[;&|`]|(?:\b(?:rm|cat|chmod|wget|curl|nc|bash|sh)\b)', processed, re.I))
    
    for name, dfa in dfas.items():
        if not dfa:
            continue
            
        # Context-specific checks
        if name == "SQL Injection" and not is_sql:
            continue
        if name == "Command Injection" and not is_cmd:
            continue
            
        if dfa.search(processed):
            return True, name
            
    return False, None

def normalize_label(label):
    """Normalize classification labels to consistent format"""
    label = label.lower().strip()
    mapping = {
        'sql injection': 'sql_injection',
        'command injection': 'cmd_injection',
        'cmd injection': 'cmd_injection',
        'shell injection': 'cmd_injection',
        'cross site scripting': 'xss',
        'xss attack': 'xss'
    }
    return mapping.get(label, label)

def load_labeled_dataset(file_path):
    records = []
    try:
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append({
                    'id': row.get('id', ''),
                    'payload': row.get('payload', ''),
                    'label': normalize_label(row.get('label', 'benign'))
                })
    except FileNotFoundError:
        print(f"Error: Dataset file not found at {file_path}")
        return []
    return records

def main():
    print("Intrusion Detection System\n")

    # Load patterns and convert to DFAs
    patterns = load_patterns()
    dfas = {name: regex_to_dfa(pattern) for name, pattern in patterns.items()}

    print("DFA Details for Patterns:\n")
    for name, dfa in dfas.items():
        print(f"Pattern: {name}")
        display_dfa(dfa)

    # Update pattern label mapping to match normalized labels
    pattern_label_map = {
        "sql_injection": "sql_injection",
        "cmd_injection": "cmd_injection",
        "xss": "xss"
    }

    # Load dataset with normalized labels
    dataset_path = "d:\\TOC\\intrusion_detection_system\\large_dataset.csv"
    records = load_labeled_dataset(dataset_path)

    if not records:
        print("No records to process. Please check the dataset file.")
        return

    # Evaluation
    total = 0
    correct = 0
    tp = Counter()
    fp = Counter()
    fn = Counter()
    classes = set()

    print(f"\nProcessing {len(records)} records...")
    for i, rec in enumerate(records):
        total += 1
        payload = rec["payload"]
        actual = normalize_label(rec["label"])  # Normalize before comparison
        is_intrusion, detected_type = check_intrusion(payload, dfas)
        predicted = normalize_label(detected_type.lower() if is_intrusion else "benign")
        
        classes.add(actual)
        classes.add(predicted)
        
        if predicted == actual:
            correct += 1
            tp[predicted] += 1
        else:
            fp[predicted] += 1
            fn[actual] += 1
        
        if i % 100 == 0:
            print(f"Processed {i}/{len(records)} records...")
        elif predicted != actual:
            print(f"Misclassification - ID {rec['id']}: predicted={predicted} actual={actual}")

    # Results
    accuracy = correct / total if total else 0.0
    print(f"\nTotal: {total}  Correct: {correct}  Accuracy: {accuracy:.3f}\n")

    print("Per-class metrics:")
    for cls in sorted(classes):
        tp_v = tp[cls]
        fp_v = fp[cls]
        fn_v = fn[cls]
        precision = tp_v / (tp_v + fp_v) if (tp_v + fp_v) else 0
        recall = tp_v / (tp_v + fn_v) if (tp_v + fn_v) else 0
        print(f" {cls}: TP={tp_v} FP={fp_v} FN={fn_v}  "
              f"Precision={precision:.3f}  Recall={recall:.3f}")

if __name__ == "__main__":
    main()