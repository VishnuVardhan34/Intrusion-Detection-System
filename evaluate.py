import csv
import json
import os
import sys
import re
from collections import defaultdict, Counter

# Try to import helpers from main.py; provide fallbacks if missing
try:
    from main import (
        load_patterns,
        regex_to_dfa,
        preprocess_payload,
        check_intrusion,
        load_labeled_dataset,
        normalize_label
    )
except Exception:
    # Fallbacks
    try:
        import main as main_mod
        load_patterns = getattr(main_mod, "load_patterns", None)
        regex_to_dfa = getattr(main_mod, "regex_to_dfa", None)
        preprocess_payload = getattr(main_mod, "preprocess_payload", None)
        check_intrusion = getattr(main_mod, "check_intrusion", None)
        load_labeled_dataset = getattr(main_mod, "load_labeled_dataset", None)
        normalize_label = getattr(main_mod, "normalize_label", None)
    except Exception:
        load_patterns = regex_to_dfa = preprocess_payload = check_intrusion = load_labeled_dataset = normalize_label = None

# Basic defaults if functions are missing
def _default_load_patterns():
    return {
        "sql_injection": r"(?i)(?:union\s+select|select.*from|or\s+1=1|;\s*(?:drop|insert|update|delete))",
        "xss": r"(?i)(?:<script|javascript:|onerror=|onload=)",
        "cmd_injection": r"(?i)(?:[;&|`]\s*(?:rm|cat|wget|curl|nc|bash|powershell))"
    }

def _default_regex_to_dfa(pat):
    try:
        return re.compile(pat, re.IGNORECASE)
    except re.error:
        return re.compile(re.escape(pat), re.IGNORECASE)

def _default_preprocess(payload):
    try:
        from urllib.parse import unquote
        import html
        p = payload
        # simple url/html decode pass
        p = unquote(p)
        p = html.unescape(p)
        p = ' '.join(p.split())
        return p
    except Exception:
        return payload

def _default_load_labeled_dataset(path):
    recs = []
    if not os.path.isfile(path):
        return recs
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            recs.append({
                "id": row.get("id", ""),
                "payload": row.get("payload", ""),
                "label": row.get("label", "benign")
            })
    return recs

def _default_normalize_label(label):
    if not label:
        return "benign"
    l = label.lower().strip()
    mapping = {
        "sql injection": "sql_injection",
        "sql_injection": "sql_injection",
        "command injection": "cmd_injection",
        "cmd_injection": "cmd_injection",
        "command_inject": "cmd_injection",
        "xss attack": "xss",
        "cross site scripting": "xss",
        "xss": "xss",
        "benign": "benign"
    }
    return mapping.get(l, l.replace(" ", "_"))

# Use provided or fallback implementations
load_patterns = load_patterns or _default_load_patterns
regex_to_dfa = regex_to_dfa or _default_regex_to_dfa
preprocess_payload = preprocess_payload or _default_preprocess
load_labeled_dataset = load_labeled_dataset or _default_load_labeled_dataset
normalize_label = normalize_label or _default_normalize_label
check_intrusion = check_intrusion  # may be None; handled later

def build_dfas():
    patterns = load_patterns()
    dfas = {}
    for name, pat in patterns.items():
        if callable(regex_to_dfa):
            dfas[name] = regex_to_dfa(pat)
        else:
            dfas[name] = re.compile(pat, re.IGNORECASE)
    return dfas

def predict_with_dfas(payload, dfas):
    text = preprocess_payload(payload)
    for name, dfa in dfas.items():
        if dfa and dfa.search(text):
            return True, name
    return False, None

def evaluate(dataset_path,
             out_mis='misclassified_samples.csv',
             out_stats='evaluation_stats.json',
             limit=None):
    dfas = build_dfas()
    records = load_labeled_dataset(dataset_path)
    if limit:
        records = records[:limit]

    stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    misclassified = []
    total = 0
    correct = 0
    classes = set()

    for rec in records:
        total += 1
        payload = rec.get("payload", "")
        raw_label = rec.get("label", "benign")
        actual = normalize_label(raw_label)
        classes.add(actual)

        # Use main.check_intrusion if available, else local DFAs
        if callable(check_intrusion):
            try:
                intr, det = check_intrusion(payload, dfas)
                predicted = normalize_label(det) if intr and det else "benign"
            except Exception:
                intr, det = predict_with_dfas(payload, dfas)
                predicted = normalize_label(det) if intr and det else "benign"
        else:
            intr, det = predict_with_dfas(payload, dfas)
            predicted = normalize_label(det) if intr and det else "benign"

        classes.add(predicted)

        if predicted == actual:
            correct += 1
            stats[actual]["tp"] += 1
        else:
            stats[predicted]["fp"] += 1
            stats[actual]["fn"] += 1
            misclassified.append({
                "id": rec.get("id", ""),
                "payload": payload,
                "actual": actual,
                "predicted": predicted
            })

    accuracy = correct / total if total else 0.0

    # compute per-class precision/recall
    per_class = {}
    for cls in sorted(classes):
        tp = stats[cls]["tp"]
        fp = stats[cls]["fp"]
        fn = stats[cls]["fn"]
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec_ = tp / (tp + fn) if (tp + fn) else 0.0
        per_class[cls] = {"tp": tp, "fp": fp, "fn": fn, "precision": round(prec, 3), "recall": round(rec_, 3)}

    # write misclassified samples
    with open(out_mis, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["id", "payload", "actual", "predicted"])
        writer.writeheader()
        for m in misclassified:
            writer.writerow(m)

    # write stats
    summary = {
        "total": total,
        "correct": correct,
        "accuracy": round(accuracy, 3),
        "per_class": per_class,
        "misclassified_count": len(misclassified),
        "misclassified_file": os.path.abspath(out_mis)
    }
    with open(out_stats, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)

    # print concise summary
    print(f"Total: {total}  Correct: {correct}  Accuracy: {accuracy:.3f}")
    print("\nPer-class metrics:")
    for cls, vals in per_class.items():
        print(f" {cls}: TP={vals['tp']} FP={vals['fp']} FN={vals['fn']}  Precision={vals['precision']:.3f}  Recall={vals['recall']:.3f}")
    print(f"\nSaved {len(misclassified)} misclassified samples -> {os.path.abspath(out_mis)}")
    print(f"Saved evaluation summary -> {os.path.abspath(out_stats)}")
    return summary, misclassified

if __name__ == "__main__":
    ds = "d:\\TOC\\intrusion_detection_system\\large_dataset.csv"
    if len(sys.argv) > 1:
        ds = sys.argv[1]
    evaluate(ds)