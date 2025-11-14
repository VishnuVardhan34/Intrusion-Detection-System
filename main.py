# Intrusion Detection System Prototype

import re
import csv
import time
import html
from collections import defaultdict, Counter
import json
import os
import sys

from patterns import load_patterns
from detector import regex_to_dfa, display_dfa, check_intrusion, RateLimiter
from utils import load_labeled_dataset, normalize_label
from ml_fallback import train_cmd_model, load_cmd_model

def build_dfas():
    patterns = load_patterns()
    return {name: regex_to_dfa(pat) for name, pat in patterns.items()}

def evaluate(records, dfas, ml_model=None, out_stats='evaluation_stats.json'):
    total = 0
    correct = 0
    tp = Counter()
    fp = Counter()
    fn = Counter()
    classes = set()
    rate_limiter = RateLimiter(window=60, max_requests=1000)

    mis = []

    for rec in records:
        total += 1
        payload = rec['payload']
        actual = normalize_label(rec.get('label','benign'))
        intr, det = check_intrusion(payload, dfas, ml_fallback=ml_model, rate_limiter=rate_limiter)
        predicted = normalize_label(det) if intr and det else 'benign'
        classes.add(actual); classes.add(predicted)

        if predicted == actual:
            correct += 1
            tp[predicted] += 1
        else:
            fp[predicted] += 1
            fn[actual] += 1
            mis.append({'id': rec.get('id',''), 'payload': payload, 'actual': actual, 'predicted': predicted})

    accuracy = correct / total if total else 0.0
    per_class = {}
    for cls in sorted(classes):
        tp_v = tp[cls]; fp_v = fp[cls]; fn_v = fn[cls]
        prec = tp_v / (tp_v + fp_v) if (tp_v + fp_v) else 0.0
        rec = tp_v / (tp_v + fn_v) if (tp_v + fn_v) else 0.0
        per_class[cls] = {'tp': tp_v, 'fp': fp_v, 'fn': fn_v, 'precision': round(prec,3), 'recall': round(rec,3)}

    summary = {'total': total, 'correct': correct, 'accuracy': round(accuracy,3), 'per_class': per_class}
    with open(out_stats, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    # save misclassified
    with open('misclassified_samples.csv', 'w', encoding='utf-8', newline='') as f:
        import csv
        w = csv.DictWriter(f, fieldnames=['id','payload','actual','predicted'])
        w.writeheader()
        w.writerows(mis)
    return summary

def main():
    print("Intrusion Detection System\n")

    dataset = os.path.join(os.path.dirname(__file__), 'large_dataset.csv')
    records = load_labeled_dataset(dataset)
    dfas = build_dfas()

    # display patterns
    print("DFA Details:")
    for name, d in dfas.items():
        print("Pattern:", name)
        display_dfa(d)

    # train/load cmd model
    model = None
    model_path = os.path.join(os.path.dirname(__file__), 'cmd_model.joblib')
    if os.path.exists(model_path):
        model = load_cmd_model(model_path)
    else:
        try:
            print("Training cmd_injection fallback model...")
            model = train_cmd_model(dataset, out_path=model_path)
        except Exception as e:
            print("Training skipped:", e)
            model = None

    print("Evaluating dataset...")
    summary = evaluate(records, dfas, ml_model=model)
    print("Summary:", summary)

if __name__ == '__main__':
    main()