import json
import sys
import os
from pathlib import Path

# plotting libs
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def load_stats(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Stats file not found: {path}")
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def per_class_df(stats, label):
    rows = []
    for cls, v in stats.get('per_class', {}).items():
        rows.append({
            'algorithm': label,
            'class': cls,
            'tp': v.get('tp', 0),
            'fp': v.get('fp', 0),
            'fn': v.get('fn', 0),
            'precision': v.get('precision', 0.0),
            'recall': v.get('recall', 0.0)
        })
    return pd.DataFrame(rows)

def plot_precision_recall(baseline_df, hybrid_df, out_dir):
    df = pd.concat([baseline_df, hybrid_df], ignore_index=True)
    sns.set(style="whitegrid")
    df_m = df.melt(id_vars=['algorithm','class'], value_vars=['precision','recall'],
                   var_name='metric', value_name='value')
    plt.figure(figsize=(10,6))
    sns.barplot(data=df_m, x='class', y='value', hue='algorithm', ci=None, palette='muted')
    plt.ylim(0,1.05)
    plt.title('Per-class Precision & Recall: baseline vs hybrid')
    plt.legend(title='Algorithm')
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir,'precision_recall_comparison.png'))
    plt.close()

def plot_class_distribution(summary, label, out_dir):
    counts = {}
    for cls,v in summary.get('per_class', {}).items():
        counts[cls] = v.get('tp',0) + v.get('fn',0)
    s = pd.Series(counts)
    plt.figure(figsize=(6,6))
    s.plot.pie(autopct='%1.1f%%', startangle=90)
    plt.title(f'Class distribution ({label})')
    plt.ylabel('')
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir,f'class_distribution_{label}.png'))
    plt.close()

def main(baseline_json, hybrid_json, out_dir='analysis_outputs'):
    # verify inputs
    for p in (baseline_json, hybrid_json):
        if not os.path.isfile(p):
            print(f"Error: required file not found: {p}")
            print("Generate evaluation stats with evaluate.py first, e.g.:")
            print("  python evaluate.py large_dataset.csv")
            sys.exit(1)

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    try:
        base = load_stats(baseline_json)
        hyp = load_stats(hybrid_json)
    except Exception as e:
        print("Failed to load stats JSON:", e)
        sys.exit(1)

    base_df = per_class_df(base, 'baseline')
    hyp_df = per_class_df(hyp, 'hybrid')

    try:
        plot_precision_recall(base_df, hyp_df, out_dir)
        plot_class_distribution(base, 'baseline', out_dir)
        plot_class_distribution(hyp, 'hybrid', out_dir)
        pd.concat([base_df, hyp_df]).to_csv(os.path.join(out_dir,'per_class_comparison.csv'), index=False)
    except Exception as e:
        print("Plotting failed:", e)
        sys.exit(1)

    print('Saved plots and CSV to', os.path.abspath(out_dir))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python analysis_plot.py baseline_stats.json hybrid_stats.json')
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])