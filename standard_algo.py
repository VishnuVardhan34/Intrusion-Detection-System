"""
Standard algorithms driver:
- Thompson's construction (regex -> NFA)
- Subset (powerset) construction (NFA -> DFA)
- Hopcroft's minimization (DFA minimize)
- Evaluate on dataset CSV (same format as hybrid)
- Produce evaluation JSON and comparison plots (if hybrid_stats provided)
"""

import csv
import json
import os
import re
import time
import argparse
from collections import defaultdict, deque
import math

# plotting libs
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Basic regex parser for a subset of regex syntax:
# supports concatenation (implicit), union '|', Kleene '*' , plus '+', question '?', grouping '(' ')', and escaped chars '\x'
# NOTE: This is a small engine for converting many practical patterns; complex PCRE features fall back to Python re.

# ---------- NFA representation ----------
class State:
    def __init__(self):
        self.edges = defaultdict(list)  # symbol -> list of states
        self.epsilon = []               # epsilon transitions

class NFA:
    def __init__(self, start: State, accept: State):
        self.start = start
        self.accept = accept

# ---------- Thompson construction ----------
def regex_to_postfix(regex):
    """Shunting-yard to convert regex to postfix (supporting implicit concatenation)."""
    # insert explicit concatenation operator '.'
    explicit = []
    prev = None
    i = 0
    while i < len(regex):
        c = regex[i]
        if c == '\\':
            if i+1 < len(regex):
                explicit.append(regex[i:i+2])
                i += 2
                prev = 'lit'
                continue
        if c in ('(', '|'):
            if prev == 'lit' or prev == ')' or prev == '*':
                explicit.append('.')
            explicit.append(c)
            prev = c
        elif c == ')':
            explicit.append(c)
            prev = ')'
        elif c in ('*','+','?'):
            explicit.append(c)
            prev = '*'
        else:
            if prev == 'lit' or prev == ')' or prev == '*':
                explicit.append('.')
            explicit.append(c)
            prev = 'lit'
        i += 1
    # shunting-yard
    prec = {'|': 1, '.': 2, '*': 3, '+': 3, '?': 3}
    out = []
    stack = []
    for token in explicit:
        if token == '(':
            stack.append(token)
        elif token == ')':
            while stack and stack[-1] != '(':
                out.append(stack.pop())
            stack.pop()
        elif token in prec:
            while stack and stack[-1] != '(' and prec.get(stack[-1],0) >= prec[token]:
                out.append(stack.pop())
            stack.append(token)
        else:
            out.append(token)
    while stack:
        out.append(stack.pop())
    return out

def thompson_from_postfix(postfix):
    stack = []
    for tok in postfix:
        if tok == '.':
            n2 = stack.pop(); n1 = stack.pop()
            n1.accept.epsilon.append(n2.start)
            stack.append(NFA(n1.start, n2.accept))
        elif tok == '|':
            n2 = stack.pop(); n1 = stack.pop()
            s = State(); a = State()
            s.epsilon.extend([n1.start, n2.start])
            n1.accept.epsilon.append(a)
            n2.accept.epsilon.append(a)
            stack.append(NFA(s,a))
        elif tok == '*':
            n = stack.pop()
            s = State(); a = State()
            s.epsilon.extend([n.start, a])
            n.accept.epsilon.extend([n.start, a])
            stack.append(NFA(s,a))
        elif tok == '+':
            n = stack.pop()
            s = State(); a = State()
            s.epsilon.append(n.start)
            n.accept.epsilon.extend([n.start, a])
            stack.append(NFA(s,a))
        elif tok == '?':
            n = stack.pop()
            s = State(); a = State()
            s.epsilon.extend([n.start, a])
            n.accept.epsilon.append(a)
            stack.append(NFA(s,a))
        else:
            # literal token or escaped sequence
            s = State(); a = State()
            sym = tok
            s.edges[sym].append(a)
            stack.append(NFA(s,a))
    if not stack:
        raise ValueError("Empty regex")
    return stack.pop()

# ---------- NFA -> DFA (subset construction) ----------
def epsilon_closure(states):
    stack = list(states)
    res = set(states)
    while stack:
        s = stack.pop()
        for e in s.epsilon:
            if e not in res:
                res.add(e); stack.append(e)
    return res

def move(states, symbol):
    res = set()
    for s in states:
        for tgt in s.edges.get(symbol, []):
            res.add(tgt)
    return res

class DFA:
    def __init__(self):
        self.start = None
        self.transitions = {}  # state_id -> {symbol: dest_state_id}
        self.accepting = set()

def nfa_to_dfa(nfa):
    # collect alphabet by examining explicit edges (literal tokens). For our NFA, edges keys can be multi-char tokens (escaped sequences)
    # We'll use symbols as exact tokens stored in state.edges keys
    start_set = frozenset(epsilon_closure({nfa.start}))
    state_map = {start_set: 0}
    dfa = DFA()
    dfa.start = 0
    queue = deque([start_set])
    dfa.transitions[0] = {}
    while queue:
        curr = queue.popleft()
        curr_id = state_map[curr]
        # gather possible symbols
        symbols = set()
        for s in curr:
            symbols.update(s.edges.keys())
        for sym in symbols:
            tgt = set()
            for s in curr:
                for t in s.edges.get(sym, []):
                    tgt.update(epsilon_closure({t}))
            if not tgt: continue
            tgt_f = frozenset(tgt)
            if tgt_f not in state_map:
                nid = len(state_map)
                state_map[tgt_f] = nid
                queue.append(tgt_f)
                dfa.transitions[nid] = {}
            else:
                nid = state_map[tgt_f]
            dfa.transitions[curr_id][sym] = nid
    # accepting states
    for stateset, sid in state_map.items():
        if nfa.accept in stateset:
            dfa.accepting.add(sid)
    return dfa

# ---------- Hopcroft minimization ----------
def hopcroft_minimize(dfa):
    # states 0..n-1
    n = len(dfa.transitions)
    # build set of symbols
    alphabet = set()
    for trans in dfa.transitions.values():
        alphabet.update(trans.keys())
    # inverse transitions: for each symbol, map dest -> set(src)
    inv = {sym: defaultdict(set) for sym in alphabet}
    for s, trans in dfa.transitions.items():
        for sym, t in trans.items():
            inv[sym][t].add(s)
    final = set(dfa.accepting)
    non_final = set(range(n)) - final
    P = [final, non_final] if non_final else [final]
    W = [final.copy(), non_final.copy()] if non_final else [final.copy()]
    while W:
        A = W.pop()
        for c in alphabet:
            X = set()
            for q in A:
                X.update(inv[c].get(q, set()))
            newP = []
            for Y in P:
                inter = Y & X
                diff = Y - X
                if inter and diff:
                    newP.append(inter)
                    newP.append(diff)
                    if Y in W:
                        W.remove(Y)
                        W.append(inter); W.append(diff)
                    else:
                        if len(inter) <= len(diff):
                            W.append(inter)
                        else:
                            W.append(diff)
                else:
                    newP.append(Y)
            P = newP
    # build new DFA
    rep = {}
    for i, block in enumerate(P):
        for s in block:
            rep[s] = i
    new_dfa = DFA()
    new_dfa.start = rep[dfa.start]
    new_dfa.transitions = {}
    for s in range(n):
        ns = rep[s]
        if ns not in new_dfa.transitions:
            new_dfa.transitions[ns] = {}
        for sym, t in dfa.transitions.get(s, {}).items():
            new_dfa.transitions[ns][sym] = rep[t]
    for s in dfa.accepting:
        new_dfa.accepting.add(rep[s])
    return new_dfa

# ---------- DFA simulation ----------
def simulate_dfa(dfa, text):
    # At each step, symbols are tokens used when building DFA; most tokens are single chars; handle multi-char tokens by trying longest-match (naive)
    state = dfa.start
    i = 0
    L = len(text)
    # convert transitions per-state to list of (symbol, dest) to try
    per_state = {s: list(trans.items()) for s, trans in dfa.transitions.items()}
    while i < L:
        matched = False
        if state not in per_state:
            return False
        for sym, dest in per_state[state]:
            # sym might be escaped token like '\|' or multi-char; unescape if starts with backslash
            token = sym
            if len(token) == 1:
                if text[i] == token:
                    state = dest; i += 1; matched = True; break
            else:
                # multi-char token match
                if text.startswith(token.replace('\\',''), i):
                    state = dest; i += len(token.replace('\\','')); matched = True; break
        if not matched:
            # no outgoing symbol matched -> reject
            return False
    return state in dfa.accepting

# ---------- Utilities & evaluation ----------
def try_build_automata(pattern):
    """Attempt to build DFA from pattern via Thompson+subset+Hopcroft.
       If parser fails, return None to indicate fallback to Python re.
    """
    try:
        postfix = regex_to_postfix(pattern)
        nfa = thompson_from_postfix(postfix)
        dfa = nfa_to_dfa(nfa)
        dfa_min = hopcroft_minimize(dfa)
        return dfa_min
    except Exception:
        return None

def evaluate_dataset(dataset_csv, patterns, hybrid_stats_json=None, out_prefix='standard'):
    records = []
    with open(dataset_csv, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            records.append({'id': r.get('id',''), 'payload': r.get('payload',''), 'label': (r.get('label') or 'benign').lower()})
    # build automata for each pattern
    automata = {}
    regex_fallback = {}
    for name, pat in patterns.items():
        dfa = try_build_automata(pat)
        if dfa:
            automata[name] = dfa
        else:
            # fallback: compile python re
            try:
                regex_fallback[name] = re.compile(pat, re.IGNORECASE)
            except re.error:
                regex_fallback[name] = None

    stats = defaultdict(lambda: {'tp':0,'fp':0,'fn':0})
    mis = []
    total = 0; correct = 0
    # timings
    t_start = time.time()
    per_rec_times = []
    for rec in records:
        total += 1
        payload = rec['payload'] or ''
        actual = rec['label'] or 'benign'
        # measure time for this payload
        t0 = time.time()
        detected = False; det_label = None
        # try automata first
        for name, dfa in automata.items():
            try:
                if simulate_dfa(dfa, payload):
                    detected = True; det_label = name; break
            except Exception:
                # if simulation fails, skip to regex fallback
                detected = False
        # regex fallback
        if not detected:
            for name, cre in regex_fallback.items():
                if cre and cre.search(payload):
                    detected = True; det_label = name; break
        t1 = time.time()
        per_rec_times.append(t1-t0)
        predicted = det_label if detected else 'benign'
        if predicted == actual:
            correct += 1
            stats[actual]['tp'] += 1
        else:
            stats[predicted]['fp'] += 1
            stats[actual]['fn'] += 1
            mis.append({'id': rec['id'], 'payload': payload, 'actual': actual, 'predicted': predicted})
    t_end = time.time()
    accuracy = correct/total if total else 0.0
    per_class = {}
    classes = set(list(stats.keys()) + [k for k in patterns.keys()]+['benign'])
    for cls in sorted(classes):
        tp = stats[cls]['tp']; fp = stats[cls]['fp']; fn = stats[cls]['fn']
        prec = tp/(tp+fp) if (tp+fp) else 0.0
        rec = tp/(tp+fn) if (tp+fn) else 0.0
        per_class[cls] = {'tp':tp,'fp':fp,'fn':fn,'precision':round(prec,3),'recall':round(rec,3)}
    # safe timing calculations
    elapsed = max(t_end - t_start, 0.0)
    avg_latency_ms = round(1000 * (sum(per_rec_times) / len(per_rec_times)), 3) if per_rec_times else 0.0
    median_latency_ms = round(1000 * (sorted(per_rec_times)[len(per_rec_times)//2]), 3) if per_rec_times else 0.0
    throughput_rps = round(total / elapsed, 3) if elapsed > 0 else 0.0

    summary = {
        'total': total,
        'correct': correct,
        'accuracy': round(accuracy, 3),
        'per_class': per_class,
        'avg_latency_ms': avg_latency_ms,
        'median_latency_ms': median_latency_ms,
        'throughput_rps': throughput_rps
    }
    # save summary and misclassified
    out_stats = f'{out_prefix}_evaluation_stats.json'
    with open(out_stats, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    with open(f'{out_prefix}_misclassified.csv', 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['id','payload','actual','predicted'])
        w.writeheader(); w.writerows(mis)
    print(f"Saved stats -> {out_stats}")
    # plotting: if hybrid_stats_json provided, create comparison plots
    if hybrid_stats_json and os.path.isfile(hybrid_stats_json):
        with open(hybrid_stats_json,'r',encoding='utf-8') as f:
            hybrid = json.load(f)
        plot_comparison(summary, hybrid, out_prefix)
    else:
        plot_summary(summary, out_prefix)
    return summary

# ---------- plotting helpers ----------
def plot_summary(summary, prefix):
    out_dir = 'plots'
    os.makedirs(out_dir, exist_ok=True)
    # per-class bar chart for precision/recall
    rows = []
    for cls, v in summary['per_class'].items():
        rows.append({'class':cls,'precision':v['precision'],'recall':v['recall']})
    df = pd.DataFrame(rows)
    plt.figure(figsize=(8,5))
    sns.barplot(data=df.melt(id_vars='class', value_vars=['precision','recall'], var_name='metric', value_name='value'),
                x='class', y='value', hue='metric', ci=None)
    plt.ylim(0,1.05); plt.title('Per-class Precision/Recall (Standard)'); plt.tight_layout()
    plt.savefig(os.path.join(out_dir, f'{prefix}_precision_recall.png')); plt.close()
    # latency/throughput
    df2 = pd.DataFrame([summary])
    plt.figure(figsize=(6,4))
    sns.barplot(x=['avg_latency_ms','median_latency_ms','throughput_rps'], y=[df2['avg_latency_ms'][0], df2['median_latency_ms'][0], df2['throughput_rps'][0]])
    plt.title('Latency (ms) & Throughput (rps)'); plt.tight_layout()
    plt.savefig(os.path.join(out_dir, f'{prefix}_perf.png')); plt.close()

def plot_comparison(std, hybrid, prefix):
    out_dir = 'plots'
    os.makedirs(out_dir, exist_ok=True)
    # combine per-class
    rows = []
    for cls, v in std['per_class'].items():
        rows.append({'algorithm':'standard','class':cls,'precision':v['precision'],'recall':v['recall']})
    for cls, v in hybrid['per_class'].items():
        rows.append({'algorithm':'hybrid','class':cls,'precision':v['precision'],'recall':v['recall']})
    df = pd.DataFrame(rows)
    plt.figure(figsize=(10,6))
    sns.barplot(data=df.melt(id_vars=['algorithm','class'], value_vars=['precision','recall'], var_name='metric', value_name='value'),
                x='class', y='value', hue='algorithm', ci=None)
    plt.ylim(0,1.05); plt.title('Precision/Recall: Standard vs Hybrid'); plt.tight_layout()
    plt.savefig(os.path.join(out_dir, f'{prefix}_comparison_precision_recall.png')); plt.close()
    # throughput and latency comparison
    plt.figure(figsize=(8,4))
    metrics = ['avg_latency_ms','median_latency_ms','throughput_rps']
    std_vals = [std.get(m,0) for m in metrics]
    hyp_vals = [hybrid.get(m,0) for m in metrics]
    df2 = pd.DataFrame({'metric':metrics, 'standard':std_vals, 'hybrid':hyp_vals})
    df2_m = df2.melt(id_vars='metric', value_vars=['standard','hybrid'], var_name='algorithm', value_name='value')
    sns.barplot(data=df2_m, x='metric', y='value', hue='algorithm', ci=None)
    plt.title('Perf comparison (standard vs hybrid)'); plt.tight_layout()
    plt.savefig(os.path.join(out_dir, f'{prefix}_comparison_perf.png')); plt.close()

# ---------- CLI ----------
def load_patterns_from_module():
    # try import patterns.py in repo
    try:
        import patterns as pmod
        return pmod.load_patterns()
    except Exception:
        # fallback sample patterns
        return {
            "sql_injection": r"(?i)(?:union\s+select|or\s+1=1|;?\s*drop\s+table|--\s*$)",
            "xss": r"(?i)(?:<script|onerror=|javascript:)",
            "cmd_injection": r"(?i)(?:[;&|`]\s*(?:rm|wget|curl|nc|bash|powershell))"
        }

def main():
    ap = argparse.ArgumentParser(description="Standard automata algorithms evaluation")
    ap.add_argument('dataset', nargs='?', default='large_dataset.csv')
    ap.add_argument('--hybrid-stats', dest='hybrid', help='path to hybrid evaluation JSON for comparison')
    ap.add_argument('--out-prefix', default='standard', help='output filename prefix')
    args = ap.parse_args()
    patterns = load_patterns_from_module()
    summary = evaluate_dataset(args.dataset, patterns, hybrid_stats_json=args.hybrid, out_prefix=args.out_prefix)
    print("Done. Summary:", summary)

if __name__ == '__main__':
    main()