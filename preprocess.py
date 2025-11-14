import re
from urllib.parse import unquote
import html
from math import log2

def recursive_url_unescape(s, max_iter=5):
    for _ in range(max_iter):
        dec = unquote(s)
        if dec == s:
            break
        s = dec
    return s

def normalize_whitespace(s):
    return ' '.join(s.split())

def preprocess_payload(payload):
    """URL/html decode, normalize, remove simple comment tokens."""
    if payload is None:
        return ""
    p = str(payload)
    p = recursive_url_unescape(p)
    p = html.unescape(p)
    p = p.replace('/*', ' ').replace('*/', ' ')
    p = normalize_whitespace(p)
    p = re.sub(r'([;()])', r' \1 ', p)
    return p.strip()

def shannon_entropy(text):
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    L = len(text)
    for v in freq.values():
        p = v / L
        ent -= p * log2(p)
    return ent

def check_entropy(text, threshold=5.0):
    return shannon_entropy(text) > threshold

def check_suspicious_chars(text):
    return bool(re.search(r'(?:%[0-9a-fA-F]{2}){2,}|&#\d+;|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', text))