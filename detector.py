import re
# change relative imports to absolute so running `python main.py` works
from preprocess import preprocess_payload, check_entropy, check_suspicious_chars
from utils import normalize_label

class RateLimiter:
    def __init__(self, window=60, max_requests=100):
        self.window = window
        self.max_requests = max_requests
        self._reqs = []

    def check(self, now_func=None):
        import time
        now = (now_func() if now_func else time.time())
        self._reqs = [t for t in self._reqs if now - t <= self.window]
        self._reqs.append(now)
        return len(self._reqs) <= self.max_requests

def regex_to_dfa(pattern):
    try:
        return re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error:
        return None

def display_dfa(dfa):
    if not dfa:
        print("Pattern: <compile error>")
        return
    print("Pattern:", dfa.pattern)
    print("Flags:", dfa.flags)

def check_intrusion(input_str, dfas, ml_fallback=None, rate_limiter=None):
    processed = preprocess_payload(input_str)
    if rate_limiter and not rate_limiter.check():
        return True, "rate_limited"

    # quick obfuscation check
    if check_entropy(processed) and check_suspicious_chars(processed):
        return True, "suspicious_encoding"

    # Context heuristics
    is_sql = bool(re.search(r'\b(select|insert|update|delete|union|drop)\b', processed, re.I))
    is_html = bool(re.search(r'<[^>]+>', processed))
    is_shell = bool(re.search(r'[;&|`]|(?:/bin/)|(?:\\cmd\\.exe)|powershell', processed, re.I))

    for label, dfa in dfas.items():
        if dfa is None:
            continue
        # apply context filters
        if label == "sql_injection" and not is_sql:
            continue
        if label == "xss" and not is_html:
            continue
        if label == "cmd_injection" and not is_shell:
            continue
        if dfa.search(processed):
            return True, normalize_label(label)

    # ML fallback for command injection
    if ml_fallback:
        try:
            pred = ml_fallback.predict(payload=processed)
            if pred == 'cmd_injection':
                return True, 'cmd_injection'
        except Exception:
            pass

    return False, None