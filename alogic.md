# Hybrid Detection Logic (SQL Injection) — Design & Example

Overview
- The hybrid detector combines fast deterministic pattern matching (DFA derived from regexes) with context-aware preprocessing and an ML fallback for ambiguous cases.
- Pipeline stages:
  1. Preprocessing: recursive URL decode, HTML entity decode, Unicode NFKC, whitespace normalization, simple comment removal.
  2. Context detection: check for SQL keywords/tokens (SELECT, UNION, INSERT, DROP, sleep, etc.). Skip SQL rules for non-SQL contexts.
  3. Fast matching: apply precompiled DFA patterns (from regex -> Thompson NFA -> subset DFA -> Hopcroft minimize). DFAs are deterministic and very fast for streaming checks.
  4. Heuristics: entropy and suspicious-encoding checks detect obfuscation (base64, repeated %-encoding).
  5. ML fallback: when context indicates command/ambiguous and DFA did not match but heuristics are suspicious, use a small ML model (features: token counts, special-char ratio, entropy) to reduce false negatives.
  6. Alerting / scoring: every match produces a score + context metadata and is logged for offline analysis and rule refinement.

Why hybrid?
- DFA matching gives near-constant performance per byte and guarantees no catastrophic backtracking for complex patterns.
- Context checks dramatically reduce the number of patterns applied to each payload (improves throughput).
- ML fallback recovers recall on tricky, obfuscated samples while the DFA layer keeps precision high.

Example: payload "' OR '1'='1 --"
1. Preprocess:
   - No URL/html encoding present → payload normalized to: "' OR '1'='1 --"
2. Context detection:
   - SQL keywords found ("OR", "'1'") → SQL context = True
3. DFA matching:
   - SQL-injection DFA (constructed from known SQLi regex patterns) is applied; pattern for boolean injection or stacked statements matches → immediate detection as SQL injection.
4. If DFA had not matched (e.g., obfuscated input), system would compute entropy and suspicious char checks, then call ML fallback to evaluate likelihood and raise detection if confidence exceeds threshold.

Notes on offline rule refinement
- Misclassified samples are logged. Periodic clustering of false negatives suggests new regex rules to feed back into the DFA layer.
- When adding new regex rules, re-run Thompson → subset → Hopcroft to regenerate optimized DFA set.

Performance considerations
- DFA construction is done offline; runtime uses precompiled DFAs.
- Hopcroft minimization reduces DFA size, improving memory/cache locality.
- Context filters and early-exit heuristics reduce pattern checks per payload, improving throughput on high-volume streams.

Security & safety
- Never execute payloads.
- Log minimal PII and encrypt stored logs.
- Rate-limit and sandbox any active testing harness to prevent accidental attacks.