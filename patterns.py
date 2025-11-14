import re

def load_patterns():
    """Return raw regex patterns (keys are normalized labels)."""
    return {
        "sql_injection": (
            r"(?i)(?:"
            r"(?:'\s*(?:or|and)\s*['\d])|"               # boolean based
            r"(?:union\s+(?:all\s+)?select)|"            # union
            r"(?:;?\s*(?:drop|delete|update|insert)\s+)|" # DDL/DML
            r"(?:--|#|/\*.*?\*/)|"                       # comments
            r"(?:sleep\s*\(|benchmark\s*\()"             # time based
            r")"
        ),
        "xss": (
            r"(?i)(?:"
            r"<script[\s\S]*?>[\s\S]*?</script>|"
            r"<[^>]*\bon\w+\s*=|"
            r"(?:javascript:|vbscript:|data:text\/html)|"
            r"<(?:iframe|object|embed|svg|img)[^>]*>"
            r")"
        ),
        "cmd_injection": (
            r"(?i)(?:"
            r"(?:[;&|`]\s*(?:rm|cat|wget|curl|nc|bash|sh|powershell|cmd|python))|"
            r"(?:\b(?:wget|curl|nc|ncat|powershell|cmd|bash|sh)\b.*\b(http|://|/bin/))|"
            r"(?:>\s*(?:/etc|/tmp|/dev))"
            r")"
        )
    }