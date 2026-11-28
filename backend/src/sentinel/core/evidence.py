"""Best-effort redaction at UI, history and export boundaries; never archive raw output."""
import re

LIMIT = 32768
SECRET_KEYS = re.compile(r'(?i)^(authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|api[_-]?key|access[_-]?token)$')
PATTERNS = (
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)', re.S), '[PRIVATE KEY REDACTED]'),
    (re.compile(r'(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+'), r'\1: [REDACTED]'),
    (re.compile(r'(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?token)(["\x27]?\s*[:=]\s*["\x27]?)[^\s&;,"\x27<>]+'), r'\1\2[REDACTED]'),
    (re.compile(r'(?i)(https?://)[^/\s:@]+:[^/\s@]+@'), r'\1[REDACTED]@'),
)


def redact(value):
    for pattern, replacement in PATTERNS:
        value = pattern.sub(replacement, value)
    return value if len(value) <= LIMIT else value[:LIMIT] + ' [evidence truncated]'


def sanitize(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if SECRET_KEYS.fullmatch(str(k)) else sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    return value
