"""
Shared sanitization utilities for masking sensitive values.

Used by both approver_mcp (audit logging) and file_queue (input summaries).
Extracted to avoid circular imports between these modules.
"""

import re
from typing import Any

# Patterns for masking sensitive values
_SENSITIVE_PATTERNS = [
    re.compile(r"(password\s*=\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(secret\s*=\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*=?\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(AWS_SECRET\S*\s*=?\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(AWS_SESSION_TOKEN\s*=?\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(ANTHROPIC_API_KEY\s*=?\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(Bearer\s+)(\S+)", re.IGNORECASE),
    re.compile(r"(sk-ant-\S{4})\S+", re.IGNORECASE),
    re.compile(r"(xoxb-\S{4})\S+", re.IGNORECASE),
    re.compile(r"(token\s*=\s*)(\S+)", re.IGNORECASE),
    # GitHub PATs
    re.compile(r"(ghp_)\S+", re.IGNORECASE),
    re.compile(r"(github_pat_)\S+", re.IGNORECASE),
    # URL-embedded credentials (user:password@host)
    re.compile(r"(://\w+:)\S+(@)", re.IGNORECASE),
]


def sanitize_value(value: Any) -> Any:
    """Recursively mask sensitive patterns in a value."""
    if isinstance(value, str):
        masked = value
        for pattern in _SENSITIVE_PATTERNS:
            masked = pattern.sub(lambda m: m.group(1) + "***REDACTED***", masked)
        return masked
    elif isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    elif isinstance(value, list | tuple):
        sanitized = [sanitize_value(item) for item in value]
        return type(value)(sanitized)
    return value
