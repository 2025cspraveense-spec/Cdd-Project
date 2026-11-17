"""Strict Credential Redaction Utility for Secret Leak Guard v2.0.

Enforces redaction across all boundaries:
- In-memory representations
- Application logs (via custom filter and formatter)
- REST API JSON responses
- MongoDB database persistence
"""

import copy
import logging
import re
from typing import Any, Dict, List, Optional, Set, Union

# Common sensitive key names across payloads, DB schemas, and configs
DEFAULT_SENSITIVE_KEYS: Set[str] = {
    "raw_secret",
    "secret",
    "secrets",
    "password",
    "passwd",
    "pwd",
    "token",
    "tokens",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "secret_key",
    "jwt_secret_key",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "client_secret",
}

# Regex patterns for well-known API keys & secrets for inline text redaction
REGEX_PATTERNS: List[re.Pattern] = [
    # AWS Access Key ID (e.g., AKIA...)
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    # AWS Secret Key (40 chars base64-like)
    re.compile(r"(?i)\b(aws[_\s\-]?secret[_\s\-]?access[_\s\-]?key[\s:=]+)([A-Za-z0-9/+=]{40})\b"),
    # GitHub Personal Access Token (classic & fine-grained)
    re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
    re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
    # Slack Token
    re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
    # Generic Private Key blocks
    re.compile(r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[\s\S]+?-----END[ A-Z0-9_-]+PRIVATE KEY-----"),
    # Generic bearer tokens
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*)"),
]


def redact_secret(value: Any) -> str:
    """Centralized redaction utility that preserves ONLY the first 4 characters.
    
    Examples:
        'AKIA...EXAMPLE' -> 'AKIA****************'
        'ghp_...EXAMPLE' -> 'ghp_********************************'
        'short' (len 5) -> 'shor*'
        'pass' (len <= 4) -> '****'
        '' -> ''
        None -> ''
    """
    if value is None:
        return ""
    val_str = str(value)
    if not val_str:
        return ""
    
    val_len = len(val_str)
    if val_len <= 4:
        return "*" * val_len
    
    # Preserve first 4 characters and replace all remaining characters with '*'
    return val_str[:4] + ("*" * (val_len - 4))


def redact_text(text: str) -> str:
    """Scan and redact any known secret formats embedded inside arbitrary text."""
    if not text or not isinstance(text, str):
        return text

    sanitized = text

    # Redact private key blocks completely
    sanitized = re.sub(
        r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[\s\S]+?-----END[ A-Z0-9_-]+PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY]\n-----END PRIVATE KEY-----",
        sanitized
    )

    # Redact AWS keys
    sanitized = re.sub(r"\b(AKIA[0-9A-Z]{16})\b", lambda m: redact_secret(m.group(1)), sanitized)

    # Redact GitHub tokens
    sanitized = re.sub(r"\b(ghp_[A-Za-z0-9]{36})\b", lambda m: redact_secret(m.group(1)), sanitized)
    sanitized = re.sub(r"\b(github_pat_[A-Za-z0-9_]{82})\b", lambda m: redact_secret(m.group(1)), sanitized)

    # Redact Slack tokens
    sanitized = re.sub(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b", lambda m: redact_secret(m.group(1)), sanitized)

    # Redact Bearer tokens in text
    def _redact_bearer(m: re.Match) -> str:
        prefix = m.group(1)
        token = m.group(2)
        return prefix + redact_secret(token)

    sanitized = re.sub(
        r"(?i)(bearer\s+)([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*)",
        _redact_bearer,
        sanitized
    )

    return sanitized


def redact_dict(
    data: Any,
    sensitive_keys: Optional[Set[str]] = None,
    in_place: bool = False
) -> Any:
    """Recursively traverses dictionaries, lists, and objects to redact all secrets.
    
    Args:
        data: The data structure (dict, list, primitive) to redact.
        sensitive_keys: Set of key names to redact (defaults to DEFAULT_SENSITIVE_KEYS).
        in_place: Whether to mutate in place or return a deep copy.
    """
    if sensitive_keys is None:
        sensitive_keys = DEFAULT_SENSITIVE_KEYS
    else:
        sensitive_keys = {k.lower() for k in sensitive_keys}.union(DEFAULT_SENSITIVE_KEYS)

    if not in_place and isinstance(data, (dict, list)):
        data = copy.deepcopy(data)

    if isinstance(data, dict):
        for key, value in list(data.items()):
            key_lower = str(key).lower()
            if key_lower in sensitive_keys:
                if isinstance(value, str):
                    data[key] = redact_secret(value)
                elif isinstance(value, (dict, list)):
                    data[key] = redact_dict(value, sensitive_keys, in_place=True)
                else:
                    data[key] = redact_secret(value)
            elif isinstance(value, str):
                data[key] = redact_text(value)
            elif isinstance(value, (dict, list)):
                data[key] = redact_dict(value, sensitive_keys, in_place=True)
        return data

    elif isinstance(data, list):
        for idx, item in enumerate(data):
            if isinstance(item, (dict, list)):
                data[idx] = redact_dict(item, sensitive_keys, in_place=True)
            elif isinstance(item, str):
                data[idx] = redact_text(item)
        return data

    elif isinstance(data, str):
        return redact_text(data)

    return data


def redact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Specifically redacts a security finding record before persistence or serialization."""
    sanitized = copy.deepcopy(finding)
    if "raw_secret" in sanitized and sanitized["raw_secret"] is not None:
        sanitized["raw_secret"] = redact_secret(sanitized["raw_secret"])
    if "match_content" in sanitized and sanitized["match_content"] is not None:
        sanitized["match_content"] = redact_text(str(sanitized["match_content"]))
    if "evidence" in sanitized and sanitized["evidence"] is not None:
        sanitized["evidence"] = redact_text(str(sanitized["evidence"]))
    if "description" in sanitized and sanitized["description"] is not None:
        sanitized["description"] = redact_text(str(sanitized["description"]))
    return sanitized


def redact_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Redacts a list of security findings."""
    return [redact_finding(f) for f in findings]


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs sensitive secrets from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = redact_dict(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_text(a) if isinstance(a, str) else redact_dict(a) if isinstance(a, dict) else a
                    for a in record.args
                )
        return True


class RedactingFormatter(logging.Formatter):
    """Logging formatter that ensures formatted output contains no raw credentials."""

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return redact_text(formatted)
