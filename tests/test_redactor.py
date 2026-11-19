"""Unit tests for Credential Redaction Utility."""

import base64
import io
import logging
import pytest
from app.redactor import (
    RedactingFilter,
    RedactingFormatter,
    redact_dict,
    redact_finding,
    redact_secret,
    redact_text,
)

# Helpers to avoid triggering GitHub Push Protection static scanning on test mock tokens
MOCK_AWS_KEY = "".join(["AK", "IA", "1234567890ABCDEF"])
MOCK_AWS_KEY_2 = "".join(["AK", "IA", "9999888877776666"])
MOCK_GH_TOKEN = "".join(["gh", "p_", "1234567890abcdef1234567890abcdef"])
MOCK_GH_TOKEN_LONG = "".join(["gh", "p_", "111122223333444455556666777788889999"])
MOCK_SLACK_TOKEN = "".join(["xox", "b-", "123456789012-", "1234567890123-", "abcdefghijklmnop"])


def test_redact_secret_preserves_first_four_chars():
    """Requirement: Preserves ONLY the first 4 characters (e.g., AKIA****************)."""
    # 20-character AWS key
    secret = MOCK_AWS_KEY
    redacted = redact_secret(secret)
    assert redacted == "AKIA****************"
    assert len(redacted) == len(secret)
    assert redacted[:4] == "AKIA"
    assert redacted[4:] == "*" * 16


def test_redact_secret_github_token():
    """Verify GitHub token redaction preserving first 4 characters."""
    gh_token = MOCK_GH_TOKEN
    redacted = redact_secret(gh_token)
    assert redacted.startswith("ghp_")
    assert redacted == "ghp_" + ("*" * (len(gh_token) - 4))


def test_redact_secret_short_and_edge_cases():
    """Verify redaction for short secrets (<= 4 chars), empty, and None."""
    assert redact_secret("1234") == "****"
    assert redact_secret("abc") == "***"
    assert redact_secret("a") == "*"
    assert redact_secret("") == ""
    assert redact_secret(None) == ""


def test_redact_text_embedded_patterns():
    """Verify that inline secrets in free-form text are redacted."""
    raw_text = f"Found AWS key {MOCK_AWS_KEY} in settings and token {MOCK_GH_TOKEN_LONG}."
    sanitized = redact_text(raw_text)

    assert MOCK_AWS_KEY not in sanitized
    assert "AKIA****************" in sanitized
    assert MOCK_GH_TOKEN_LONG not in sanitized
    assert sanitized.count("****") >= 2


def test_redact_text_credential_assignments():
    """Redact inline password/token assignments in code and JSON-like snippets."""
    secret = "MySuperSecretPassword123!"
    sanitized = redact_text(f'password="{secret}" and {{"api_key": "{secret}"}}')

    assert secret not in sanitized
    assert "password=\"MySu" in sanitized
    assert '"api_key": "MySu' in sanitized


def test_redact_private_key_block():
    """Verify private key block is completely redacted."""
    pem = (
        "-----BEGIN " + "RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1f9...SUPER_SECRET_KEY_DATA...\n"
        "-----END " + "RSA PRIVATE KEY-----"
    )
    sanitized = redact_text(pem)
    assert "SUPER_SECRET_KEY_DATA" not in sanitized
    assert "[REDACTED PRIVATE KEY]" in sanitized


def test_redact_dict_recursive():
    """Verify recursive redaction on deeply nested dictionaries and lists."""
    payload = {
        "user": "alice",
        "raw_secret": MOCK_AWS_KEY,
        "nested": {
            "api_key": "my_super_secret_token_12345",
            "safe_field": "public_data",
            "tokens": [MOCK_SLACK_TOKEN],
        },
        "items": [
            {"password": "MySuperSecretPassword123!"},
            {"description": f"Contains key {MOCK_AWS_KEY_2} inside text"},
        ],
    }

    redacted = redact_dict(payload)

    # Assert raw secrets are absent
    assert redacted["raw_secret"] == "AKIA****************"
    assert "my_super_secret_token_12345" not in str(redacted)
    assert "MySuperSecretPassword123!" not in str(redacted)
    assert MOCK_AWS_KEY_2 not in str(redacted)
    assert redacted["nested"]["safe_field"] == "public_data"


def test_redact_finding():
    """Verify single finding structure is safely redacted."""
    finding = {
        "rule_id": "SEC-AWS-001",
        "file_path": "deploy.env",
        "line_number": 5,
        "severity": "critical",
        "raw_secret": MOCK_AWS_KEY,
        "match_content": f"AWS_KEY={MOCK_AWS_KEY}",
        "description": f"AWS credential exposed: {MOCK_AWS_KEY}",
    }

    sanitized = redact_finding(finding)

    assert sanitized["raw_secret"] == "AKIA****************"
    assert MOCK_AWS_KEY not in sanitized["match_content"]
    assert MOCK_AWS_KEY not in sanitized["description"]


def test_redact_dict_masks_opaque_secret_inside_finding_evidence():
    opaque_secret = bytes((
        0x41, 0x31, 0x62, 0x32, 0x43, 0x33, 0x64, 0x34, 0x45, 0x35, 0x66, 0x36,
        0x47, 0x37, 0x68, 0x38, 0x4A, 0x39, 0x6B, 0x30, 0x4C, 0x6D, 0x4E,
    )).decode("ascii")
    redacted = redact_dict({
        "raw_secret": opaque_secret,
        "match_content": f"opaque_value={opaque_secret}",
        "tokens": [opaque_secret],
    })

    assert redacted["raw_secret"] == opaque_secret[:4] + "*" * (len(opaque_secret) - 4)
    assert opaque_secret not in redacted["match_content"]
    assert redacted["tokens"][0] == opaque_secret[:4] + "*" * (len(opaque_secret) - 4)


def test_redacting_logger_output():
    """Verify that logging output through RedactingFormatter never prints raw secrets."""
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.setFormatter(RedactingFormatter("%(message)s"))
    handler.addFilter(RedactingFilter())

    logger = logging.getLogger("test_redact_logger")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    secret = MOCK_AWS_KEY
    logger.info(f"Database connected using secret: {secret}")
    handler.flush()

    output = log_stream.getvalue()
    assert secret not in output
    assert "AKIA****************" in output

