
"""Secret Detection Engine for Secret Leak Guard v2.0."""

import os
import re
import math
from typing import Any, Dict, List, Set, Tuple

from app.engines.base import BaseEngine


# ---------------------------------------------------------
# Rule compiler
# ---------------------------------------------------------

def compile_rule(rule_id, description, severity, pattern, remediation):
    return {
        "rule_id": rule_id,
        "description": description,
        "severity": severity,
        "pattern": re.compile(pattern),
        "remediation": remediation,
    }


# ---------------------------------------------------------
# Secret detection rules (32 rules)
# ---------------------------------------------------------

SECRET_RULES = [

    # AWS
    compile_rule(
        "SEC-AWS-001", "AWS Access Key ID exposed", "critical",
        r"\b(AKIA[0-9A-Z]{16})\b",
        "Revoke the AWS key and use IAM roles."
    ),
    compile_rule(
        "SEC-AWS-002", "AWS Secret Access Key assignment", "critical",
        r"""(?i)\baws_secret_access_key\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]""",
        "Rotate the AWS secret and use IAM roles."
    ),

    # GitHub
    compile_rule(
        "SEC-GH-001", "GitHub Personal Access Token exposed", "critical",
        r"\b(ghp_[A-Za-z0-9]{36})\b",
        "Revoke the GitHub token immediately."
    ),
    compile_rule(
        "SEC-GH-002", "GitHub OAuth token exposed", "critical",
        r"\b(gho_[A-Za-z0-9]{36})\b",
        "Revoke the GitHub OAuth token."
    ),
    compile_rule(
        "SEC-GH-003", "GitHub user token exposed", "high",
        r"\b(ghu_[A-Za-z0-9]{36})\b",
        "Revoke and replace the GitHub token."
    ),
    compile_rule(
        "SEC-GH-004", "GitHub App token exposed", "critical",
        r"\b(ghs_[A-Za-z0-9]{36})\b",
        "Revoke the GitHub App token."
    ),
    compile_rule(
        "SEC-GH-005", "GitHub refresh token exposed", "high",
        r"\b(ghr_[A-Za-z0-9]{36})\b",
        "Revoke the refresh token."
    ),
    compile_rule(
        "SEC-GH-006", "GitHub fine-grained token exposed", "critical",
        r"\b(github_pat_[A-Za-z0-9_]{20,})\b",
        "Revoke the fine-grained token."
    ),

    # GitLab
    compile_rule(
        "SEC-GL-001", "GitLab personal or project token exposed", "critical",
        r"\b(glpat-[A-Za-z0-9_-]{20,})\b",
        "Revoke the GitLab token."
    ),

    # Google
    compile_rule(
        "SEC-GCP-001", "Google API key exposed", "high",
        r"\b(AIza[0-9A-Za-z_-]{35})\b",
        "Restrict and rotate the Google API key."
    ),

    # Azure
    compile_rule(
        "SEC-AZ-001", "Azure client secret assignment", "critical",
        r"""(?i)\b(?:azure_client_secret|client_secret)\s*[:=]\s*['"]([^'"]{16,})['"]""",
        "Rotate the Azure secret and use managed identity."
    ),
    compile_rule(
        "SEC-AZ-002", "Azure Storage account key assignment", "critical",
        r"""(?i)\b(?:azure_storage_key|storage_account_key)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40,})['"]""",
        "Rotate the storage key and use managed identity."
    ),

    # Slack
    compile_rule(
        "SEC-SLACK-001", "Slack API or bot token exposed", "high",
        r"\b(xox[baprs]-[A-Za-z0-9-]{10,48})\b",
        "Regenerate the Slack token."
    ),
    compile_rule(
        "SEC-SLACK-002", "Slack webhook URL exposed", "high",
        r"(https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+)",
        "Regenerate the Slack webhook."
    ),

    # Discord
    compile_rule(
        "SEC-DISCORD-001", "Discord bot token exposed", "critical",
        r"\b([MN][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{25,})\b",
        "Reset the Discord bot token."
    ),
    compile_rule(
        "SEC-DISCORD-002", "Discord webhook exposed", "high",
        r"(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)",
        "Delete and recreate the Discord webhook."
    ),

    # Telegram
    compile_rule(
        "SEC-TG-001", "Telegram bot token exposed", "critical",
        r"\b(\d{8,10}:[A-Za-z0-9_-]{35})\b",
        "Revoke the Telegram bot token using BotFather."
    ),

    # Stripe
    compile_rule(
        "SEC-STRIPE-001", "Stripe live secret key exposed", "critical",
        r"\b(sk_live_[A-Za-z0-9]{20,})\b",
        "Roll the Stripe secret key."
    ),
    compile_rule(
        "SEC-STRIPE-002", "Stripe restricted key exposed", "high",
        r"\b(rk_live_[A-Za-z0-9]{20,})\b",
        "Roll the restricted Stripe key."
    ),

    # Twilio
    compile_rule(
        "SEC-TWILIO-001", "Twilio API key exposed", "high",
        r"\b(SK[0-9a-fA-F]{32})\b",
        "Revoke the Twilio API key."
    ),

    # SendGrid
    compile_rule(
        "SEC-SG-001", "SendGrid API key exposed", "critical",
        r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b",
        "Revoke the SendGrid API key."
    ),

    # NPM
    compile_rule(
        "SEC-NPM-001", "NPM access token exposed", "critical",
        r"\b(npm_[A-Za-z0-9]{36})\b",
        "Revoke the NPM token."
    ),

    # PyPI
    compile_rule(
        "SEC-PYPI-001", "PyPI API token exposed", "critical",
        r"\b(pypi-[A-Za-z0-9_-]{50,})\b",
        "Revoke the PyPI token."
    ),

    # Heroku - require credential assignment context
    compile_rule(
        "SEC-HEROKU-001", "Heroku API key exposed", "high",
        r"""(?i)\bheroku_api_key\s*[:=]\s*['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]""",
        "Rotate the Heroku API key if exposed in source code."
    ),

    # Mailgun
    compile_rule(
        "SEC-MG-001", "Mailgun API key exposed", "critical",
        r"\b(key-[A-Za-z0-9]{32})\b",
        "Revoke the Mailgun API key."
    ),

    # Shopify
    compile_rule(
        "SEC-SHOPIFY-001", "Shopify access token exposed", "critical",
        r"\b(shpat_[A-Za-z0-9]{32,}|shpca_[A-Za-z0-9]{32,}|shppa_[A-Za-z0-9]{32,}|shpss_[A-Za-z0-9]{32,})\b",
        "Revoke the Shopify access token."
    ),

    # AI providers
    compile_rule(
        "SEC-OPENAI-001", "OpenAI API key exposed", "critical",
        r"\b(sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,})\b",
        "Revoke and replace the OpenAI API key."
    ),
    compile_rule(
        "SEC-ANTHROPIC-001", "Anthropic API key exposed", "critical",
        r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b",
        "Revoke and replace the Anthropic API key."
    ),

    # Database connection strings
    compile_rule(
        "SEC-DB-001", "Database connection string contains credentials", "critical",
        r"(?i)\b((?:mongodb|postgres(?:ql)?|mysql)://[^:\s]+:[^@\s]+@[^/\s]+)",
        "Remove credentials from the connection string and rotate them."
    ),

    # JWT
    compile_rule(
        "SEC-JWT-001", "Exposed JSON Web Token", "high",
        r"\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b",
        "Do not hardcode JWTs; invalidate and reissue the exposed token."
    ),

    # Private keys
    compile_rule(
        "SEC-KEY-001", "Asymmetric private key marker detected", "critical",
        r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)",
        "Remove the private key from source control and rotate it."
    ),

    # Generic credential assignments
    compile_rule(
        "SEC-GEN-001", "Generic hardcoded API secret or password", "high",
        r"""(?i)\b(?:api_key|apikey|secret_key|client_secret|db_password|password|access_token|auth_token)\s*[:=]\s*['"]([^'"]{8,})['"]""",
        "Externalize credentials to environment variables or a secret manager."
    ),
]


# ---------------------------------------------------------
# Entropy detection
# ---------------------------------------------------------

PLACEHOLDERS = {
    "your_api_key",
    "your_secret",
    "changeme",
    "change_me",
    "example",
    "sample",
    "placeholder",
    "dummy",
    "test",
    "password",
    "secret",
    "1234567890",
    "abcdef",
    "replace_me",
}


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not value:
        return 0.0

    length = len(value)
    frequencies = {}

    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_placeholder(value: str) -> bool:
    """Identify common placeholder values."""
    normalized = value.strip().strip("'\"").lower()

    return (
        normalized in PLACEHOLDERS
        or normalized.startswith("your_")
        or normalized.startswith("example_")
        or normalized.startswith("test_")
        or normalized.startswith("placeholder_")
        or normalized.startswith("dummy_")
    )


def entropy_candidates(line: str):
    """Yield high-entropy Base64-like or hexadecimal candidates."""

    candidates = re.findall(
        r"[A-Za-z0-9+/=_-]{16,}",
        line
    )

    for candidate in candidates:

        if is_placeholder(candidate):
            continue

        # Hex candidates are evaluated separately to avoid
        # generating both HEX and BASE64 findings.
        if re.fullmatch(r"[A-Fa-f0-9]{16,}", candidate):

            if shannon_entropy(candidate) > 3.0:
                yield candidate, "hex"

        elif shannon_entropy(candidate) > 4.5:

            yield candidate, "base64"


# ---------------------------------------------------------
# Secret Detection Engine
# ---------------------------------------------------------

class SecretEngine(BaseEngine):
    """Engine for identifying hardcoded secrets and credentials."""

    name: str = "SecretEngine"
    category: str = "Secrets & Credentials"

    description: str = (
        "Scans files for leaked credentials, "
        "private keys, API tokens and high-entropy secrets."
    )

    def scan(self, workspace_path: str) -> List[Dict[str, Any]]:

        findings = []
        seen: Set[Tuple] = set()

        files_to_scan = self.collect_scannable_files(workspace_path)

        for file_path in files_to_scan:

            rel_path = os.path.relpath(
                file_path,
                workspace_path
            )

            try:

                with open(
                    file_path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as file:

                    for line_no, line in enumerate(file, start=1):

                        known_secrets = set()

                        # ---------------------------------
                        # Regex-based detection
                        # ---------------------------------

                        for rule in SECRET_RULES:

                            match = rule["pattern"].search(line)

                            if not match:
                                continue

                            raw_secret = (
                                match.group(1)
                                if match.groups()
                                else match.group(0)
                            )

                            if is_placeholder(raw_secret):
                                continue

                            known_secrets.add(raw_secret)

                            fingerprint = (
                                rule["rule_id"],
                                rel_path,
                                line_no,
                                raw_secret,
                            )

                            if fingerprint in seen:
                                continue

                            seen.add(fingerprint)

                            findings.append(
                                self.create_finding(
                                    rule_id=rule["rule_id"],
                                    file_path=rel_path,
                                    line_number=line_no,
                                    severity=rule["severity"],
                                    description=rule["description"],
                                    raw_secret=raw_secret,
                                    match_content=line.strip(),
                                    remediation=rule["remediation"],
                                )
                            )

                        # ---------------------------------
                        # Entropy-based detection
                        # ---------------------------------

                        for candidate, candidate_type in entropy_candidates(line):

                            # Avoid duplicating a secret already
                            # detected by a provider-specific rule.
                            if any(
                                candidate in secret or secret in candidate
                                for secret in known_secrets
                            ):
                                continue

                            rule_id = (
                                f"SEC-ENT-{candidate_type.upper()}-001"
                            )

                            fingerprint = (
                                rule_id,
                                rel_path,
                                line_no,
                                candidate,
                            )

                            if fingerprint in seen:
                                continue

                            seen.add(fingerprint)

                            findings.append(
                                self.create_finding(
                                    rule_id=rule_id,
                                    file_path=rel_path,
                                    line_number=line_no,
                                    severity="medium",
                                    description=(
                                        f"High-entropy {candidate_type} token "
                                        "may contain a secret."
                                    ),
                                    raw_secret=candidate,
                                    match_content=line.strip(),
                                    remediation=(
                                        "Review the token. If it is a credential, "
                                        "rotate it and store it securely."
                                    ),
                                )
                            )

            except OSError:
                continue

        return findings
