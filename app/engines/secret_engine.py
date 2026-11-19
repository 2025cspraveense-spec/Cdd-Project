"""Secret Detection Engine for Secret Leak Guard v2.0."""

import os
import re
import math
from collections import Counter
from typing import Any, Dict, List
from app.engines.base import BaseEngine

# Provider-specific credential signatures. Generic entropy checks below cover
# opaque tokens that do not have a recognizable provider prefix.
SECRET_RULES = [
    {
        "rule_id": "SEC-AWS-001",
        "description": "AWS Access Key ID exposed in code",
        "severity": "critical",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "remediation": "Revoke the exposed AWS key and use IAM Roles or HashiCorp Vault.",
    },
    {
        "rule_id": "SEC-GH-001",
        "description": "GitHub Personal Access Token exposed",
        "severity": "critical",
        "pattern": re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
        "remediation": "Revoke the GitHub PAT immediately and rotate credentials.",
    },
    {
        "rule_id": "SEC-SLACK-001",
        "description": "Slack API / Bot Token exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        "remediation": "Regenerate the Slack bot/user token in the Slack API dashboard.",
    },
    {
        "rule_id": "SEC-KEY-001",
        "description": "Asymmetric Private Key block detected",
        "severity": "critical",
        "pattern": re.compile(r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----"),
        "remediation": "Do not commit private keys to source control; store in Vault or KMS.",
    },
    {
        "rule_id": "SEC-GEN-001",
        "description": "Generic hardcoded API secret or password assignment",
        "severity": "high",
        "pattern": re.compile(
            r"""(?i)(?:api_key|apikey|secret_key|client_secret|db_password|password)\s*[:=]\s*['"]([A-Za-z0-9_\-!@#$%^&*]{8,})['"]"""
        ),
        "remediation": "Externalize sensitive configuration to environment variables or Vault.",
    },
    {
        "rule_id": "SEC-JWT-001",
        "description": "Exposed JSON Web Token (JWT) string",
        "severity": "medium",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"),
        "remediation": "Avoid hardcoding JWT tokens; issue tokens dynamically.",
    },
    {
        "rule_id": "SEC-AWS-002",
        "description": "AWS Secret Access Key exposed",
        "severity": "critical",
        "pattern": re.compile(r"""(?i)(?:aws[_-]?)?secret[_-]?access[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})"""),
        "remediation": "Revoke and rotate the AWS secret; use an IAM role or Vault.",
    },
    {
        "rule_id": "SEC-GH-002",
        "description": "GitHub fine-grained personal access token exposed",
        "severity": "critical",
        "pattern": re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        "remediation": "Revoke the token and issue a replacement with least privilege.",
    },
    {
        "rule_id": "SEC-GITLAB-001",
        "description": "GitLab personal or project access token exposed",
        "severity": "critical",
        "pattern": re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"),
        "remediation": "Revoke and rotate the GitLab token.",
    },
    {
        "rule_id": "SEC-GCP-001",
        "description": "Google API key exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        "remediation": "Restrict, revoke, and rotate the Google API key.",
    },
    {
        "rule_id": "SEC-GCP-002",
        "description": "Google OAuth client secret exposed",
        "severity": "high",
        "pattern": re.compile(r"""(?i)client_secret\s*[:=]\s*['"]?(GOCSPX-[A-Za-z0-9_-]{20,})"""),
        "remediation": "Rotate the OAuth client secret in Google Cloud Console.",
    },
    {
        "rule_id": "SEC-AZURE-001",
        "description": "Azure Storage account key exposed",
        "severity": "critical",
        "pattern": re.compile(r"""(?i)(?:accountkey|account_key)\s*[:=]\s*['"]?([A-Za-z0-9+/]{80,}={0,2})"""),
        "remediation": "Rotate the storage account key and use managed identity.",
    },
    {
        "rule_id": "SEC-AZURE-002",
        "description": "Azure application client secret exposed",
        "severity": "high",
        "pattern": re.compile(r"""(?i)azure[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9~._-]{16,})"""),
        "remediation": "Rotate the application secret and use a managed identity.",
    },
    {
        "rule_id": "SEC-STRIPE-001",
        "description": "Stripe secret API key exposed",
        "severity": "critical",
        "pattern": re.compile(r"\b(sk_live_[0-9A-Za-z]{16,})\b"),
        "remediation": "Roll the Stripe secret key and review recent API activity.",
    },
    {
        "rule_id": "SEC-STRIPE-002",
        "description": "Stripe restricted API key exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(rk_live_[0-9A-Za-z]{16,})\b"),
        "remediation": "Roll the Stripe restricted key and scope its permissions.",
    },
    {
        "rule_id": "SEC-OPENAI-001",
        "description": "OpenAI API key exposed",
        "severity": "critical",
        "pattern": re.compile(r"\b(sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,})\b"),
        "remediation": "Revoke and rotate the API key in the provider console.",
    },
    {
        "rule_id": "SEC-ANTHROPIC-001",
        "description": "Anthropic API key exposed",
        "severity": "critical",
        "pattern": re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b"),
        "remediation": "Revoke and rotate the API key in the provider console.",
    },
    {
        "rule_id": "SEC-TWILIO-001",
        "description": "Twilio authentication token exposed",
        "severity": "high",
        "pattern": re.compile(r"""(?i)twilio[_-]?auth[_-]?token\s*[:=]\s*['"]?([0-9a-f]{32})"""),
        "remediation": "Rotate the Twilio auth token and review account activity.",
    },
    {
        "rule_id": "SEC-SENDGRID-001",
        "description": "SendGrid API key exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b"),
        "remediation": "Revoke and rotate the SendGrid API key.",
    },
    {
        "rule_id": "SEC-MAILGUN-001",
        "description": "Mailgun API key exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(key-[0-9a-f]{32})\b"),
        "remediation": "Revoke and rotate the Mailgun API key.",
    },
    {
        "rule_id": "SEC-MAILCHIMP-001",
        "description": "Mailchimp API key exposed",
        "severity": "high",
        "pattern": re.compile(r"\b([0-9a-f]{32}-us[0-9]{1,2})\b"),
        "remediation": "Revoke and rotate the Mailchimp API key.",
    },
    {
        "rule_id": "SEC-NPM-001",
        "description": "npm access token exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(npm_[A-Za-z0-9]{30,})\b"),
        "remediation": "Revoke and rotate the npm token.",
    },
    {
        "rule_id": "SEC-PYPI-001",
        "description": "PyPI API token exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(pypi-[A-Za-z0-9_-]{50,})\b"),
        "remediation": "Revoke and rotate the PyPI token.",
    },
    {
        "rule_id": "SEC-DISCORD-001",
        "description": "Discord bot token exposed",
        "severity": "high",
        "pattern": re.compile(r"\b([MN][A-Za-z\d_-]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,})\b"),
        "remediation": "Reset the bot token in the Discord developer portal.",
    },
    {
        "rule_id": "SEC-DISCORD-002",
        "description": "Discord webhook credential exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,})\b"),
        "remediation": "Delete and recreate the webhook.",
    },
    {
        "rule_id": "SEC-HEROKU-001",
        "description": "Heroku API key exposed",
        "severity": "high",
        "pattern": re.compile(r"""(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['"]?([0-9a-f]{32})"""),
        "remediation": "Revoke and rotate the Heroku API key.",
    },
    {
        "rule_id": "SEC-SHOPIFY-001",
        "description": "Shopify access token exposed",
        "severity": "critical",
        "pattern": re.compile(r"\b(shpat_[A-Za-z0-9]{32,})\b"),
        "remediation": "Revoke and rotate the Shopify access token.",
    },
    {
        "rule_id": "SEC-SQUARE-001",
        "description": "Square access token exposed",
        "severity": "critical",
        "pattern": re.compile(r"\b(sq0atp-[A-Za-z0-9_-]{22,})\b"),
        "remediation": "Revoke and rotate the Square access token.",
    },
    {
        "rule_id": "SEC-DATADOG-001",
        "description": "Datadog API key exposed",
        "severity": "high",
        "pattern": re.compile(r"""(?i)datadog[_-]?api[_-]?key\s*[:=]\s*['"]?([0-9a-f]{32})"""),
        "remediation": "Revoke and rotate the Datadog API key.",
    },
    {
        "rule_id": "SEC-NEWRELIC-001",
        "description": "New Relic license key exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(NRAK-[A-Z0-9]{27})\b"),
        "remediation": "Revoke and rotate the New Relic key.",
    },
    {
        "rule_id": "SEC-HUGGINGFACE-001",
        "description": "Hugging Face access token exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(hf_[A-Za-z0-9]{30,})\b"),
        "remediation": "Revoke and rotate the Hugging Face token.",
    },
]

OPAQUE_TOKEN = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z0-9+/_-]{16,}={0,2})(?![A-Za-z0-9_])")


def shannon_entropy(value: str) -> float:
    """Returns Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class SecretEngine(BaseEngine):
    """Engine for identifying hardcoded secrets, API keys, and credentials."""

    name: str = "SecretEngine"
    category: str = "Secrets & Credentials"
    description: str = "Scans files for leaked credentials, private keys, and API tokens."

    def scan(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        files_to_scan = self.collect_scannable_files(workspace_path)

        for file_path in files_to_scan:
            rel_path = os.path.relpath(file_path, workspace_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        matched_secrets = set()
                        for rule in SECRET_RULES:
                            match = rule["pattern"].search(line)
                            if match:
                                raw_secret = match.group(1) if match.groups() else match.group(0)
                                matched_secrets.add(raw_secret)
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
                        for match in OPAQUE_TOKEN.finditer(line):
                            token = match.group(1)
                            if any(token in secret or secret in token for secret in matched_secrets):
                                continue
                            if re.fullmatch(r"[0-9a-fA-F]{16,}", token):
                                rule_id, description, threshold = (
                                    "SEC-ENTROPY-HEX",
                                    "High-entropy hexadecimal token detected",
                                    3.0,
                                )
                            else:
                                rule_id, description, threshold = (
                                    "SEC-ENTROPY-B64",
                                    "High-entropy Base64-like token detected",
                                    4.5,
                                )
                            if shannon_entropy(token) <= threshold:
                                continue
                            findings.append(
                                self.create_finding(
                                    rule_id=rule_id,
                                    file_path=rel_path,
                                    line_number=line_no,
                                    severity="high",
                                    description=description,
                                    raw_secret=token,
                                    match_content=line.strip(),
                                    remediation="Treat the value as a secret; revoke it if active and store it in a secrets manager.",
                                )
                            )
            except (OSError, UnicodeDecodeError):
                continue

        return findings
