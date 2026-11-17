"""Secret Detection Engine for Secret Leak Guard v2.0."""

import os
import re
from typing import Any, Dict, List
from app.engines.base import BaseEngine

# Detection rules for secrets with regex and severity
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
]


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
                        for rule in SECRET_RULES:
                            match = rule["pattern"].search(line)
                            if match:
                                raw_secret = match.group(1) if match.groups() else match.group(0)
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
            except (OSError, UnicodeDecodeError):
                continue

        return findings
