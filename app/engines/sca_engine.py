"""Software Composition Analysis (SCA) Engine for Secret Leak Guard v2.0."""

import os
import re
from typing import Any, Dict, List
from app.engines.base import BaseEngine

# Sample vulnerable package signatures for SCA mock/stub
KNOWN_VULNERABLE_PACKAGES = [
    {
        "package": "requests",
        "pattern": re.compile(r"""^\s*requests\s*(?:==|<=|<)\s*(?:2\.(?:[0-9]|1[0-9]|2[0-7])\b)"""),
        "rule_id": "SCA-PY-001",
        "severity": "medium",
        "description": "Outdated requests package with known CVEs (CVE-2023-32681)",
        "remediation": "Upgrade requests to >= 2.31.0.",
    },
    {
        "package": "urllib3",
        "pattern": re.compile(r"""^\s*urllib3\s*(?:==|<=|<)\s*(?:1\.(?:[0-9]|1[0-9]|2[0-5])\b)"""),
        "rule_id": "SCA-PY-002",
        "severity": "high",
        "description": "Vulnerable urllib3 package with CVE-2021-33503 (ReDoS / CRLF injection)",
        "remediation": "Upgrade urllib3 to >= 1.26.5 or 2.0.0+.",
    },
    {
        "package": "pyyaml",
        "pattern": re.compile(r"""^\s*pyyaml\s*(?:==|<=|<)\s*(?:5\.[1-3]\b|[1-4]\.)"""),
        "rule_id": "SCA-PY-003",
        "severity": "critical",
        "description": "PyYAML arbitrary code execution vulnerability (CVE-2020-14343)",
        "remediation": "Upgrade PyYAML to >= 5.4 or use safe_load.",
    },
    {
        "package": "flask",
        "pattern": re.compile(r"""^\s*flask\s*(?:==|<=|<)\s*(?:0\.|1\.[0-1]\b)"""),
        "rule_id": "SCA-PY-004",
        "severity": "medium",
        "description": "Outdated Flask version vulnerable to unexpected session tampering",
        "remediation": "Upgrade Flask to >= 3.0.0.",
    },
    {
        "package": "cryptography",
        "pattern": re.compile(r"""^\s*cryptography\s*(?:==|<=|<)\s*(?:3\.|40\.)"""),
        "rule_id": "SCA-PY-005",
        "severity": "high",
        "description": "Vulnerable cryptography package with OpenSSL memory corruption flaws",
        "remediation": "Upgrade cryptography to >= 41.0.6.",
    },
]


class SCAEngine(BaseEngine):
    """Engine for identifying vulnerable open-source dependencies in project manifests."""

    name: str = "SCAEngine"
    category: str = "Software Composition Analysis"
    description: str = "Scans package manifests (e.g. requirements.txt) for known vulnerable libraries."

    def scan(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        manifest_names = ("requirements.txt", "Pipfile", "pyproject.toml", "package.json")

        for root, _, files in os.walk(workspace_path):
            for file in files:
                if file.lower() in manifest_names:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, workspace_path)

                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            for line_no, line in enumerate(f, start=1):
                                stripped = line.strip()
                                if not stripped or stripped.startswith("#"):
                                    continue
                                for vuln in KNOWN_VULNERABLE_PACKAGES:
                                    if vuln["pattern"].search(stripped):
                                        findings.append(
                                            self.create_finding(
                                                rule_id=vuln["rule_id"],
                                                file_path=rel_path,
                                                line_number=line_no,
                                                severity=vuln["severity"],
                                                description=vuln["description"],
                                                raw_secret=None,
                                                match_content=stripped,
                                                remediation=vuln["remediation"],
                                            )
                                        )
                    except (OSError, UnicodeDecodeError):
                        continue

        return findings
