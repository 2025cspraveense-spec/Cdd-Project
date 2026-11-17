"""Static Application Security Testing (SAST) Engine for Secret Leak Guard v2.0."""

import os
import re
from typing import Any, Dict, List
from app.engines.base import BaseEngine

SAST_RULES = [
    {
        "rule_id": "SAST-CMD-001",
        "description": "Potential Command Injection via os.system or subprocess with shell=True",
        "severity": "critical",
        "pattern": re.compile(r"""(?:os\.system|subprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True)"""),
        "remediation": "Avoid invoking shell directly; pass arguments as an array with shell=False.",
    },
    {
        "rule_id": "SAST-SQL-001",
        "description": "Potential SQL Injection via string formatting in SQL execute call",
        "severity": "high",
        "pattern": re.compile(r"""(?:execute|raw_sql)\s*\(\s*(?:f['"]|['"].*%s|\.format\()"""),
        "remediation": "Use parameterized queries or ORM query building instead of string interpolation.",
    },
    {
        "rule_id": "SAST-DESER-001",
        "description": "Insecure Deserialization via pickle.loads or yaml.load without SafeLoader",
        "severity": "critical",
        "pattern": re.compile(r"""(?:pickle\.loads|yaml\.load\s*\([^)]*(?:Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader)|$))"""),
        "remediation": "Use safe deserialization (e.g. yaml.safe_load, json.loads) instead of pickle.",
    },
    {
        "rule_id": "SAST-CRYPTO-001",
        "description": "Weak Cryptographic Hash Function (MD5 or SHA1) used",
        "severity": "medium",
        "pattern": re.compile(r"""hashlib\.(?:md5|sha1)\s*\("""),
        "remediation": "Use secure hashing algorithms such as SHA-256 or bcrypt for sensitive data.",
    },
    {
        "rule_id": "SAST-EVAL-001",
        "description": "Dangerous use of dynamic evaluation (eval / exec)",
        "severity": "high",
        "pattern": re.compile(r"""\b(?:eval|exec)\s*\("""),
        "remediation": "Avoid using eval/exec on untrusted or dynamic input.",
    },
]


class SASTEngine(BaseEngine):
    """Engine for identifying code vulnerabilities and insecure programming patterns."""

    name: str = "SASTEngine"
    category: str = "Code Quality & SAST"
    description: str = "Performs Static Application Security Testing on source code files."

    def scan(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        extensions = (".py", ".js", ".ts", ".php", ".rb", ".java", ".go")
        files_to_scan = self.collect_scannable_files(workspace_path, extensions=extensions)

        for file_path in files_to_scan:
            rel_path = os.path.relpath(file_path, workspace_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        for rule in SAST_RULES:
                            match = rule["pattern"].search(line)
                            if match:
                                findings.append(
                                    self.create_finding(
                                        rule_id=rule["rule_id"],
                                        file_path=rel_path,
                                        line_number=line_no,
                                        severity=rule["severity"],
                                        description=rule["description"],
                                        raw_secret=None,
                                        match_content=line.strip(),
                                        remediation=rule["remediation"],
                                    )
                                )
            except (OSError, UnicodeDecodeError):
                continue

        return findings
