"""Container & Dockerfile Security Analysis Engine for Secret Leak Guard v2.0."""

import os
import re
from typing import Any, Dict, List
from app.engines.base import BaseEngine

DOCKERFILE_RULES = [
    {
        "rule_id": "CONT-ROOT-001",
        "description": "Container runs as default root user; no non-root USER instruction found",
        "severity": "high",
        "check_type": "missing_user",
        "remediation": "Add 'USER nonroot' or specify a non-privileged UID before ENTRYPOINT/CMD.",
    },
    {
        "rule_id": "CONT-TAG-001",
        "description": "Base image uses mutable or missing ':latest' tag",
        "severity": "medium",
        "pattern": re.compile(r"""(?i)^\s*FROM\s+([^\s:]+(?::latest|\s*$))"""),
        "remediation": "Pin base images to an immutable SHA256 digest or specific semantic version tag.",
    },
    {
        "rule_id": "CONT-PORT-001",
        "description": "Exposing sensitive database or admin port (22, 27017, 6379, 8200)",
        "severity": "high",
        "pattern": re.compile(r"""(?i)^\s*EXPOSE\s+.*?\b(22|27017|6379|8200|3306|5432)\b"""),
        "remediation": "Do not expose internal database or SSH ports directly on public containers.",
    },
    {
        "rule_id": "CONT-CURL-001",
        "description": "Insecure piping of curl/wget to bash or sh",
        "severity": "critical",
        "pattern": re.compile(r"""(?i)(?:curl|wget)[^|\n]+?\|\s*(?:bash|sh)"""),
        "remediation": "Download scripts, verify their cryptographic hash, and inspect before running.",
    },
    {
        "rule_id": "CONT-ENV-001",
        "description": "Hardcoded secret or credential in Dockerfile ENV instruction",
        "severity": "critical",
        "pattern": re.compile(r"""(?i)^\s*ENV\s+.*?(?:password|secret|token|api_key)\s*=\s*['"]?[A-Za-z0-9_\-!@#$%^&*]{6,}"""),
        "remediation": "Do not burn credentials into container images; mount secrets at runtime using Vault.",
    },
    {
        "rule_id": "CONT-ADD-001",
        "description": "Use of ADD instead of COPY for local files",
        "severity": "low",
        "pattern": re.compile(r"""(?i)^\s*ADD\s+(?!https?://)"""),
        "remediation": "Prefer COPY over ADD when copying local files to avoid unexpected tar extraction.",
    },
]


class ContainerEngine(BaseEngine):
    """Engine for identifying misconfigurations and security flaws in Dockerfiles and container manifests."""

    name: str = "ContainerEngine"
    category: str = "Container Security"
    description: str = "Analyzes Dockerfiles and container specifications for security anti-patterns."

    def scan(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        dockerfile_candidates = []

        for root, _, files in os.walk(workspace_path):
            for file in files:
                if file.lower() == "dockerfile" or file.lower().endswith((".dockerfile", ".containerfile")):
                    dockerfile_candidates.append(os.path.join(root, file))

        for df_path in dockerfile_candidates:
            rel_path = os.path.relpath(df_path, workspace_path)
            has_user_directive = False

            try:
                with open(df_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_no, raw_line in enumerate(lines, start=1):
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.upper().startswith("USER "):
                        has_user_directive = True

                    for rule in DOCKERFILE_RULES:
                        if "pattern" in rule and rule["pattern"].search(line):
                            findings.append(
                                self.create_finding(
                                    rule_id=rule["rule_id"],
                                    file_path=rel_path,
                                    line_number=line_no,
                                    severity=rule["severity"],
                                    description=rule["description"],
                                    raw_secret=None,
                                    match_content=line,
                                    remediation=rule["remediation"],
                                )
                            )

                # Check if USER instruction was completely absent in the Dockerfile
                if not has_user_directive and lines:
                    root_rule = next(r for r in DOCKERFILE_RULES if r.get("check_type") == "missing_user")
                    findings.append(
                        self.create_finding(
                            rule_id=root_rule["rule_id"],
                            file_path=rel_path,
                            line_number=1,
                            severity=root_rule["severity"],
                            description=root_rule["description"],
                            raw_secret=None,
                            match_content="<missing USER directive>",
                            remediation=root_rule["remediation"],
                        )
                    )

            except (OSError, UnicodeDecodeError):
                continue

        return findings
