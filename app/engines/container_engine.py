"""Container & Dockerfile Security Analysis Engine for Secret Leak Guard v2.0."""

import os
import re
from typing import Any, Dict, List
from app.engines.base import BaseEngine

DOCKERFILE_RULES = [
    {
        "rule_id": "CONT-ROOT-001",
        "description": "Container runs as root or has no explicit non-root USER instruction",
        "severity": "high",
        "check_type": "missing_user",
        "remediation": "Add 'USER nonroot' or specify a non-privileged UID before ENTRYPOINT/CMD.",
    },
    {
        "rule_id": "CONT-HEALTH-001",
        "description": "No HEALTHCHECK instruction is configured for the container",
        "severity": "medium",
        "check_type": "missing_healthcheck",
        "remediation": "Add a HEALTHCHECK that verifies the service is ready and responsive.",
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
        "rule_id": "CONT-ADD-001",
        "description": "Use of ADD instead of COPY for local files",
        "severity": "low",
        "check_type": "local_add",
        "remediation": "Prefer COPY over ADD when copying local files to avoid unexpected tar extraction.",
    },
    {
        "rule_id": "CONT-SUDO-001",
        "description": "Dockerfile installs or invokes sudo inside the container",
        "severity": "medium",
        "pattern": re.compile(r"(?i)(?:^|\s)sudo(?:\s|$)"),
        "remediation": "Run the container as a dedicated non-root user instead of installing sudo.",
    },
    {
        "rule_id": "CONT-CHMOD-001",
        "description": "Dockerfile grants unsafe world-writable file permissions",
        "severity": "medium",
        "pattern": re.compile(r"(?i)(?:--chmod(?:=|\s+)|\bchmod\s+(?:-[^\s]+\s+)*)(?:0?666|0?777)\b"),
        "remediation": "Use least-privilege file modes and avoid granting write access to all users.",
    },
    {
        "rule_id": "CONT-ENV-001",
        "description": "Hardcoded secret or credential in Dockerfile ENV or ARG instruction",
        "severity": "critical",
        "check_type": "hardcoded_secret",
        "remediation": "Do not bake credentials into image layers; inject them through a secrets manager at runtime.",
    },
    {
        "rule_id": "CONT-TAG-001",
        "description": "Base image uses a missing or mutable latest tag",
        "severity": "medium",
        "check_type": "unpinned_image",
        "remediation": "Pin base images to a specific version and preferably an immutable SHA256 digest.",
    },
]

SENSITIVE_NAME = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)")
SECRET_ASSIGNMENT = re.compile(r"(?i)(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=(['\"]?)([^'\"\s]+)")


class ContainerEngine(BaseEngine):
    """Engine for identifying misconfigurations and security flaws in Dockerfiles and container manifests."""

    name: str = "ContainerEngine"
    category: str = "Container Security"
    description: str = "Analyzes Dockerfiles and container specifications for security anti-patterns."

    def _emit(self, rule: Dict[str, Any], rel_path: str, line_number: int, content: str) -> Dict[str, Any]:
        return self.create_finding(
            rule_id=rule["rule_id"],
            file_path=rel_path,
            line_number=line_number,
            severity=rule["severity"],
            description=rule["description"],
            match_content=content,
            remediation=rule["remediation"],
        )

    @staticmethod
    def _image_is_unpinned(line: str) -> bool:
        parts = line.split()
        image_index = next((index for index, part in enumerate(parts) if part.upper() == "FROM"), None)
        if image_index is None:
            return False
        image = next((part for part in parts[image_index + 1:] if not part.startswith("--")), "")
        if image.upper() == "SCRATCH" or not image:
            return False
        if "@sha256:" in image:
            return False
        final_component = image.rsplit("/", 1)[-1]
        if ":" not in final_component:
            return True
        return final_component.rsplit(":", 1)[1].lower() == "latest"

    @staticmethod
    def _is_local_add(line: str) -> bool:
        parts = line.split()
        if not parts or parts[0].upper() != "ADD":
            return False
        sources = []
        index = 1
        while index < len(parts):
            part = parts[index]
            if part.startswith("--"):
                index += 1
                if "=" not in part and index < len(parts):
                    index += 1
                continue
            sources.append(part)
            index += 1
        return bool(sources) and not sources[0].lower().startswith(("http://", "https://"))

    @staticmethod
    def _hardcoded_secret(line: str) -> bool:
        instruction = line.split(None, 1)
        if len(instruction) != 2 or instruction[0].upper() not in {"ENV", "ARG"}:
            return False
        assignments = list(SECRET_ASSIGNMENT.finditer(instruction[1]))
        if instruction[0].upper() == "ENV" and not assignments:
            # Docker's legacy ENV syntax is "ENV name value".
            legacy = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s+(.+)", instruction[1])
            assignments = [legacy] if legacy else []
            if assignments and not SENSITIVE_NAME.search(assignments[0].group(1)):
                return False
            return bool(assignments and assignments[0].group(2).strip() and "$" not in assignments[0].group(2))
        return any(
            SENSITIVE_NAME.search(match.group(1))
            and match.group(3).strip()
            and not match.group(3).startswith("$")
            for match in assignments
        )

    def scan(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        dockerfile_candidates = []

        for root, _, files in os.walk(workspace_path):
            for file in files:
                if file.lower() == "dockerfile" or file.lower().endswith((".dockerfile", ".containerfile")):
                    dockerfile_candidates.append(os.path.join(root, file))

        for df_path in dockerfile_candidates:
            rel_path = os.path.relpath(df_path, workspace_path)
            last_stage_user = None
            last_stage_user_line = 1
            has_healthcheck = False

            try:
                with open(df_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                pending = ""
                pending_line = 1
                for line_no, raw_line in enumerate(lines, start=1):
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if not pending:
                        pending_line = line_no
                    pending += line[:-1].rstrip() + " " if line.endswith("\\") else line
                    if line.endswith("\\"):
                        continue
                    line = pending.strip()
                    pending = ""

                    if line.upper().startswith("FROM "):
                        last_stage_user = None
                        last_stage_user_line = line_no
                        has_healthcheck = False
                    elif line.upper().startswith("USER "):
                        user_value = line.split(None, 1)[1].strip()
                        last_stage_user = user_value.split()[0] if user_value else None
                        last_stage_user_line = line_no
                    elif line.upper().startswith("HEALTHCHECK "):
                        has_healthcheck = line.upper() != "HEALTHCHECK NONE"

                    for rule in DOCKERFILE_RULES:
                        if rule.get("pattern") and rule["pattern"].search(line):
                            findings.append(self._emit(rule, rel_path, pending_line, line))
                    for check_type, predicate in (
                        ("unpinned_image", self._image_is_unpinned),
                        ("hardcoded_secret", self._hardcoded_secret),
                        ("local_add", self._is_local_add),
                    ):
                        rule = next((r for r in DOCKERFILE_RULES if r.get("check_type") == check_type), None)
                        if rule and predicate(line):
                            findings.append(self._emit(rule, rel_path, pending_line, line))

                # Evaluate the final build stage; an explicit USER root is not safe.
                user_identity = last_stage_user.split(":", 1)[0].lower() if last_stage_user else None
                is_root = user_identity is None or user_identity == "root" or user_identity.startswith("$") or (
                    user_identity.isdecimal() and int(user_identity) == 0
                )
                if is_root and lines:
                    root_rule = next(r for r in DOCKERFILE_RULES if r.get("check_type") == "missing_user")
                    findings.append(
                        self.create_finding(
                            rule_id=root_rule["rule_id"],
                            file_path=rel_path,
                            line_number=last_stage_user_line,
                            severity=root_rule["severity"],
                            description=root_rule["description"],
                            raw_secret=None,
                            match_content=(
                                f"USER {last_stage_user}" if last_stage_user is not None
                                else "<missing USER directive>"
                            ),
                            remediation=root_rule["remediation"],
                        )
                    )
                if not has_healthcheck and lines:
                    healthcheck_rule = next(
                        r for r in DOCKERFILE_RULES if r.get("check_type") == "missing_healthcheck"
                    )
                    findings.append(
                        self.create_finding(
                            rule_id=healthcheck_rule["rule_id"],
                            file_path=rel_path,
                            line_number=max(1, len(lines)),
                            severity=healthcheck_rule["severity"],
                            description=healthcheck_rule["description"],
                            match_content="<missing HEALTHCHECK instruction>",
                            remediation=healthcheck_rule["remediation"],
                        )
                    )

            except (OSError, UnicodeDecodeError):
                continue

        return findings
