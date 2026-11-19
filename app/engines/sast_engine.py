"""Static Application Security Testing (SAST) Engine for Secret Leak Guard v2.0."""

import ast
import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List
from app.engines.base import BaseEngine
from app.scoring import calculate_finding_fingerprint

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


AST_RULES = {
    "SAST-CMD-001": (
        "Potential Command Injection via os.system or subprocess with shell=True",
        "critical",
        "Avoid invoking shell directly; pass arguments as an array with shell=False.",
    ),
    "SAST-SQL-001": (
        "Potential SQL Injection via string formatting in SQL execute call",
        "high",
        "Use parameterized queries or ORM query building instead of string interpolation.",
    ),
    "SAST-DESER-001": (
        "Insecure Deserialization via pickle.loads or yaml.load without SafeLoader",
        "critical",
        "Use safe deserialization (e.g. yaml.safe_load, json.loads) instead of pickle.",
    ),
    "SAST-EVAL-001": (
        "Dangerous use of dynamic evaluation (eval / exec)",
        "high",
        "Avoid using eval/exec on untrusted or dynamic input.",
    ),
    "SAST-CRYPTO-001": (
        "Weak Cryptographic Hash Function (MD5 or SHA1) used",
        "medium",
        "Use secure hashing algorithms such as SHA-256 or bcrypt for sensitive data.",
    ),
}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _python_ast_findings(source: str, file_path: str, engine: "SASTEngine") -> List[Dict[str, Any]]:
    """Finds Python call-site issues from syntax trees without importing or executing code."""
    try:
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError):
        return []

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        name = _call_name(node.func)
        rule_id = None
        if name == "os.system" or (
            name in {"subprocess.call", "subprocess.Popen", "subprocess.run"}
            and any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True for keyword in node.keywords)
        ):
            rule_id = "SAST-CMD-001"
        elif name in {"eval", "exec"}:
            rule_id = "SAST-EVAL-001"
        elif name == "pickle.loads" or (
            name == "yaml.load"
            and not any(
                keyword.arg == "Loader"
                and "SafeLoader" in _call_name(keyword.value)
                for keyword in node.keywords
            )
        ):
            rule_id = "SAST-DESER-001"
        elif name in {"hashlib.md5", "hashlib.sha1"}:
            rule_id = "SAST-CRYPTO-001"
        elif name.endswith((".execute", ".raw_sql")) and node.args:
            query = node.args[0]
            formatted = isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
                isinstance(query, ast.Call)
                and isinstance(query.func, ast.Attribute)
                and query.func.attr == "format"
            )
            if formatted:
                rule_id = "SAST-SQL-001"

        if rule_id:
            description, severity, remediation = AST_RULES[rule_id]
            findings.append(
                engine.create_finding(
                    rule_id=rule_id,
                    file_path=file_path,
                    line_number=node.lineno,
                    severity=severity,
                    description=description,
                    match_content=ast.get_source_segment(source, node) or "",
                    remediation=remediation,
                )
            )
    return findings


def _tool_severity(value: str, mapping: Dict[str, str]) -> str:
    return mapping.get(str(value).upper(), "medium")


class SASTEngine(BaseEngine):
    """Engine for identifying code vulnerabilities and insecure programming patterns."""

    name: str = "SASTEngine"
    category: str = "Code Quality & SAST"
    description: str = "Performs Static Application Security Testing on source code files."

    def __init__(
        self,
        semgrep_binary: str = "semgrep",
        bandit_binary: str = "bandit",
        tool_timeout: int = 120,
    ):
        self.semgrep_binary = semgrep_binary
        self.bandit_binary = bandit_binary
        self.tool_timeout = tool_timeout

    def _run_json_tool(self, command: List[str], workspace_path: str, tool: str) -> Dict[str, Any]:
        if shutil.which(command[0]) is None:
            raise RuntimeError(f"{tool} is required for runtime SAST scans but is not installed.")
        try:
            result = subprocess.run(
                command,
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=self.tool_timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"{tool} exceeded the {self.tool_timeout}-second scan timeout.") from error
        try:
            report = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError) as error:
            raise RuntimeError(f"{tool} returned invalid JSON output.") from error
        if result.returncode != 0:
            bandit_findings_status = (
                tool == "Bandit"
                and result.returncode == 1
                and not report.get("errors")
            )
            if not bandit_findings_status:
                raise RuntimeError(f"{tool} exited with status {result.returncode}.")
        return report

    @staticmethod
    def _relative_tool_path(path: str, workspace_path: str) -> str:
        if not path:
            return "."
        resolved = os.path.realpath(os.path.join(workspace_path, path) if not os.path.isabs(path) else path)
        workspace = os.path.realpath(workspace_path)
        if os.path.commonpath((workspace, resolved)) != workspace:
            raise RuntimeError("Static analysis tool returned a path outside the scan workspace.")
        return os.path.relpath(resolved, workspace)

    def _run_semgrep(self, workspace_path: str) -> List[Dict[str, Any]]:
        report = self._run_json_tool(
            [
                self.semgrep_binary,
                "scan",
                "--config", os.path.join(os.path.dirname(__file__), "semgrep_rules.yml"),
                "--json",
                "--metrics=off",
                "--no-git-ignore",
                "--quiet",
                "--max-target-bytes", "5000000",
                "--exclude", ".git",
                "--exclude", "node_modules",
                "--exclude", ".venv",
                workspace_path,
            ],
            workspace_path,
            "Semgrep",
        )
        findings = []
        for result in report.get("results", []):
            extra = result.get("extra") or {}
            metadata = extra.get("metadata") or {}
            rule_id = str(result.get("check_id") or "semgrep/unknown")
            severity = _tool_severity(
                extra.get("severity") or metadata.get("severity"),
                {"ERROR": "critical", "WARNING": "high", "INFO": "medium"},
            )
            path = self._relative_tool_path(str(result.get("path") or ""), workspace_path)
            findings.append(self.create_finding(
                rule_id=f"SAST-SEMGREP-{rule_id}",
                file_path=path,
                line_number=int((result.get("start") or {}).get("line") or 1),
                severity=severity,
                description=str(extra.get("message") or rule_id),
                match_content=str(extra.get("lines") or ""),
                remediation=str(metadata.get("remediation") or "Review and remediate this static analysis finding."),
            ))
        return findings

    def _run_bandit(self, workspace_path: str) -> List[Dict[str, Any]]:
        python_files = self.collect_scannable_files(workspace_path, extensions=(".py",))
        if not python_files:
            return []
        findings = []
        for offset in range(0, len(python_files), 100):
            report = self._run_json_tool(
                [self.bandit_binary, "-f", "json", "-q", *python_files[offset:offset + 100]],
                workspace_path,
                "Bandit",
            )
            for result in report.get("results", []):
                path = self._relative_tool_path(str(result.get("filename") or ""), workspace_path)
                test_id = str(result.get("test_id") or "B999")
                findings.append(self.create_finding(
                    rule_id=f"SAST-BANDIT-{test_id}",
                    file_path=path,
                    line_number=int(result.get("line_number") or 1),
                    severity=_tool_severity(
                        result.get("issue_severity"),
                        {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"},
                    ),
                    description=str(result.get("issue_text") or test_id),
                    match_content=str(result.get("code") or ""),
                    remediation=str(result.get("more_info") or "Review and remediate this Bandit finding."),
                ))
        return findings

    def scan(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        extensions = (".py", ".js", ".ts", ".php", ".rb", ".java", ".go")
        files_to_scan = self.collect_scannable_files(workspace_path, extensions=extensions)

        for file_path in files_to_scan:
            rel_path = os.path.relpath(file_path, workspace_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                    for line_no, line in enumerate(source.splitlines(), start=1):
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
                if file_path.lower().endswith(".py"):
                    findings.extend(_python_ast_findings(source, rel_path, self))
            except (OSError, UnicodeDecodeError):
                continue

        findings.extend(self._run_semgrep(workspace_path))
        findings.extend(self._run_bandit(workspace_path))
        unique_findings = {}
        for finding in findings:
            unique_findings.setdefault(calculate_finding_fingerprint(finding), finding)
        return list(unique_findings.values())
