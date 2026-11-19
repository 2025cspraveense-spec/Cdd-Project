"""Software Composition Analysis (SCA) Engine using OSV.dev."""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import requests
from packaging.version import InvalidVersion, Version
from semantic_version import Version as SemVer

from app.engines.base import BaseEngine

PINNED_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)"
)
EXACT_VERSION = re.compile(r"^[0-9]+(?:\.[0-9A-Za-z_-]+){1,3}$")


class SCAEngine(BaseEngine):
    """Queries OSV.dev for pinned dependencies found in supported manifests."""

    name: str = "SCAEngine"
    category: str = "Software Composition Analysis"
    description: str = "Scans pinned Python and npm dependencies against OSV.dev advisories."

    def __init__(
        self,
        enabled: bool = True,
        api_url: str = "https://api.osv.dev/v1/querybatch",
        timeout: int = 10,
    ):
        self.enabled = enabled
        self.api_url = api_url
        self.timeout = timeout

    @staticmethod
    def _compare_versions(left: str, right: str, range_type: str, ecosystem: str) -> int:
        """Compare OSV event versions using ecosystem-aware version ordering."""
        try:
            if range_type == "SEMVER" or ecosystem.lower() == "npm":
                a = SemVer.coerce(left)
                b = SemVer.coerce(right)
            elif ecosystem.lower() == "pypi":
                a = Version(left)
                b = Version(right)
            else:
                raise ValueError(f"Unsupported ecosystem version ordering: {ecosystem}")
        except (ValueError, InvalidVersion) as error:
            raise RuntimeError("OSV returned a version that cannot be compared safely.") from error
        return (a > b) - (a < b)

    @classmethod
    def _range_affects(cls, version: str, version_range: Dict[str, Any], ecosystem: str) -> bool:
        range_type = str(version_range.get("type") or "").upper()
        if range_type not in {"SEMVER", "ECOSYSTEM"}:
            return False
        if range_type == "SEMVER" and ecosystem.lower() not in {"npm", "pypi"}:
            return False

        lower: Optional[str] = None
        for event in version_range.get("events", []):
            if "introduced" in event:
                lower = str(event["introduced"])
                if lower == "0":
                    lower = None
            elif "fixed" in event:
                upper = str(event["fixed"])
                if lower is None or cls._compare_versions(version, lower, range_type, ecosystem) >= 0:
                    if cls._compare_versions(version, upper, range_type, ecosystem) < 0:
                        return True
                lower = None
            elif "last_affected" in event:
                upper = str(event["last_affected"])
                if lower is None or cls._compare_versions(version, lower, range_type, ecosystem) >= 0:
                    if cls._compare_versions(version, upper, range_type, ecosystem) <= 0:
                        return True
                lower = None
            elif "limit" in event:
                upper = str(event["limit"])
                if lower is None or cls._compare_versions(version, lower, range_type, ecosystem) >= 0:
                    if cls._compare_versions(version, upper, range_type, ecosystem) < 0:
                        return True
                lower = None

        if lower is not None:
            return cls._compare_versions(version, lower, range_type, ecosystem) >= 0
        return False

    @classmethod
    def _vulnerability_affects(
        cls, vulnerability: Dict[str, Any], name: str, version: str, ecosystem: str
    ) -> bool:
        has_supported_range = False
        for affected in vulnerability.get("affected", []):
            package = affected.get("package") or {}
            if package.get("ecosystem") and str(package["ecosystem"]).lower() != ecosystem.lower():
                continue
            if package.get("name"):
                affected_name = str(package["name"]).lower().replace("_", "-")
                if affected_name != name.lower().replace("_", "-"):
                    continue
            for version_range in affected.get("ranges", []):
                if str(version_range.get("type", "")).upper() in {"SEMVER", "ECOSYSTEM"}:
                    has_supported_range = True
                    if cls._range_affects(version, version_range, ecosystem):
                        return True
            if version in affected.get("versions", []):
                return True
        # OSV querybatch has already matched this exact package/version; preserve
        # results when an advisory only provides a non-version range such as GIT.
        return not has_supported_range

    @staticmethod
    def _read_requirements(path: str) -> List[Tuple[str, str, str, int]]:
        dependencies = []
        with open(path, "r", encoding="utf-8", errors="ignore") as stream:
            for line_number, line in enumerate(stream, start=1):
                match = PINNED_REQUIREMENT.match(line)
                if match:
                    dependencies.append(
                        (match.group(1).lower().replace("_", "-"), match.group(2), "PyPI", line_number)
                    )
        return dependencies

    @staticmethod
    def _read_npm_manifest(path: str) -> List[Tuple[str, str, str, int]]:
        with open(path, "r", encoding="utf-8", errors="ignore") as stream:
            manifest = json.load(stream)
        if not isinstance(manifest, dict):
            return []
        dependencies = []
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            section_data = manifest.get(section)
            if not isinstance(section_data, dict):
                continue
            for name, version in section_data.items():
                if isinstance(version, str) and EXACT_VERSION.fullmatch(version):
                    dependencies.append((name, version, "npm", 1))

        # package-lock v2/v3 provides exact versions for transitive packages too.
        if isinstance(manifest.get("packages"), dict):
            for package_path, package in manifest["packages"].items():
                if not package_path:
                    continue
                name = package.get("name") if isinstance(package, dict) else None
                version = package.get("version") if isinstance(package, dict) else None
                if not name and package_path.startswith("node_modules/"):
                    name = package_path[len("node_modules/"):]
                if name and isinstance(version, str) and EXACT_VERSION.fullmatch(version):
                    dependencies.append((name, version, "npm", 1))

        return dependencies

    def scan(self, workspace_path: str) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []

        dependencies: List[Tuple[str, str, str, str, int]] = []
        manifest_names = {"requirements.txt", "package.json", "package-lock.json"}
        for root, _, files in os.walk(workspace_path):
            for filename in files:
                if filename.lower() not in manifest_names:
                    continue
                path = os.path.join(root, filename)
                relative_path = os.path.relpath(path, workspace_path)
                try:
                    if filename.lower() == "requirements.txt":
                        parsed = self._read_requirements(path)
                    else:
                        parsed = self._read_npm_manifest(path)
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
                dependencies.extend(
                    (name, version, ecosystem, relative_path, line_number)
                    for name, version, ecosystem, line_number in parsed
                )

        if not dependencies:
            return []

        query = {
            "queries": [
                {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                for name, version, ecosystem, _, _ in dependencies
            ]
        }
        try:
            response = requests.post(self.api_url, json=query, timeout=self.timeout)
            response.raise_for_status()
            results = response.json().get("results", [])
        except (requests.RequestException, ValueError, AttributeError) as error:
            raise RuntimeError(f"OSV.dev dependency query failed: {error}") from error

        if len(results) != len(dependencies):
            raise RuntimeError(
                f"OSV.dev returned {len(results)} results for {len(dependencies)} dependencies."
            )

        findings = []
        for dependency, result in zip(dependencies, results):
            name, version, ecosystem, relative_path, line_number = dependency
            for vulnerability in result.get("vulns", []):
                if not self._vulnerability_affects(vulnerability, name, version, ecosystem):
                    continue
                severity = "high" if vulnerability.get("severity") else "medium"
                vuln_id = vulnerability.get("id", "OSV-UNKNOWN")
                summary = vulnerability.get("summary") or f"Known vulnerability in {name} {version}"
                findings.append(
                    self.create_finding(
                        rule_id=f"SCA-OSV-{vuln_id}",
                        file_path=relative_path,
                        line_number=line_number,
                        severity=severity,
                        description=f"{summary} ({vuln_id})",
                        match_content=f"{name}=={version}",
                        remediation=f"Upgrade {name} to a version not affected by {vuln_id}.",
                    )
                )
        return findings
