"""Base Engine Interface for Secret Leak Guard v2.0."""

import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseEngine(ABC):
    """Abstract base class for static analysis and scanning engines."""

    name: str = "BaseEngine"
    category: str = "General"
    description: str = "Base static analysis engine interface."

    @abstractmethod
    def scan(self, workspace_path: str) -> List[Dict[str, Any]]:
        """Scans the workspace directory and returns a list of security findings.
        
        Args:
            workspace_path: Canonical absolute path to the unpacked workspace.
            
        Returns:
            List of standardized finding dictionaries.
        """
        pass

    def create_finding(
        self,
        rule_id: str,
        file_path: str,
        line_number: int,
        severity: str,
        description: str,
        raw_secret: Optional[str] = None,
        match_content: Optional[str] = None,
        remediation: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates a standardized finding dictionary."""
        return {
            "engine_name": self.name,
            "rule_id": rule_id,
            "category": category or self.category,
            "severity": severity.lower(),
            "file_path": file_path.replace("\\", "/"),
            "line_number": int(line_number),
            "description": description,
            "raw_secret": raw_secret,
            "match_content": match_content,
            "remediation": remediation or "Review and sanitize the reported finding.",
        }

    def collect_scannable_files(
        self,
        workspace_path: str,
        extensions: Optional[tuple] = None,
        max_file_size: int = 5 * 1024 * 1024
    ) -> List[str]:
        """Walks the workspace and returns list of scannable file paths."""
        scannable = []
        skip_dirs = {".git", ".svn", "__pycache__", "node_modules", ".venv", "venv", ".idea", ".vscode"}

        for root, dirs, files in os.walk(workspace_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for file in files:
                if extensions and not file.lower().endswith(extensions):
                    continue
                full_path = os.path.join(root, file)
                try:
                    if os.path.isfile(full_path) and os.path.getsize(full_path) <= max_file_size:
                        scannable.append(full_path)
                except OSError:
                    continue

        return scannable
