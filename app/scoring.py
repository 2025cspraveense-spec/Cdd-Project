"""Weighted Risk Scoring & Grading System for Secret Leak Guard v2.0."""

import hashlib
import os
from typing import Any, Dict, List, Tuple


# Severity Weights defined by specification
SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
    "info": 0,
}


def calculate_finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Calculates a deterministic SHA-256 fingerprint for a finding.
    
    Deduplication is based on:
    - rule_id
    - normalized file_path (forward slashes, lowercase)
    - line_number
    - raw_secret or match_content
    """
    rule_id = str(finding.get("rule_id", "")).strip()
    raw_path = str(finding.get("file_path", "")).strip()
    # Normalize path separators for cross-platform consistency
    normalized_path = os.path.normpath(raw_path).replace("\\", "/").lower()
    line_number = str(finding.get("line_number", 0)).strip()
    
    # Use raw_secret or match_content or description
    evidence = str(
        finding.get("raw_secret")
        or finding.get("match_content")
        or finding.get("description")
        or ""
    ).strip()

    fingerprint_seed = f"{rule_id}:{normalized_path}:{line_number}:{evidence}"
    return hashlib.sha256(fingerprint_seed.encode("utf-8")).hexdigest()


def assign_grade(score: int) -> str:
    """Assigns security grade based on the bounded risk score (0-100).
    
    Specification:
        A+ : 0
        A  : 1–10
        B  : 11–25
        C  : 26–50
        D  : 51–75
        F  : 76–100
    """
    if score <= 0:
        return "A+"
    elif 1 <= score <= 10:
        return "A"
    elif 11 <= score <= 25:
        return "B"
    elif 26 <= score <= 50:
        return "C"
    elif 51 <= score <= 75:
        return "D"
    else:
        return "F"


def deduplicate_findings(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Deduplicates a list of findings by deterministic SHA-256 fingerprint.
    
    Returns:
        Tuple of (deduplicated_findings, duplicate_count)
    """
    seen_fingerprints = set()
    deduped = []
    duplicate_count = 0

    for finding in findings:
        fp = finding.get("fingerprint") or calculate_finding_fingerprint(finding)
        finding_with_fp = dict(finding)
        finding_with_fp["fingerprint"] = fp

        if fp in seen_fingerprints:
            duplicate_count += 1
            continue

        seen_fingerprints.add(fp)
        deduped.append(finding_with_fp)

    return deduped, duplicate_count


def calculate_risk_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates the weighted risk score and assigns a grade.
    
    Process:
    1. Deduplicate findings deterministically by SHA-256 fingerprint.
    2. Sum raw risk score using severity weights (Critical=25, High=10, Medium=3, Low=1).
    3. Cap final score at bounded range [0, 100] via min(100, raw_score).
    4. Assign security grade based on bounded score.
    """
    deduped_findings, duplicate_count = deduplicate_findings(findings)

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    raw_score = 0
    for finding in deduped_findings:
        sev = str(finding.get("severity", "info")).lower()
        if sev not in severity_counts:
            sev = "info"
        severity_counts[sev] += 1
        raw_score += SEVERITY_WEIGHTS.get(sev, 0)

    # Cap score at bounded range of 0 to 100
    final_score = min(100, max(0, raw_score))
    grade = assign_grade(final_score)

    return {
        "raw_score": raw_score,
        "final_score": final_score,
        "grade": grade,
        "total_findings_evaluated": len(findings),
        "unique_findings_count": len(deduped_findings),
        "duplicate_findings_count": duplicate_count,
        "severity_counts": severity_counts,
        "deduplicated_findings": deduped_findings,
    }
