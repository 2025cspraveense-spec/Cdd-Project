"""Unit tests for Weighted Risk Scoring & Grading System."""

import pytest
from app.redactor import redact_dict
from app.scoring import (
    SEVERITY_WEIGHTS,
    assign_grade,
    calculate_finding_fingerprint,
    calculate_risk_score,
    deduplicate_findings,
)


def test_severity_weights_values():
    """Verify that severity weights match exact specification."""
    assert SEVERITY_WEIGHTS["critical"] == 25
    assert SEVERITY_WEIGHTS["high"] == 10
    assert SEVERITY_WEIGHTS["medium"] == 3
    assert SEVERITY_WEIGHTS["low"] == 1
    assert SEVERITY_WEIGHTS["info"] == 0


@pytest.mark.parametrize("score,expected_grade", [
    (0, "A+"),
    (-5, "A+"),
    (1, "A"),
    (5, "A"),
    (10, "A"),
    (11, "B"),
    (20, "B"),
    (25, "B"),
    (26, "C"),
    (40, "C"),
    (50, "C"),
    (51, "D"),
    (65, "D"),
    (75, "D"),
    (76, "F"),
    (90, "F"),
    (100, "F"),
    (150, "F"),
])
def test_grade_boundaries(score, expected_grade):
    """Verify exact grade boundaries for A+, A, B, C, D, and F."""
    assert assign_grade(score) == expected_grade


def test_twenty_findings_one_hundred_score_grade_f():
    """Requirement: 20 findings resulting in 100/100 = Grade F."""
    # Generate 20 distinct High-severity findings (each High = 10 pts)
    # 20 * 10 = 200 raw score -> bounded to 100 -> Grade F
    findings = [
        {
            "rule_id": f"SEC-RULE-{i:03d}",
            "file_path": f"src/module_{i}.py",
            "line_number": i * 5,
            "severity": "high",
            "raw_secret": f"SECRET_KEY_SAMPLE_{i:03d}",
            "description": f"High severity leak #{i}",
        }
        for i in range(1, 21)
    ]

    report = calculate_risk_score(findings)

    assert report["total_findings_evaluated"] == 20
    assert report["unique_findings_count"] == 20
    assert report["raw_score"] == 200
    assert report["final_score"] == 100
    assert report["grade"] == "F"
    assert report["severity_counts"]["high"] == 20


def test_mixed_severity_score_and_grading():
    """Verify scoring calculation across mixed severities."""
    findings = [
        {"rule_id": "R1", "file_path": "a.py", "line_number": 1, "severity": "critical", "raw_secret": "k1"}, # 25
        {"rule_id": "R2", "file_path": "b.py", "line_number": 2, "severity": "high", "raw_secret": "k2"},     # 10
        {"rule_id": "R3", "file_path": "c.py", "line_number": 3, "severity": "medium", "raw_secret": "k3"},   # 3
        {"rule_id": "R4", "file_path": "d.py", "line_number": 4, "severity": "low", "raw_secret": "k4"},      # 1
    ]
    # Total raw = 25 + 10 + 3 + 1 = 39 -> Grade C (26-50)
    report = calculate_risk_score(findings)
    assert report["raw_score"] == 39
    assert report["final_score"] == 39
    assert report["grade"] == "C"


def test_zero_findings_perfect_score():
    """Zero findings yields raw_score 0, final_score 0, Grade A+."""
    report = calculate_risk_score([])
    assert report["raw_score"] == 0
    assert report["final_score"] == 0
    assert report["grade"] == "A+"
    assert report["unique_findings_count"] == 0


def test_deterministic_fingerprint_deduplication():
    """Findings with the same rule, path, line, and evidence must be deduplicated."""
    duplicate_item = {
        "rule_id": "SEC-AWS-001",
        "file_path": "config/settings.py",
        "line_number": 42,
        "severity": "critical",
        "raw_secret": "".join(["AK", "IA", "IOSFODNN7EXAMPLE"]),
        "description": "AWS Key leaked",
    }

    # Pass 5 identical duplicates
    findings = [dict(duplicate_item) for _ in range(5)]
    deduped, dup_count = deduplicate_findings(findings)

    assert len(deduped) == 1
    assert dup_count == 4

    # Scoring should only score the 1 unique finding: 1 critical = 25 -> Grade B
    report = calculate_risk_score(findings)
    assert report["unique_findings_count"] == 1
    assert report["duplicate_findings_count"] == 4
    assert report["raw_score"] == 25
    assert report["final_score"] == 25
    assert report["grade"] == "B"


def test_fingerprint_cross_platform_normalization():
    """Ensure Windows backslash vs UNIX forward slash normalize to the same fingerprint."""
    f1 = {
        "rule_id": "R1", "file_path": "app\\config\\db.py", "line_number": 10,
        "category": "Secrets", "title": "Credential exposed", "raw_secret": "secret",
    }
    f2 = {
        "rule_id": "R2", "file_path": "app/config/db.py", "line_number": 10,
        "category": "Secrets", "title": "Credential exposed", "raw_secret": "different",
    }

    fp1 = calculate_finding_fingerprint(f1)
    fp2 = calculate_finding_fingerprint(f2)
    assert fp1 == fp2


def test_fingerprint_uses_category_and_title_not_evidence():
    finding = {
        "file_path": "src/auth.py",
        "line_number": 17,
        "category": "Secrets",
        "title": "Credential exposed",
        "raw_secret": "sensitive-value",
        "match_content": "line with sensitive-value",
    }
    changed_evidence = {**finding, "raw_secret": "rotated-value", "match_content": "changed"}
    changed_title = {**finding, "title": "Different finding"}

    assert calculate_finding_fingerprint(finding) == calculate_finding_fingerprint(changed_evidence)
    assert calculate_finding_fingerprint(finding) != calculate_finding_fingerprint(changed_title)


def test_fingerprint_stays_stable_when_title_is_redacted():
    finding = {
        "file_path": "app.py",
        "line_number": 4,
        "category": "Code Quality & SAST",
        "title": "Possible hardcoded password: password='super-secret-value-123'",
    }
    persisted_finding = redact_dict(finding)

    assert persisted_finding["title"] != finding["title"]
    assert calculate_finding_fingerprint(finding) == calculate_finding_fingerprint(persisted_finding)
