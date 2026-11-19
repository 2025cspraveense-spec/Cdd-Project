"""Unit tests for MongoDB 7.0 Persistence Layer & Indexing."""

import datetime
import pytest
from app.db import DatabaseClient


@pytest.fixture
def mock_db():
    client = DatabaseClient(use_mock=True, db_name="test_guard_db")
    yield client
    client.close()


def test_ensure_indexes_creation(mock_db):
    """Verify single, compound, and TTL indexes are created across all collections."""
    indexes = mock_db.ensure_indexes()

    assert "scan_reports" in indexes
    assert "finding_fingerprints" in indexes
    assert "project_configs" in indexes
    assert "historical_metrics" in indexes
    assert "users" in indexes

    # Verify TTL and compound indexes in scan_reports
    col_indexes = mock_db.db["scan_reports"].index_information()
    assert "idx_scan_job_id_unique" in col_indexes
    assert "idx_scan_reports_ttl" in col_indexes
    assert "idx_scan_project_created_compound" in col_indexes


def test_save_scan_report_enforces_redaction(mock_db):
    """Database persistence must automatically redact raw secrets before storage."""
    raw_secret_value = "".join(["AK", "IA", "1234567890ABCDEF"])
    job_id = "job-db-test-01"

    report_payload = {
        "job_id": job_id,
        "project_id": "proj-alpha",
        "status": "COMPLETED",
        "findings": [
            {
                "rule_id": "SEC-AWS-001",
                "raw_secret": raw_secret_value,
                "description": f"Found key {raw_secret_value}",
            }
        ],
    }

    mock_db.save_scan_report(report_payload)
    retrieved = mock_db.get_scan_report(job_id)

    assert retrieved is not None
    assert retrieved["job_id"] == job_id
    # Raw secret must NOT be in the DB document
    finding = retrieved["findings"][0]
    assert finding["raw_secret"] == "AKIA****************"
    assert raw_secret_value not in finding["description"]
    assert "expires_at" in retrieved


def test_finding_fingerprints_tracking(mock_db):
    """Fingerprints track occurrences and first/last seen timestamps."""
    project_id = "proj-beta"
    dummy_secret = "".join(["AK", "IA", "1234567890ABCDEF"])
    findings = [
        {
            "fingerprint": "fp_sha256_hash_12345",
            "rule_id": "SEC-001",
            "severity": "high",
            "file_path": "src/auth.py",
            "raw_secret": dummy_secret,
        }
    ]

    # First occurrence
    mock_db.record_finding_fingerprints(project_id, findings)
    fp_doc = mock_db.db["finding_fingerprints"].find_one({"fingerprint": "fp_sha256_hash_12345"})

    assert fp_doc is not None
    assert fp_doc["occurrence_count"] == 1
    assert fp_doc["status"] == "open"
    # Ensure secret is redacted in fingerprint collection
    assert dummy_secret not in str(fp_doc)

    # Second occurrence increments count
    mock_db.record_finding_fingerprints(project_id, findings)
    fp_doc_updated = mock_db.db["finding_fingerprints"].find_one({"fingerprint": "fp_sha256_hash_12345"})
    assert fp_doc_updated["occurrence_count"] == 2


def test_historical_metrics_persistence(mock_db):
    """Historical metrics are persisted and queryable."""
    project_id = "proj-gamma"
    mock_db.save_historical_metrics({
        "project_id": project_id,
        "job_id": "job-hist-1",
        "raw_score": 50,
        "final_score": 50,
        "grade": "C",
        "severity_counts": {"critical": 2},
    })

    metrics = mock_db.get_historical_metrics(project_id)
    assert len(metrics) == 1
    assert metrics[0]["final_score"] == 50
    assert metrics[0]["grade"] == "C"


def test_dynamic_mongodb_credentials_are_passed_as_auth_options():
    client = DatabaseClient(
        use_mock=True,
        mongo_username="leased-user",
        mongo_password="leased-password",
        mongo_auth_source="secret_leak_guard_v2",
    )

    assert client._auth_options() == {
        "username": "leased-user",
        "password": "leased-password",
        "authSource": "secret_leak_guard_v2",
    }
