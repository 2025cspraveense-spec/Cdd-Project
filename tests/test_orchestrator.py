"""Unit tests for Scanner Orchestrator and Engine Concurrency."""

import os
import time
import pytest

from app.db import DatabaseClient
from app.scanner_orchestrator import ScanStatus, ScannerOrchestrator


@pytest.fixture
def orchestrator_fixture(tmp_path):
    db = DatabaseClient(use_mock=True, db_name="test_orch_db")
    workspaces = tmp_path / "workspaces"
    workspaces.mkdir()
    allowed_bases = [str(tmp_path)]

    orchestrator = ScannerOrchestrator(
        db_client=db,
        max_workers=2,
        workspace_base_dir=str(workspaces),
        allowed_local_paths=allowed_bases,
    )
    yield orchestrator, db, workspaces
    orchestrator.shutdown()
    db.close()


def test_orchestrator_parallel_scan_full_lifecycle(orchestrator_fixture, tmp_path):
    """Test full parallel scan execution across all 4 engines and state progression."""
    orchestrator, db, workspaces = orchestrator_fixture

    # Create a realistic test project containing security issues across all 4 engines
    proj_dir = tmp_path / "vulnerable_project"
    proj_dir.mkdir()

    mock_aws_key = "".join(["AK", "IA", "1234567890ABCDEF"])
    # Secret issue
    (proj_dir / "settings.py").write_text(f"AWS_KEY = '{mock_aws_key}'\n")

    # SAST issue
    (proj_dir / "runner.py").write_text("import os\nos.system('echo ' + user_input)\n")

    # SCA issue
    (proj_dir / "requirements.txt").write_text("pyyaml==5.1\n")

    # Dockerfile issue
    (proj_dir / "Dockerfile").write_text("FROM python:latest\nEXPOSE 22\n")

    job_id = "job-orch-full-01"
    initial_report = orchestrator.submit_scan(
        job_id=job_id,
        project_id="test-full-pipeline",
        ingestion_mode="local",
        target=str(proj_dir),
        user={"username": "test_analyst"},
    )

    assert initial_report["status"] == ScanStatus.PENDING

    # Wait for background job to reach completion (or timeout)
    max_wait = 10
    start = time.time()
    final_report = None

    while time.time() - start < max_wait:
        final_report = db.get_scan_report(job_id)
        if final_report and final_report.get("status") in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            break
        time.sleep(0.1)

    assert final_report is not None
    assert final_report["status"] == ScanStatus.COMPLETED
    assert final_report["progress"]["percentage"] == 100

    # Verify score and grade
    scores = final_report["scores"]
    assert scores["unique_findings"] >= 4
    assert final_report["grade"] in ("B", "C", "D", "F")

    # Verify that raw secrets in findings are REDACTED
    findings = final_report["findings"]
    secret_findings = [f for f in findings if f.get("engine_name") == "SecretEngine"]
    assert len(secret_findings) > 0
    for sf in secret_findings:
        assert sf["raw_secret"] == "AKIA****************"
        assert mock_aws_key not in sf["match_content"]


def test_orchestrator_failure_handling_and_cleanup(orchestrator_fixture, tmp_path):
    """Test that invalid ingestion paths transition state to FAILED and error is recorded."""
    orchestrator, db, workspaces = orchestrator_fixture

    job_id = "job-orch-fail-01"
    orchestrator.submit_scan(
        job_id=job_id,
        project_id="test-fail",
        ingestion_mode="local",
        target=str(tmp_path / "non_existent_folder"),
        user={"username": "test_user"},
    )

    # Wait for completion
    max_wait = 5
    start = time.time()
    final_report = None

    while time.time() - start < max_wait:
        final_report = db.get_scan_report(job_id)
        if final_report and final_report.get("status") == ScanStatus.FAILED:
            break
        time.sleep(0.1)

    assert final_report is not None
    assert final_report["status"] == ScanStatus.FAILED
    assert final_report["error_message"] is not None
