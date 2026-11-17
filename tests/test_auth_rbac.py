"""Integration & Unit tests for Authentication & RBAC."""

import pytest
from app.auth import (
    Role,
    decode_jwt_token,
    generate_jwt_token,
    hash_password,
    verify_password,
)


def test_password_hashing_and_verification():
    """Verify bcrypt password hashing and verification."""
    password = "SuperSecurePassword123!"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_generation_and_validation(app):
    """Verify JWT generation, claims, and decoding."""
    with app.app_context():
        token = generate_jwt_token(
            user_id="user_123",
            username="analyst_bob",
            role=Role.ANALYST,
            secret_key=app.config["JWT_SECRET_KEY"],
            expires_in_hours=2,
        )
        assert token is not None

        decoded = decode_jwt_token(token, secret_key=app.config["JWT_SECRET_KEY"])
        assert decoded["sub"] == "user_123"
        assert decoded["username"] == "analyst_bob"
        assert decoded["role"] == Role.ANALYST
        assert decoded["iss"] == "secret-leak-guard-v2"


def test_api_register_user_success(client):
    """Test user registration endpoint."""
    response = client.post("/api/v1/auth/register", json={
        "username": "new_analyst",
        "password": "Password123!",
        "role": "analyst",
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data["status"] == "success"
    assert data["user"]["username"] == "new_analyst"
    assert data["user"]["role"] == "analyst"


def test_api_register_duplicate_username_fails(client):
    """Registering an existing username returns 409 Conflict."""
    response = client.post("/api/v1/auth/register", json={
        "username": "admin_user",  # seeded in conftest
        "password": "Password123!",
        "role": "admin",
    })
    assert response.status_code == 409


def test_api_login_success(client):
    """Test login with valid credentials."""
    response = client.post("/api/v1/auth/login", json={
        "username": "analyst_user",
        "password": "AnalystP@ssword123",
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "access_token" in data
    assert data["user"]["role"] == Role.ANALYST


def test_api_login_invalid_password(client):
    """Test login with invalid password returns 401."""
    response = client.post("/api/v1/auth/login", json={
        "username": "analyst_user",
        "password": "IncorrectPassword!",
    })
    assert response.status_code == 401


def test_rbac_scan_submission_permissions(client, admin_headers, analyst_headers, viewer_headers, tmp_path):
    """Verify RBAC: Admin and Analyst can submit scans; Viewer receives 403 Forbidden."""
    scan_folder = tmp_path / "valid_project"
    scan_folder.mkdir()
    (scan_folder / "app.py").write_text("print('test')")

    payload = {
        "ingestion_mode": "local",
        "project_id": "test-rbac-proj",
        "target": str(scan_folder),
    }

    # 1. Unauthenticated -> 401
    resp_unauth = client.post("/api/v1/scans", json=payload)
    assert resp_unauth.status_code == 401

    # 2. Viewer role -> 403 Forbidden
    resp_viewer = client.post("/api/v1/scans", json=payload, headers=viewer_headers)
    assert resp_viewer.status_code == 403
    assert "not authorized" in resp_viewer.get_json()["message"]

    # 3. Analyst role -> 202 Accepted
    resp_analyst = client.post("/api/v1/scans", json=payload, headers=analyst_headers)
    assert resp_analyst.status_code == 202

    # 4. Admin role -> 202 Accepted
    resp_admin = client.post("/api/v1/scans", json=payload, headers=admin_headers)
    assert resp_admin.status_code == 202


def test_rbac_viewer_can_view_status_and_results(client, viewer_headers, db):
    """Viewer can query status and results of scans."""
    job_id = "job-viewer-accessible"
    db.save_scan_report({
        "job_id": job_id,
        "project_id": "proj-1",
        "status": "COMPLETED",
        "findings": [],
        "scores": {"final_score": 0},
        "grade": "A+",
    })

    # Viewer queries status
    resp_status = client.get(f"/api/v1/scans/{job_id}/status", headers=viewer_headers)
    assert resp_status.status_code == 200

    # Viewer queries results
    resp_results = client.get(f"/api/v1/scans/{job_id}/results", headers=viewer_headers)
    assert resp_results.status_code == 200
    assert resp_results.get_json()["grade"] == "A+"
