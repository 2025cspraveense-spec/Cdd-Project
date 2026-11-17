"""REST API Routes & Controllers for Secret Leak Guard v2.0."""

import os
import tempfile
import uuid
from typing import Any, Dict
from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.utils import secure_filename

from app.auth import (
    Role,
    generate_jwt_token,
    hash_password,
    require_auth,
    require_role,
    validate_login_payload,
    validate_register_payload,
    verify_password,
)
from app.redactor import redact_dict
from app.scanner_orchestrator import ScanStatus

api_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


# ---------------------------------------------------------------------------
# Health & Status Endpoints
# ---------------------------------------------------------------------------

@api_bp.route("/health", methods=["GET"])
def health_check():
    """System health check endpoint providing DB and Vault status."""
    db = current_app.extensions["db"]
    vault = current_app.extensions["vault"]

    db_status = "connected"
    if db.is_mock:
        db_status = "mock_in_memory"

    vault_info = vault.health_check()

    return jsonify({
        "status": "healthy",
        "service": current_app.config.get("APP_NAME", "Secret Leak Guard"),
        "version": current_app.config.get("APP_VERSION", "2.0.0"),
        "database": {
            "status": db_status,
            "type": "mongomock" if db.is_mock else "mongodb_7.0",
        },
        "vault": vault_info,
    }), 200


# ---------------------------------------------------------------------------
# Authentication & User Management
# ---------------------------------------------------------------------------

@api_bp.route("/auth/register", methods=["POST"])
def register():
    """Register a new user account (admin/analyst/viewer)."""
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"status": "error", "error": "Invalid JSON body"}), 400

    try:
        validated = validate_register_payload(payload)
    except ValueError as e:
        return jsonify({"status": "error", "error": "Validation error", "message": str(e)}), 400

    db = current_app.extensions["db"]
    existing_user = db.get_user_by_username(validated["username"])
    if existing_user:
        return jsonify({"status": "error", "error": "Username already exists"}), 409

    # Hash password with bcrypt
    password_hash = hash_password(validated["password"])

    user_doc = {
        "username": validated["username"],
        "password_hash": password_hash,
        "role": validated["role"],
    }
    db.create_user(user_doc)

    return jsonify({
        "status": "success",
        "message": f"User '{validated['username']}' registered successfully.",
        "user": {
            "username": validated["username"],
            "role": validated["role"],
        },
    }), 201


@api_bp.route("/auth/login", methods=["POST"])
def login():
    """Authenticate with username & password, returns JWT token."""
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"status": "error", "error": "Invalid JSON body"}), 400

    try:
        creds = validate_login_payload(payload)
    except ValueError as e:
        return jsonify({"status": "error", "error": "Validation error", "message": str(e)}), 400

    db = current_app.extensions["db"]
    user = db.get_user_by_username(creds["username"])
    if not user or not verify_password(creds["password"], user.get("password_hash", "")):
        return jsonify({"status": "error", "error": "Invalid credentials", "message": "Incorrect username or password."}), 401

    token = generate_jwt_token(
        user_id=str(user.get("_id", user["username"])),
        username=user["username"],
        role=user.get("role", Role.VIEWER),
        expires_in_hours=current_app.config.get("JWT_EXPIRATION_HOURS", 24),
    )

    return jsonify({
        "status": "success",
        "token_type": "Bearer",
        "access_token": token,
        "user": {
            "username": user["username"],
            "role": user.get("role", Role.VIEWER),
        },
    }), 200


@api_bp.route("/auth/me", methods=["GET"])
@require_auth
def get_current_user():
    """Returns details of the currently authenticated user."""
    return jsonify({
        "status": "success",
        "user": g.current_user,
    }), 200


# ---------------------------------------------------------------------------
# Scan Management Endpoints
# ---------------------------------------------------------------------------

@api_bp.route("/scans", methods=["POST"])
@require_role([Role.ADMIN, Role.ANALYST])
def submit_scan():
    """Submit a project for security scanning via one of 4 ingestion modes:
    - archive: Upload .zip, .tar.gz, .tgz
    - local: Existing local directory path
    - git: HTTPS Git repository URL
    - dockerfile: Raw Dockerfile content or uploaded file
    """
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    ingestion_mode = None
    project_id = "default-project"
    target_data = None
    selected_engines = None

    # Handle multipart/form-data (file upload)
    if request.content_type and "multipart/form-data" in request.content_type:
        ingestion_mode = request.form.get("ingestion_mode", "archive").lower()
        project_id = request.form.get("project_id", project_id).strip()
        engines_param = request.form.get("engines")
        if engines_param:
            selected_engines = [e.strip() for e in engines_param.split(",") if e.strip()]

        if ingestion_mode == "archive":
            if "file" not in request.files:
                return jsonify({"status": "error", "error": "Missing file field for archive upload."}), 400
            file_obj = request.files["file"]
            if not file_obj.filename:
                return jsonify({"status": "error", "error": "No file selected."}), 400

            filename = secure_filename(file_obj.filename)
            allowed_exts = current_app.config.get("ALLOWED_ARCHIVE_EXTENSIONS", (".zip", ".tar.gz", ".tgz", ".tar"))
            if not any(filename.lower().endswith(ext) for ext in allowed_exts):
                return jsonify({
                    "status": "error",
                    "error": f"Unsupported archive format. Allowed: {allowed_exts}"
                }), 400

            # Save uploaded archive to temporary storage
            temp_dir = tempfile.gettempdir()
            saved_archive_path = os.path.join(temp_dir, f"{job_id}_{filename}")
            file_obj.save(saved_archive_path)
            target_data = saved_archive_path

        elif ingestion_mode == "dockerfile":
            if "file" in request.files and request.files["file"].filename:
                target_data = request.files["file"].read().decode("utf-8", errors="ignore")
            else:
                target_data = request.form.get("dockerfile_content")
            if not target_data:
                return jsonify({"status": "error", "error": "Missing Dockerfile content or file."}), 400

        elif ingestion_mode in ("git", "local"):
            target_data = request.form.get("target")
            if not target_data:
                return jsonify({"status": "error", "error": f"Missing 'target' parameter for {ingestion_mode}."}), 400

    # Handle application/json
    else:
        json_data = request.get_json(silent=True) or {}
        ingestion_mode = str(json_data.get("ingestion_mode", "")).lower()
        project_id = str(json_data.get("project_id", project_id)).strip()
        target_data = json_data.get("target") or json_data.get("dockerfile_content")
        selected_engines = json_data.get("engines")

    # Validate ingestion mode
    valid_modes = {"archive", "local", "git", "dockerfile"}
    if ingestion_mode not in valid_modes:
        return jsonify({
            "status": "error",
            "error": f"Invalid ingestion_mode '{ingestion_mode}'. Supported modes: {list(valid_modes)}"
        }), 400

    if not target_data:
        return jsonify({"status": "error", "error": "Target data/content is required for scanning."}), 400

    orchestrator = current_app.extensions["orchestrator"]

    # Submit job for asynchronous execution
    initial_report = orchestrator.submit_scan(
        job_id=job_id,
        project_id=project_id,
        ingestion_mode=ingestion_mode,
        target=target_data,
        user=g.current_user,
        selected_engines=selected_engines,
    )

    response_data = {
        "status": "accepted",
        "job_id": job_id,
        "project_id": project_id,
        "scan_status": ScanStatus.PENDING,
        "message": "Scan job successfully submitted and running asynchronously.",
        "links": {
            "status": f"/api/v1/scans/{job_id}/status",
            "results": f"/api/v1/scans/{job_id}/results",
        },
    }

    # Always enforce redaction on outgoing JSON response
    return jsonify(redact_dict(response_data)), 202


@api_bp.route("/scans/<job_id>/status", methods=["GET"])
@require_auth
def get_scan_status(job_id: str):
    """Retrieve the real-time progress and status of a scan job."""
    db = current_app.extensions["db"]
    report = db.get_scan_report(job_id)

    if not report:
        return jsonify({"status": "error", "error": "Scan job not found", "job_id": job_id}), 404

    status_data = {
        "job_id": report["job_id"],
        "project_id": report.get("project_id"),
        "status": report.get("status"),
        "progress": report.get("progress"),
        "created_at": report.get("created_at"),
        "updated_at": report.get("updated_at"),
        "error_message": report.get("error_message"),
    }

    return jsonify(redact_dict(status_data)), 200


@api_bp.route("/scans/<job_id>/results", methods=["GET"])
@require_auth
def get_scan_results(job_id: str):
    """Retrieve full scan results, risk score, grade, and redacted findings."""
    db = current_app.extensions["db"]
    report = db.get_scan_report(job_id)

    if not report:
        return jsonify({"status": "error", "error": "Scan job not found", "job_id": job_id}), 404

    # If scan is not yet complete, indicate current state
    if report.get("status") != ScanStatus.COMPLETED:
        return jsonify({
            "status": "in_progress",
            "job_id": job_id,
            "scan_status": report.get("status"),
            "progress": report.get("progress"),
            "message": "Scan results will be available once the scan job reaches COMPLETED state.",
        }), 200

    results_data = {
        "status": "success",
        "job_id": report["job_id"],
        "project_id": report.get("project_id"),
        "scan_status": report.get("status"),
        "grade": report.get("grade"),
        "scores": report.get("scores"),
        "findings": report.get("findings", []),
        "created_at": report.get("created_at"),
        "updated_at": report.get("updated_at"),
    }

    # Strict redaction across API boundary
    return jsonify(redact_dict(results_data)), 200


@api_bp.route("/scans", methods=["GET"])
@require_auth
def list_scans():
    """List scan jobs with optional project and status filters."""
    db = current_app.extensions["db"]
    project_id = request.args.get("project_id")
    status = request.args.get("status")
    limit = min(int(request.args.get("limit", 20)), 100)
    skip = int(request.args.get("skip", 0))

    scans = db.list_scan_reports(project_id=project_id, status=status, limit=limit, skip=skip)
    
    # Strip heavy findings list for overview list
    summary_list = []
    for s in scans:
        summary_list.append({
            "job_id": s.get("job_id"),
            "project_id": s.get("project_id"),
            "status": s.get("status"),
            "grade": s.get("grade"),
            "scores": s.get("scores"),
            "created_at": s.get("created_at"),
        })

    return jsonify(redact_dict({"status": "success", "count": len(summary_list), "scans": summary_list})), 200


# ---------------------------------------------------------------------------
# Metrics & Vault Helper Endpoints
# ---------------------------------------------------------------------------

@api_bp.route("/projects/<project_id>/metrics", methods=["GET"])
@require_auth
def get_project_metrics(project_id: str):
    """Retrieve security metrics and historical trends for a project."""
    db = current_app.extensions["db"]
    limit = min(int(request.args.get("limit", 30)), 100)
    metrics = db.get_historical_metrics(project_id, limit=limit)

    return jsonify(redact_dict({
        "status": "success",
        "project_id": project_id,
        "metrics_count": len(metrics),
        "history": metrics,
    })), 200


@api_bp.route("/vault/rotate-secret", methods=["POST"])
@require_role([Role.ADMIN])
def rotate_vault_secret():
    """Helper endpoint to trigger secret rotation in HashiCorp Vault."""
    payload = request.get_json(silent=True) or {}
    key = payload.get("key")
    new_value = payload.get("new_value")

    if not key or not new_value:
        return jsonify({"status": "error", "error": "Both 'key' and 'new_value' are required."}), 400

    vault = current_app.extensions["vault"]
    result = vault.rotate_secret(key=key, new_value=new_value)

    return jsonify(redact_dict({
        "status": "success",
        "message": f"Secret '{key}' rotation executed.",
        "result": result,
    })), 200
