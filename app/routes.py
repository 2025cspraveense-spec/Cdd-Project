"""REST API Routes & Controllers for Secret Leak Guard v2.0."""

import html
import io
import json
import os
import tempfile
import uuid
from typing import Any, Dict
from xml.sax.saxutils import escape
from flask import Blueprint, current_app, g, jsonify, request, send_file
from werkzeug.utils import secure_filename

from app import limiter
from app.ai_assistant import (
    AIConsentRequiredError,
    AIProviderError,
    AIUnavailableError,
)
from app.redactor import redact_dict
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
from app.scanner_orchestrator import ScanStatus

api_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def _owned_scan(job_id: str):
    user = g.current_user
    return current_app.extensions["db"].get_scan_report(
        job_id,
        owner_id=user.get("user_id"),
        owner_username=user.get("username"),
    )


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
    uploaded_archive = False

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
            try:
                file_obj.save(saved_archive_path)
            except Exception:
                try:
                    os.remove(saved_archive_path)
                except FileNotFoundError:
                    pass
                raise
            target_data = saved_archive_path
            uploaded_archive = True

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
        cleanup_archive=uploaded_archive,
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
    report = _owned_scan(job_id)

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
    report = _owned_scan(job_id)

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
        "engine_errors": report.get("engine_errors", {}),
        "created_at": report.get("created_at"),
        "updated_at": report.get("updated_at"),
    }

    # Strict redaction across API boundary
    return jsonify(redact_dict(results_data)), 200


@api_bp.route("/scans/<job_id>/reports/<report_format>", methods=["GET"])
@require_auth
def download_scan_report(job_id: str, report_format: str):
    """Download a redacted scan report as PDF, HTML, JSON, or SARIF 2.1.0."""
    formats = {
        "pdf": ("application/pdf", "pdf"),
        "html": ("text/html; charset=utf-8", "html"),
        "json": ("application/json", "json"),
        "sarif": ("application/sarif+json", "sarif"),
    }
    if report_format not in formats:
        return jsonify({
            "status": "error",
            "error": "Unsupported report format. Choose pdf, html, json, or sarif.",
        }), 400

    report = _owned_scan(job_id)
    if not report:
        return jsonify({"status": "error", "error": "Scan job not found", "job_id": job_id}), 404
    if report.get("status") != ScanStatus.COMPLETED:
        return jsonify({
            "status": "error",
            "error": "Reports are available after the scan has completed.",
            "scan_status": report.get("status"),
        }), 409

    report = redact_dict(report)
    findings = report.get("findings", [])
    scores = report.get("scores") or {}
    summary = {
        "job_id": report.get("job_id"),
        "project_id": report.get("project_id"),
        "created_at": str(report.get("created_at", "")),
        "grade": report.get("grade"),
        "scores": scores,
        "findings": findings,
    }
    mime_type, extension = formats[report_format]
    filename = f"security-report-{secure_filename(str(job_id))}.{extension}"

    if report_format == "json":
        payload = json.dumps(summary, indent=2, ensure_ascii=False).encode("utf-8")
    elif report_format == "sarif":
        rules = {}
        results = []
        for finding in findings:
            rule_id = str(finding.get("rule_id") or "UNKNOWN")
            rules.setdefault(rule_id, {
                "id": rule_id,
                "shortDescription": {"text": finding.get("description", "Security finding")},
                "help": {"text": finding.get("remediation", "Review and remediate this finding.")},
                "properties": {"category": finding.get("category", finding.get("engine_name", "Security"))},
            })
            severity = str(finding.get("severity", "info")).lower()
            level = "error" if severity in ("critical", "high") else "warning" if severity == "medium" else "note"
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": finding.get("description", "Security finding")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(finding.get("file_path", ""))},
                        "region": {"startLine": max(1, int(finding.get("line_number") or 1))},
                    },
                }],
                "properties": {
                    "severity": severity,
                    "category": finding.get("category", finding.get("engine_name", "Security")),
                    "remediation": finding.get("remediation", ""),
                    "redactedSnippet": finding.get("match_content", ""),
                },
            })
        payload = json.dumps({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "Secret Leak Guard",
                    "version": current_app.config.get("APP_VERSION", "2.0.0"),
                    "rules": list(rules.values()),
                }},
                "results": results,
                "properties": {
                    "projectId": summary["project_id"],
                    "riskScore": scores.get("final_score", 0),
                    "securityGrade": summary["grade"],
                    "severityCounts": scores.get("severity_counts", {}),
                },
            }],
        }, indent=2, ensure_ascii=False).encode("utf-8")
    elif report_format == "html":
        severity_counts = scores.get("severity_counts", {})
        severity_rows = "".join(
            f"<tr><th>{html.escape(str(severity).title())}</th><td>{int(count or 0)}</td></tr>"
            for severity, count in severity_counts.items()
        )
        finding_rows = "".join(
            "<tr>"
            f"<td>{html.escape(str(finding.get('severity', 'info')).upper())}</td>"
            f"<td>{html.escape(str(finding.get('rule_id', '')))}</td>"
            f"<td>{html.escape(str(finding.get('file_path', '')))}:{int(finding.get('line_number') or 0)}</td>"
            f"<td>{html.escape(str(finding.get('description', '')))}"
            f"<br><small>{html.escape(str(finding.get('remediation', '')))}</small></td>"
            "</tr>"
            for finding in findings
        )
        document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Security report - {html.escape(str(summary['project_id'] or 'Project'))}</title>
<style>body{{font:15px system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#172033}}
h1,h2{{color:#102a43}}table{{border-collapse:collapse;width:100%;margin:16px 0 32px}}
th,td{{border:1px solid #d5deea;padding:10px;text-align:left}}th{{background:#edf3f8}}
.score{{font-size:1.2rem;font-weight:700}}</style></head><body>
<h1>Security assessment</h1><p><strong>Project:</strong> {html.escape(str(summary['project_id'] or ''))}</p>
<p><strong>Scan:</strong> {html.escape(str(summary['job_id'] or ''))} · {html.escape(summary['created_at'])}</p>
<p class="score">Risk score: {int(scores.get('final_score') or 0)}/100 · Grade: {html.escape(str(summary['grade'] or 'N/A'))}</p>
<h2>Severity matrix</h2><table><thead><tr><th>Severity</th><th>Findings</th></tr></thead><tbody>{severity_rows}</tbody></table>
<h2>Findings and remediation</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Description / remediation</th></tr></thead>
<tbody>{finding_rows or '<tr><td colspan="4">No findings.</td></tr>'}</tbody></table></body></html>"""
        payload = document.encode("utf-8")
    else:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )

        buffer = io.BytesIO()
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#102a43")))
        styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=8, leading=10, wordWrap="CJK"))
        styles.add(ParagraphStyle(name="SectionHeading", parent=styles["Heading2"], textColor=colors.HexColor("#087e8b"), spaceBefore=10))
        document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=17 * mm, leftMargin=17 * mm, topMargin=16 * mm, bottomMargin=16 * mm)
        story = [
            Paragraph("Security Assessment", styles["ReportTitle"]),
            Spacer(1, 8),
            Paragraph(f"<b>Project:</b> {escape(str(summary['project_id'] or ''))}", styles["BodyText"]),
            Paragraph(f"<b>Scan ID:</b> {escape(str(summary['job_id'] or ''))}", styles["BodyText"]),
            Paragraph(f"<b>Generated:</b> {escape(summary['created_at'])}", styles["BodyText"]),
            Paragraph(
                f"<b>Risk score:</b> {int(scores.get('final_score') or 0)}/100"
                f"&nbsp;&nbsp;&nbsp; <b>Security grade:</b> {escape(str(summary['grade'] or 'N/A'))}",
                styles["BodyText"],
            ),
            Paragraph("Severity matrix", styles["SectionHeading"]),
        ]
        severity_counts = scores.get("severity_counts", {})
        severity_data = [["Severity", "Findings"]] + [
            [str(severity).title(), int(count or 0)]
            for severity, count in severity_counts.items()
        ]
        severity_table = Table(severity_data, colWidths=[90 * mm, 60 * mm], repeatRows=1)
        severity_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102a43")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#ccd6e0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ("PADDING", (0, 0), (-1, -1), 7),
        ]))
        story.extend([severity_table, Paragraph("Findings and remediation", styles["SectionHeading"])])
        finding_data = [["Severity", "Finding / location / redacted snippet", "Recommended remediation"]]
        for finding in findings:
            location = f"{finding.get('file_path', '')}:{finding.get('line_number') or 0}"
            snippet = finding.get("match_content") or finding.get("raw_secret") or ""
            details = (
                f"<b>{escape(str(finding.get('rule_id', '')))}</b><br/>"
                f"{escape(str(finding.get('description', '')))}<br/>"
                f"<font color='#526579'>{escape(str(location))}</font><br/>"
                f"<font color='#8b2430'>Redacted evidence: {escape(str(snippet))}</font>"
            )
            finding_data.append([
                Paragraph(escape(str(finding.get("severity", "info")).upper()), styles["SmallCell"]),
                Paragraph(details, styles["SmallCell"]),
                Paragraph(escape(str(finding.get("remediation", "Review and remediate this finding."))), styles["SmallCell"]),
            ])
        if len(finding_data) == 1:
            finding_data.append(["INFO", Paragraph("No findings.", styles["SmallCell"]), ""])
        finding_table = Table(finding_data, colWidths=[22 * mm, 90 * mm, 48 * mm], repeatRows=1)
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102a43")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#ccd6e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(finding_table)
        document.build(story)
        payload = buffer.getvalue()
        buffer.close()

    return send_file(
        io.BytesIO(payload),
        mimetype=mime_type,
        as_attachment=True,
        download_name=filename,
        max_age=0,
    )


@api_bp.route("/scans", methods=["GET"])
@require_auth
def list_scans():
    """List the current user's scan jobs with pagination and sorting."""
    db = current_app.extensions["db"]
    project_id = request.args.get("project_id")
    status = request.args.get("status")
    try:
        limit = int(request.args.get("limit", 20))
        skip = int(request.args.get("skip", 0))
    except ValueError:
        return jsonify({"status": "error", "error": "'limit' and 'skip' must be integers."}), 400
    if not 1 <= limit <= 100 or skip < 0:
        return jsonify({"status": "error", "error": "'limit' must be 1-100 and 'skip' cannot be negative."}), 400

    sort_by = request.args.get("sort", "created_at")
    sort_direction = request.args.get("order", "desc").lower()
    if sort_by != "created_at" or sort_direction not in {"asc", "desc"}:
        return jsonify({"status": "error", "error": "Scans can be sorted by created_at in asc or desc order."}), 400

    user = g.current_user
    scans = db.list_scan_reports(
        project_id=project_id,
        status=status,
        limit=limit,
        skip=skip,
        owner_id=user.get("user_id"),
        owner_username=user.get("username"),
        sort_order=1 if sort_direction == "asc" else -1,
    )
    
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
    try:
        limit = int(request.args.get("limit", 30))
    except ValueError:
        return jsonify({"status": "error", "error": "'limit' must be an integer."}), 400
    if not 1 <= limit <= 100:
        return jsonify({"status": "error", "error": "'limit' must be between 1 and 100."}), 400
    user = g.current_user
    metrics = db.get_historical_metrics(
        project_id,
        limit=limit,
        owner_id=user.get("user_id"),
        owner_username=user.get("username"),
    )

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


@api_bp.route("/vault/renew-lease", methods=["POST"])
@require_role([Role.ADMIN])
def renew_vault_lease():
    payload = request.get_json(silent=True) or {}
    lease_id = payload.get("lease_id")
    increment = payload.get("increment", 3600)
    if not isinstance(lease_id, str) or not lease_id.strip():
        return jsonify({"status": "error", "error": "A valid 'lease_id' is required."}), 400
    if not isinstance(increment, int) or isinstance(increment, bool) or not 1 <= increment <= 86400:
        return jsonify({"status": "error", "error": "'increment' must be an integer from 1 to 86400."}), 400
    result = current_app.extensions["vault"].renew_lease(lease_id.strip(), increment=increment)
    if not result.get("renewed"):
        return jsonify(redact_dict({"status": "error", "result": result})), 503
    return jsonify(redact_dict({"status": "success", "result": result})), 200


@api_bp.route("/vault/renew-token", methods=["POST"])
@require_role([Role.ADMIN])
def renew_vault_token():
    payload = request.get_json(silent=True) or {}
    increment = payload.get("increment", 3600)
    if not isinstance(increment, int) or isinstance(increment, bool) or not 1 <= increment <= 86400:
        return jsonify({"status": "error", "error": "'increment' must be an integer from 1 to 86400."}), 400
    vault = current_app.extensions["vault"]
    if not vault.enabled or not vault.is_connected:
        return jsonify({"status": "error", "error": "Authenticated Vault is required for token renewal."}), 503
    result = vault.renew_token(increment=increment)
    return jsonify(redact_dict({"status": "success", "result": result})), 200


def _invoke_ai(task: str, *, finding_required: bool = False, question_required: bool = False):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "error": "A JSON request body is required."}), 400
    scan_id = payload.get("scan_id")
    if not isinstance(scan_id, str) or not scan_id.strip():
        return jsonify({"status": "error", "error": "'scan_id' is required."}), 400

    report = _owned_scan(scan_id.strip())
    if not report:
        return jsonify({"status": "error", "error": "Scan not found."}), 404
    if report.get("status") != ScanStatus.COMPLETED:
        return jsonify({"status": "error", "error": "AI assistance requires a completed scan."}), 409

    finding = None
    if finding_required:
        fingerprint = payload.get("finding_fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint.strip():
            return jsonify({"status": "error", "error": "'finding_fingerprint' is required."}), 400
        finding = next(
            (item for item in report.get("findings", [])
             if item.get("fingerprint") == fingerprint.strip()),
            None,
        )
        if not finding:
            return jsonify({"status": "error", "error": "Finding not found in this scan."}), 404

    question = payload.get("question")
    if question_required and (not isinstance(question, str) or not question.strip() or len(question) > 2000):
        return jsonify({"status": "error", "error": "'question' must contain 1-2000 characters."}), 400

    try:
        entry = current_app.extensions["ai_assistant"].respond(
            user_id=str(g.current_user.get("user_id") or ""),
            scan_id=scan_id.strip(),
            task=task,
            report=report,
            consent=payload.get("consent") is True,
            finding=finding,
            question=question.strip() if isinstance(question, str) else None,
        )
    except AIConsentRequiredError as error:
        return jsonify({"status": "error", "error": str(error)}), 400
    except AIUnavailableError as error:
        return jsonify({"status": "error", "error": str(error)}), 503
    except AIProviderError:
        current_app.logger.warning("AI %s request failed for scan %s.", task, scan_id)
        return jsonify({"status": "error", "error": "The AI provider request failed."}), 502

    return jsonify(redact_dict({"status": "success", "entry": entry})), 200


@api_bp.route("/ai/explain", methods=["POST"])
@limiter.limit("10 per minute")
@require_auth
def ai_explain():
    return _invoke_ai("explain", finding_required=True)


@api_bp.route("/ai/remediate", methods=["POST"])
@limiter.limit("10 per minute")
@require_auth
def ai_remediate():
    return _invoke_ai("remediate", finding_required=True)


@api_bp.route("/ai/chat", methods=["POST"])
@limiter.limit("10 per minute")
@require_auth
def ai_chat():
    return _invoke_ai("chat", question_required=True)


@api_bp.route("/ai/summary", methods=["POST"])
@limiter.limit("10 per minute")
@require_auth
def ai_summary():
    return _invoke_ai("summary")


@api_bp.route("/ai/history/<scan_id>", methods=["GET"])
@limiter.limit("30 per minute")
@require_auth
def ai_history(scan_id: str):
    if not _owned_scan(scan_id):
        return jsonify({"status": "error", "error": "Scan not found."}), 404
    try:
        limit = int(request.args.get("limit", 30))
    except ValueError:
        return jsonify({"status": "error", "error": "'limit' must be an integer."}), 400
    if not 1 <= limit <= 100:
        return jsonify({"status": "error", "error": "'limit' must be between 1 and 100."}), 400
    entries = current_app.extensions["db"].list_ai_history(
        str(g.current_user.get("user_id") or ""),
        scan_id,
        limit=limit,
    )
    return jsonify(redact_dict({"status": "success", "entries": entries})), 200
