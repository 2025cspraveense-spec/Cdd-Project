"""Application Factory for Secret Leak Guard v2.0."""

import logging
import os
from typing import Any, Dict, Optional
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config, config_by_name
from app.db import DatabaseClient
from app.ingestion import (
    IngestionError,
    PathTraversalError,
    SSRFProtectionError,
    ZipSlipError,
)
from app.redactor import RedactingFilter, RedactingFormatter, redact_dict
from app.scanner_orchestrator import ScannerOrchestrator
from app.vault_client import VaultClient

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri="memory://",
)


def setup_secure_logging(app: Flask) -> None:
    """Configures application logging with strict credential redaction filters and formatters."""
    formatter = RedactingFormatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] %(message)s"
    )
    redact_filter = RedactingFilter()

    # Apply to root and app loggers
    app.logger.addFilter(redact_filter)
    for handler in app.logger.handlers:
        handler.setFormatter(formatter)
        handler.addFilter(redact_filter)

    # Also apply to standard logging root handler
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)
        handler.addFilter(redact_filter)


def create_app(
    config_name: Optional[str] = None,
    config_override: Optional[Dict[str, Any]] = None
) -> Flask:
    """Flask application factory."""
    app = Flask(__name__)

    # 1. Load Configuration
    if not config_name:
        config_name = os.getenv("FLASK_ENV", "development").lower()
    config_class = config_by_name.get(config_name, Config)
    app.config.from_object(config_class)

    if config_override:
        app.config.update(config_override)

    # 2. Setup Secure Redacting Logging
    setup_secure_logging(app)

    # 3. Initialize HashiCorp Vault Client
    vault = VaultClient(
        vault_addr=app.config.get("VAULT_ADDR"),
        vault_token=app.config.get("VAULT_TOKEN"),
        mount_point=app.config.get("VAULT_MOUNT_POINT", "secret"),
        secret_path=app.config.get("VAULT_SECRET_PATH", "secret-leak-guard"),
        enabled=app.config.get("VAULT_ENABLED", False),
        timeout=app.config.get("VAULT_TIMEOUT", 5),
    )

    # Dynamically resolve secrets from Vault if connected
    if vault.is_connected:
        jwt_key = vault.get_secret("JWT_SECRET_KEY")
        if jwt_key:
            app.config["JWT_SECRET_KEY"] = jwt_key
        mongo_uri = vault.get_secret("MONGO_URI")
        if mongo_uri:
            app.config["MONGO_URI"] = mongo_uri

    # 4. Initialize MongoDB 7.0 Database Client
    db = DatabaseClient(
        mongo_uri=app.config.get("MONGO_URI", "mongodb://localhost:27017"),
        db_name=app.config.get("MONGO_DB_NAME", "secret_leak_guard_v2"),
        ttl_seconds=app.config.get("MONGO_TTL_SECONDS", 30 * 24 * 3600),
        use_mock=app.config.get("MONGO_USE_MOCK", False),
    )

    # 5. Initialize Scanner Orchestrator
    orchestrator = ScannerOrchestrator(
        db_client=db,
        max_workers=app.config.get("ENGINE_MAX_WORKERS", 4),
        workspace_base_dir=app.config.get("WORKSPACE_BASE_DIR"),
        allowed_local_paths=app.config.get("ALLOWED_LOCAL_SCAN_PATHS"),
    )

    # 6. Attach Singletons to Extensions Dictionary
    app.extensions["vault"] = vault
    app.extensions["db"] = db
    app.extensions["orchestrator"] = orchestrator

    # 7. Initialize Rate Limiter
    limiter.init_app(app)

    # 8. Register Blueprints
    from app.routes import api_bp
    app.register_blueprint(api_bp)

    # 9. Register Global Security & Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify(redact_dict({
            "status": "error",
            "code": 400,
            "error": "Bad Request",
            "message": str(error),
        })), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify(redact_dict({
            "status": "error",
            "code": 401,
            "error": "Unauthorized",
            "message": str(error),
        })), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify(redact_dict({
            "status": "error",
            "code": 403,
            "error": "Forbidden",
            "message": str(error),
        })), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify(redact_dict({
            "status": "error",
            "code": 404,
            "error": "Not Found",
            "message": "The requested resource was not found on this server.",
        })), 404

    @app.errorhandler(429)
    def ratelimit_exceeded(error):
        return jsonify(redact_dict({
            "status": "error",
            "code": 429,
            "error": "Too Many Requests",
            "message": "Rate limit exceeded. Please throttle your requests.",
        })), 429

    @app.errorhandler(ZipSlipError)
    def handle_zip_slip(error):
        app.logger.warning(f"ZipSlip attempt blocked: {error}")
        return jsonify(redact_dict({
            "status": "error",
            "code": 400,
            "error": "ZipSlipSecurityViolation",
            "message": str(error),
        })), 400

    @app.errorhandler(SSRFProtectionError)
    def handle_ssrf(error):
        app.logger.warning(f"SSRF attempt blocked: {error}")
        return jsonify(redact_dict({
            "status": "error",
            "code": 400,
            "error": "SSRFProtectionViolation",
            "message": str(error),
        })), 400

    @app.errorhandler(PathTraversalError)
    def handle_path_traversal(error):
        app.logger.warning(f"Path traversal attempt blocked: {error}")
        return jsonify(redact_dict({
            "status": "error",
            "code": 403,
            "error": "PathTraversalViolation",
            "message": str(error),
        })), 403

    @app.errorhandler(IngestionError)
    def handle_ingestion_error(error):
        return jsonify(redact_dict({
            "status": "error",
            "code": 400,
            "error": "IngestionError",
            "message": str(error),
        })), 400

    @app.errorhandler(Exception)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}", exc_info=True)
        return jsonify(redact_dict({
            "status": "error",
            "code": 500,
            "error": "Internal Server Error",
            "message": "An unexpected error occurred processing your request.",
        })), 500

    return app
