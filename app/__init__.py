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
from app.database_lease import DatabaseLeaseManager
from app.ai_assistant import AIAssistant

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

    if config_name == "production":
        required_secrets = {
            "SECRET_KEY": app.config.get("SECRET_KEY"),
            "JWT_SECRET_KEY": app.config.get("JWT_SECRET_KEY"),
            "VAULT_TOKEN": app.config.get("VAULT_TOKEN"),
        }
        weak_values = {
            "insecure-dev-secret-key-change-in-production",
            "insecure-jwt-secret-key-change-in-production",
            "change-me-to-a-very-strong-random-key-in-production",
            "change-me-to-a-secure-jwt-signing-key-32chars",
            "root",
        }
        invalid = [
            key for key, value in required_secrets.items()
            if not isinstance(value, str) or len(value) < 32 or value.lower() in weak_values
        ]
        if invalid:
            raise RuntimeError(
                "Production startup requires strong values for: " + ", ".join(invalid)
            )
        if not app.config.get("VAULT_ENABLED") or app.config.get("MONGO_USE_MOCK"):
            raise RuntimeError("Production startup requires Vault and live MongoDB.")

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
    if config_name == "production" and not vault.is_connected:
        raise RuntimeError("Production startup requires an authenticated Vault connection.")

    # Seed only missing KV-v2 keys from environment when bootstrap is explicitly enabled.
    mongo_uri = app.config.get("MONGO_URI", "mongodb://localhost:27017")
    database_credentials = None
    mongo_username = None
    mongo_password = None
    mongo_auth_source = app.config.get(
        "MONGO_AUTH_SOURCE", app.config.get("MONGO_DB_NAME", "admin")
    )
    if vault.is_connected:
        if app.config.get("VAULT_BOOTSTRAP_ENV", False):
            vault_secrets = vault.provision_secrets({
                key: app.config[key]
                for key in (
                    "SECRET_KEY",
                    "JWT_SECRET_KEY",
                    "MONGO_URI",
                    "GEMINI_API_KEY",
                    "GROQ_API_KEY",
                )
                if app.config.get(key)
            })
            for key in ("SECRET_KEY", "JWT_SECRET_KEY"):
                if vault_secrets.get(key):
                    app.config[key] = vault_secrets[key]
        jwt_key = vault.get_secret("JWT_SECRET_KEY")
        if jwt_key:
            app.config["JWT_SECRET_KEY"] = jwt_key
        try:
            database_credentials = vault.generate_database_credentials(
                role=app.config.get("VAULT_DATABASE_ROLE", "slg-backend-role"),
                mount_point=app.config.get("VAULT_DATABASE_MOUNT_POINT", "database"),
            )
            mongo_username = database_credentials["username"]
            mongo_password = database_credentials["password"]
        except RuntimeError as error:
            if not app.config.get("VAULT_DATABASE_FALLBACK", False):
                raise RuntimeError(
                    "Vault database credentials are unavailable and KV-v2 fallback is disabled."
                ) from error
            try:
                mongo_username = vault.get_secret("MONGO_APP_USERNAME")
                mongo_password = vault.get_secret("MONGO_APP_PASSWORD")
            except (KeyError, RuntimeError) as secret_error:
                raise RuntimeError("Vault KV-v2 MongoDB fallback credentials are missing.") from secret_error
            if not mongo_username or not mongo_password:
                raise RuntimeError("Vault KV-v2 MongoDB fallback credentials are incomplete.") from error
            mongo_auth_source = "admin"
            app.logger.warning(
                "Dynamic MongoDB credentials unavailable; using KV-v2 fallback (%s).",
                type(error).__name__,
            )

    # 4. Initialize MongoDB 7.0 Database Client
    db = DatabaseClient(
        mongo_uri=mongo_uri,
        db_name=app.config.get("MONGO_DB_NAME", "secret_leak_guard_v2"),
        ttl_seconds=app.config.get("MONGO_TTL_SECONDS", 30 * 24 * 3600),
        use_mock=app.config.get("MONGO_USE_MOCK", False),
        allow_mock_fallback=config_name != "production",
        mongo_username=mongo_username,
        mongo_password=mongo_password,
        mongo_auth_source=mongo_auth_source,
    )
    if config_name == "production" and db.is_mock:
        raise RuntimeError("Production startup requires a live MongoDB connection.")

    # 5. Initialize Scanner Orchestrator
    orchestrator = ScannerOrchestrator(
        db_client=db,
        max_workers=app.config.get("ENGINE_MAX_WORKERS", 4),
        workspace_base_dir=app.config.get("WORKSPACE_BASE_DIR"),
        allowed_local_paths=app.config.get("ALLOWED_LOCAL_SCAN_PATHS"),
        osv_enabled=app.config.get("OSV_ENABLED", True),
    )
    ai_provider = app.config.get("AI_PROVIDER", "gemini").strip().lower()
    if ai_provider == "groq":
        ai_api_key = app.config.get("GROQ_API_KEY", "")
        ai_model = app.config.get("GROQ_MODEL", "openai/gpt-oss-20b")
        ai_secret_name = "GROQ_API_KEY"
    elif ai_provider == "gemini":
        ai_api_key = app.config.get("GEMINI_API_KEY", "")
        ai_model = app.config.get("GEMINI_MODEL", "gemini-3.8-flash")
        ai_secret_name = "GEMINI_API_KEY"
    else:
        raise RuntimeError("AI_PROVIDER must be either 'gemini' or 'groq'.")
    if not ai_api_key and vault.is_connected:
        try:
            ai_api_key = vault.get_secret(ai_secret_name) or ""
        except (KeyError, RuntimeError):
            ai_api_key = ""
    ai_assistant = AIAssistant(
        database=db,
        api_key=ai_api_key,
        model=ai_model,
        timeout_seconds=app.config.get("GEMINI_TIMEOUT_SECONDS", 15),
        generator=app.config.get("AI_GENERATOR"),
        provider=ai_provider,
    )

    # 6. Attach Singletons to Extensions Dictionary
    app.extensions["vault"] = vault
    app.extensions["db"] = db
    app.extensions["orchestrator"] = orchestrator
    app.extensions["ai_assistant"] = ai_assistant
    app.extensions["database_lease_manager"] = None
    if database_credentials:
        lease_manager = DatabaseLeaseManager(
            vault=vault,
            database=db,
            auth_source=app.config.get("MONGO_AUTH_SOURCE", app.config.get("MONGO_DB_NAME", "admin")),
            role=app.config.get("VAULT_DATABASE_ROLE", "slg-backend-role"),
            lease=database_credentials,
        )
        lease_manager.start()
        app.extensions["database_lease_manager"] = lease_manager

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
