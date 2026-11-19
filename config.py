"""Configuration module for Secret Leak Guard v2.0."""

import os
import tempfile
from pathlib import Path
from typing import List
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()


class Config:
    """Base configuration settings."""

    # Application settings
    APP_NAME: str = "Secret Leak Guard"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    TESTING: bool = False

    # Security & Flask Keys
    SECRET_KEY: str = os.getenv("SECRET_KEY", "insecure-dev-secret-key-change-in-production")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "insecure-jwt-secret-key-change-in-production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRATION_HOURS: int = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))

    # Database settings (MongoDB 7.0)
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "secret_leak_guard_v2")
    MONGO_TTL_SECONDS: int = int(os.getenv("MONGO_TTL_SECONDS", str(30 * 24 * 3600)))  # 30 days
    MONGO_USE_MOCK: bool = os.getenv("MONGO_USE_MOCK", "false").lower() in ("true", "1", "yes")

    # HashiCorp Vault 1.15.6 Settings
    VAULT_ADDR: str = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    VAULT_TOKEN: str = os.getenv("VAULT_TOKEN", "")
    VAULT_MOUNT_POINT: str = os.getenv("VAULT_MOUNT_POINT", "secret")
    VAULT_SECRET_PATH: str = os.getenv("VAULT_SECRET_PATH", "secret-leak-guard")
    VAULT_ENABLED: bool = os.getenv("VAULT_ENABLED", "true").lower() in ("true", "1", "yes")
    VAULT_BOOTSTRAP_ENV: bool = os.getenv("VAULT_BOOTSTRAP_ENV", "false").lower() in ("true", "1", "yes")
    VAULT_TIMEOUT: int = int(os.getenv("VAULT_TIMEOUT", "5"))
    VAULT_DATABASE_ROLE: str = os.getenv("VAULT_DATABASE_ROLE", "slg-backend-role")
    VAULT_DATABASE_MOUNT_POINT: str = os.getenv("VAULT_DATABASE_MOUNT_POINT", "database")
    VAULT_DATABASE_FALLBACK: bool = os.getenv("VAULT_DATABASE_FALLBACK", "false").lower() in ("true", "1", "yes")
    MONGO_AUTH_SOURCE: str = os.getenv("MONGO_AUTH_SOURCE", "admin")

    # Workspace & Ingestion settings
    # Default to system temp dir or /tmp/scanner_workspaces
    _default_tmp = "/tmp/scanner_workspaces" if os.name != "nt" else os.path.join(tempfile.gettempdir(), "scanner_workspaces")
    WORKSPACE_BASE_DIR: str = os.getenv("WORKSPACE_BASE_DIR", _default_tmp)
    
    # Allowed base directories for Local Path ingestion mode (prevents traversal)
    ALLOWED_LOCAL_SCAN_PATHS: List[str] = [
        p.strip() for p in os.getenv(
            "ALLOWED_LOCAL_SCAN_PATHS", 
            f"{os.getcwd()},{tempfile.gettempdir()}"
        ).split(",") if p.strip()
    ]

    # File uploads
    MAX_CONTENT_LENGTH: int = int(os.getenv("MAX_CONTENT_LENGTH", str(50 * 1024 * 1024)))  # 50 MB
    ALLOWED_ARCHIVE_EXTENSIONS: tuple = (".zip", ".tar.gz", ".tgz", ".tar")

    # Rate Limiting
    RATELIMIT_DEFAULT: str = os.getenv("RATELIMIT_DEFAULT", "100 per minute")
    RATELIMIT_STORAGE_URI: str = os.getenv("RATELIMIT_STORAGE_URI", "memory://")

    # Engine Execution & Concurrency
    ENGINE_MAX_WORKERS: int = int(os.getenv("ENGINE_MAX_WORKERS", "4"))
    SCAN_JOB_TIMEOUT_SECONDS: int = int(os.getenv("SCAN_JOB_TIMEOUT_SECONDS", "300"))
    OSV_ENABLED: bool = os.getenv("OSV_ENABLED", "true").lower() in ("true", "1", "yes")


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = True
    MONGO_DB_NAME = "secret_leak_guard_test"
    MONGO_USE_MOCK = True
    VAULT_ENABLED = False
    OSV_ENABLED = False
    JWT_EXPIRATION_HOURS = 1
    WORKSPACE_BASE_DIR = os.path.join(tempfile.gettempdir(), "scanner_workspaces_test")
    RATELIMIT_STORAGE_URI = "memory://"


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    TESTING = False
    # In production, Vault should be enabled and keys should not use defaults
    VAULT_ENABLED = os.getenv("VAULT_ENABLED", "true").lower() in ("true", "1", "yes")


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
