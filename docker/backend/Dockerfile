# =============================================================================
# Secret Leak Guard v2.0 - Scanner Backend Dockerfile
# Multi-Stage Build: Python 3.12 Slim -> Hardened Minimal Runtime Image
# Enforces non-root execution as UID 10001
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build & Wheel Compilation Stage
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies for C-extensions (bcrypt, cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment for isolated dependency packaging
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python production dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Hardened Production Runtime Stage
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL maintainer="DevOps Team <devops@secretleakguard.io>" \
      version="2.0.0" \
      service="scanner-backend" \
      description="Production hardened static analysis backend for Secret Leak Guard v2.0"

# Install minimal runtime tools:
# - git: Required for Git URL ingestion mode (git clone --depth 1)
# - curl & ca-certificates: Required for container health checks and secure external APIs
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Security Hardening: Create non-root group and user with UID 10001
RUN groupadd -g 10001 slggroup && \
    useradd -u 10001 -g slggroup -s /bin/bash -m -d /home/slguser slguser

# Configure environment variables
ENV VIRTUAL_ENV="/opt/venv" \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WORKSPACE_BASE_DIR="/tmp/scanner_workspaces" \
    FLASK_ENV=production \
    PORT=5000

# Copy pre-compiled virtual environment from builder stage
COPY --from=builder --chown=10001:10001 /opt/venv /opt/venv

WORKDIR /app

# Copy application code, configuration, and runner
COPY --chown=10001:10001 app/ /app/app/
COPY --chown=10001:10001 config.py run.py ./
COPY --chown=10001:10001 scripts/create_admin.py /app/scripts/create_admin.py

# Create workspaces and log directories with restricted non-root permissions
RUN mkdir -p /tmp/scanner_workspaces /app/logs && \
    chown -R 10001:10001 /tmp/scanner_workspaces /app /home/slguser && \
    chmod 700 /tmp/scanner_workspaces

# Switch to unprivileged non-root user UID 10001
USER 10001:10001

# Expose backend REST API port
EXPOSE 5000

# Container Healthcheck instruction
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/v1/health || exit 1

# Launch production WSGI Gunicorn server
CMD ["gunicorn", "--workers=4", "--threads=2", "--bind=0.0.0.0:5000", "--timeout=120", "--access-logfile=-", "--error-logfile=-", "run:app"]
