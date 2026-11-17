# Secret Leak Guard v2.0 - Complete Enterprise Platform

**Secret Leak Guard v2.0** is an enterprise-grade, asynchronous static analysis, secret detection, and automated remediation platform. It features a complete multi-tier microservices architecture:
- **Unified Gateway**: Nginx 1.27.5 reverse proxy with custom JSON error pages and HTTP security headers
- **Frontend Dashboard**: React 18.2 interactive security operations console
- **Scanner Backend**: Python 3.12 / Flask 3.1 API orchestrating 4 parallel analysis engines
- **Persistence Layer**: MongoDB 7.0 with compound and TTL expiration indexing
- **Secrets Management**: HashiCorp Vault 1.15.6 with KV-v2 engine and lease renewal
- **CI/CD & DevSecOps**: GitHub Actions, Gitleaks, Trivy, GHCR publishing, and automated rollback

---

## 1. System Architecture

```
                                    +-----------------------------------------+
                                    |         User Browser / CI/CD            |
                                    +-----------------------------------------+
                                                         |
                                            HTTP Ports 80 & 8080 (1000MB)
                                                         v
                       +-------------------------------------------------------------------+
                       |              Unified Gateway (Nginx 1.27.5 - UID 10001)           |
                       |  - Strict CSP, HSTS, X-Frame, X-Content-Type, Referrer-Policy      |
                       |  - Custom JSON Error Pages (HTTP 413 Payload & HTTP 502 Bad Gateway)|
                       |  - Dual Listening on Ports 80 and 8080                            |
                       +-------------------------------------------------------------------+
                                         |                   |                   |
                        / and /app/      |     /api/v1/      |      /vault/      |
                        +----------------+                   |                   +-------------+
                        |                                    v                                 |
                        v                   +----------------------------------+               v
    +------------------------------------+  | Scanner Backend (Python 3.12/    |  +---------------------------+
    | Frontend Dashboard (React 18.2)    |  | Flask 3.1 / Gunicorn - UID 10001)|  | HashiCorp Vault 1.15.6    |
    | - Non-root Nginx server (:3000)    |  +----------------------------------+  | - KV-v2 Secret Engine     |
    | - Live Jobs & Findings Monitor     |                   |                    | - Dynamic Lease & Renewal |
    | - Posture Grading & Gauge (A+ to F)|                   v                    | - Cap IPC_LOCK (:8200)    |
    +------------------------------------+  +----------------------------------+  +---------------------------+
                                            | 4 Parallel Analysis Engines      |               |
                                            | - SecretEngine                   |               |
                                            | - SASTEngine                     |               |
                                            | - SCAEngine                      |               |
                                            | - ContainerEngine                |               |
                                            +----------------------------------+               |
                                                             |                                 |
                                                             v                                 |
                                            +----------------------------------+               |
                                            | Database: MongoDB 7.0 (:27017)   |<--------------+
                                            | - Compound, Unique & TTL Indexes |
                                            | - scan_reports, fingerprints     |
                                            +----------------------------------+
```

---

## 2. Directory Structure

```
.
├── docker-compose.yml            # 5-Service Docker Compose orchestration on slg-network
├── .env.example                  # Environment configuration template
├── requirements.txt              # Backend production dependencies (Flask 3.1, Gunicorn, hvac, pymongo)
├── config.py                     # Multi-environment runtime configuration
├── run.py                        # Backend application entrypoint
├── README.md                     # Platform architecture & operations documentation
├── .github/
│   └── workflows/
│       └── ci-cd.yml             # 5-Stage GitHub Actions DevSecOps Pipeline
├── docker/
│   ├── backend/
│   │   └── Dockerfile            # Multi-stage Python 3.12 slim builder -> hardened runtime (UID 10001)
│   ├── frontend/
│   │   └── Dockerfile            # Multi-stage Node 20 builder -> Nginx 1.27.5 static server (UID 10001)
│   └── gateway/
│       ├── Dockerfile            # Multi-stage Nginx 1.27.5 Alpine runtime (UID 10001)
│       └── nginx.conf            # Dual port (80/8080), 1000MB upload, JSON 413/502 error handlers
├── frontend/
│   ├── package.json              # React 18.2 dependencies & esbuild bundler
│   ├── build.js                  # Automated frontend compilation script
│   ├── nginx.conf                # Non-root internal Nginx configuration (:3000)
│   ├── public/index.html         # Single Page Application HTML shell
│   └── src/
│       ├── index.js              # React 18.2 entrypoint
│       ├── App.js                # Interactive Security Control Center Dashboard
│       └── App.css               # Futuristic dark-mode security operations styling
├── app/                          # Flask 3.1 REST API & Analysis Engine Package
│   ├── __init__.py               # Application factory, rate limiter, redacting logging
│   ├── auth.py                   # PyJWT, bcrypt hashing, RBAC decorators (@require_role)
│   ├── db.py                     # MongoDB 7.0 client, compound & TTL indexes, mongomock fallback
│   ├── ingestion.py              # 4 Ingestion modes, canonical Zip-Slip defense, SSRF blocker
│   ├── redactor.py               # Strict redaction (preserves first 4 chars: AKIA****************)
│   ├── routes.py                 # REST API endpoints (/api/v1/auth, /api/v1/scans, /api/v1/health)
│   ├── scanner_orchestrator.py   # ThreadPoolExecutor concurrency, state machine, lifecycle
│   ├── scoring.py                # Weighted risk scoring, SHA-256 fingerprinting, grading
│   ├── vault_client.py           # HashiCorp Vault hvac KV-v2 integration with fallback
│   └── engines/                  # Modular static analysis engine interfaces
│       ├── __init__.py
│       ├── base.py               # BaseEngine abstract class and finding models
│       ├── secret_engine.py      # Secret scanner (AWS, GitHub, Slack, Private Keys)
│       ├── sast_engine.py        # SAST scanner (Command Injection, SQLi, Deserialization)
│       ├── sca_engine.py         # SCA dependency scanner (requirements.txt, package.json)
│       └── container_engine.py   # Container & Dockerfile security analyzer
├── scan_targets/                 # Read-only host mount for local scan targets
├── scripts/
│   └── verify_stack.sh           # Project Expo live stack verification and healthcheck script
└── tests/                        # 85-Test Comprehensive Automated Pytest Suite
    ├── conftest.py
    ├── test_auth_rbac.py
    ├── test_db.py
    ├── test_ingestion.py
    ├── test_orchestrator.py
    ├── test_redactor.py
    ├── test_routes_api.py
    ├── test_scoring.py
    └── test_vault_client.py
```

---

## 3. Microservices & Container Architecture

### 3.1 Five-Service Docker Compose Topology
All services communicate over an isolated Docker bridge network:
- **Network Name**: `slg-network` (`subnet: 172.28.0.0/16`)

| Service Name | Container Name | Image / Base | Internal Port | External Port | User |
|---|---|---|---|---|---|
| `gateway` | `slg-gateway` | `nginx:1.27.5-alpine` | `80`, `8080` | `80:80`, `8080:8080` | UID `10001` |
| `frontend` | `slg-frontend` | `node:20` $\rightarrow$ `nginx:1.27.5` | `3000` | Internal only | UID `10001` |
| `backend` | `slg-backend` | `python:3.12-slim` | `5000` | Internal only | UID `10001` |
| `mongodb` | `slg-mongodb` | `mongo:7.0` | `27017` | Internal only | `mongodb` |
| `vault` | `slg-vault` | `hashicorp/vault:1.15.6` | `8200` | Internal only | `vault` (`IPC_LOCK`) |

### 3.2 Security Hardening & Non-Root Execution
- **Unprivileged User**: All custom images (`backend`, `frontend`, `gateway`) create and execute as **UID `10001`** (`slguser`).
- **Filesystem Permissions**: Cache directories (`/var/cache/nginx`, `/tmp/nginx`, `/tmp/scanner_workspaces`) are pre-created with `10001:10001` ownership.
- **Explicit Container Healthchecks**: Every service features automated polling health checks (`curl`, `mongosh`, `vault status`).
- **Read-Only Host Mounts**: Local scan targets are bound read-only (`./scan_targets:/scan_targets:ro`) to prevent accidental host mutation.

---

## 4. Nginx 1.27.5 Unified Reverse Proxy Gateway

### 4.1 Routing Matrix
- **`http://localhost:80/`** & **`http://localhost:8080/`** $\longrightarrow$ Frontend React 18.2 Dashboard
- **`http://localhost:80/api/v1/`** $\longrightarrow$ Scanner Backend REST API
- **`http://localhost:80/vault/`** $\longrightarrow$ HashiCorp Vault UI and REST API
- **`http://localhost:80/health`** $\longrightarrow$ Gateway Health Check Endpoint

### 4.2 Large Archive Upload Support
- Configured with `client_max_body_size 1000M;` and `proxy_request_buffering off;` to allow direct streaming of massive archives into backend workspaces without premature disk exhaustion.

### 4.3 Custom JSON Error Responses
Nginx intercepts HTTP error codes and returns structured JSON responses:
- **HTTP 413 (Payload Too Large)**:
  ```json
  {
    "status": "error",
    "code": 413,
    "error": "PayloadTooLarge",
    "message": "Uploaded archive exceeds the maximum permitted limit of 1000MB."
  }
  ```
- **HTTP 502 (Bad Gateway)**:
  ```json
  {
    "status": "error",
    "code": 502,
    "error": "BadGateway",
    "message": "Upstream service temporarily unavailable. Gateway failed to connect to target service."
  }
  ```

### 4.4 HTTP Security Headers
Every HTTP response carries enterprise security headers:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self' http: https:; frame-ancestors 'none';
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-XSS-Protection: 1; mode=block
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

## 5. DevSecOps & CI/CD Automation Pipeline

Located at `.github/workflows/ci-cd.yml`, the pipeline runs on every `push` and `pull_request` to `main` and `develop`:

```
+-----------------------------------------------------------------------------------+
| GitHub Actions DevSecOps Workflow                                                 |
|                                                                                   |
|  [Job 1] Gitleaks Secret Detection                                                |
|          Scans entire git history and codebase to block leaked credentials.       |
|                                                                                   |
|  [Job 2] Automated Build & Pytest Suite                                           |
|          Runs Python 3.12 test suite (85 unit/integration tests) + Node build.    |
|                                                                                   |
|  [Job 3] Trivy Security & Vulnerability Audit                                     |
|          Scans filesystem and dependencies for CRITICAL/HIGH CVEs + SARIF upload. |
|                                                                                   |
|  [Job 4] Multi-Stage Docker Build, Tag & Publish                                  |
|          Builds backend, frontend, gateway; tags with Git SHA and pushes to GHCR. |
|                                                                                   |
|  [Job 5] Automated Deployment, Health Verification & Rollback                     |
|          Deploys via docker compose, verifies all endpoints, auto-rolls back      |
|          if health checks fail.                                                   |
+-----------------------------------------------------------------------------------+
```

---

## 6. Live Project Expo Verification Script

For live project demonstrations and automated validation, run the included Bash verification utility:

```bash
chmod +x scripts/verify_stack.sh
./scripts/verify_stack.sh
```

### Verification Checks Performed:
1. **Prerequisites**: Docker Engine and Docker Compose version validation.
2. **Image Footprints**: Inspection of multi-stage optimized image sizes.
3. **Container Health**: Real-time inspection of all 5 container health checks.
4. **Network Topology**: Inspection of `slg-network` subnet and container IP bindings.
5. **Persistent Storage**: Verification of `slg_mongodb_data`, `slg_vault_data`, `slg_workspace_data`.
6. **Gateway Routing**: Verification of port 80 and 8080 listeners, reverse proxy pass, and security headers.
7. **JSON Error Validation**: Conformance testing for HTTP 413 and 502 JSON error payloads.

---

## 7. Starting the Production Stack

```bash
# 1. Setup environment configuration
cp .env.example .env

# 2. Build and launch all 5 microservices
docker-compose up -d --build

# 3. View container health status
docker-compose ps

# 4. Access Platform Interfaces:
# - Frontend Control Dashboard: http://localhost/
# - Scanner REST API:         http://localhost/api/v1/health
# - HashiCorp Vault UI:       http://localhost/vault/
# - Alternative Port:         http://localhost:8080/
```
