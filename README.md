# Secret Leak Guard v2.0 - Backend, Database & Secrets Management Layer

**Secret Leak Guard v2.0** is an enterprise-grade, asynchronous static analysis and secret detection backend built with Python 3.12, Flask 3.1, MongoDB 7.0, and HashiCorp Vault 1.15.6.

---

## 1. Architecture Overview

```
                                  +---------------------------------------+
                                  |         Client / CI/CD Systems        |
                                  +---------------------------------------+
                                                     |
                                   HTTPS REST API (JWT Auth + RBAC)
                                                     v
                                  +---------------------------------------+
                                  |         Flask 3.1 REST API            |
                                  |   Rate Limiter (Flask-Limiter)        |
                                  +---------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------+
| Secure Project Ingestion Layer                                                                    |
|  [Mode 1] Archive Uploads (.zip/.tar.gz) -> Zip-Slip Canonical Path Traversal Defense             |
|  [Mode 2] Local Path                      -> Directory Traversal & Allowed Roots Validation       |
|  [Mode 3] Git URL Ingestion               -> Scheme Whitelist + Full SSRF IP Block (RFC 1918)     |
|  [Mode 4] Dockerfile                      -> Isolated Temp Workspace Allocation                   |
+---------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------+
| Parallel Scanner Orchestrator (ThreadPoolExecutor)                                               |
|  States: PENDING -> INGESTING -> SCANNING -> SCORING -> COMPLETED / FAILED                        |
|                                                                                                   |
|      +------------------+  +----------------+  +---------------+  +---------------------+         |
|      |   SecretEngine   |  |   SASTEngine   |  |   SCAEngine   |  |   ContainerEngine   |         |
|      +------------------+  +----------------+  +---------------+  +---------------------+         |
+---------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------+
| Weighted Risk Scoring & Grading Engine                                                            |
|  - Deterministic SHA-256 Fingerprint Deduplication                                                |
|  - Severity Weights: Critical=25 | High=10 | Medium=3 | Low=1 | Info=0                            |
|  - Score Bounded to [0, 100]                                                                      |
|  - Grade Thresholds: A+ (0) | A (1-10) | B (11-25) | C (26-50) | D (51-75) | F (76-100)           |
+---------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------+
| Strict Credential Redaction Barrier (redact_secret: Preserves only first 4 chars)                 |
|  - Database Boundary | Application Log Streams | API Response JSON Payloads                       |
+---------------------------------------------------------------------------------------------------+
                            |                                            |
                            v                                            v
+---------------------------------------+      +---------------------------------------------------+
|   MongoDB 7.0 Persistence & Indexing  |      |   HashiCorp Vault 1.15.6 (KV-v2 Secrets Engine)   |
|   - Compound & Unique Indexes         |      |   - Dynamic Secret Leasing & Lease Renewal        |
|   - TTL Expiration Indexes            |      |   - Secret Rotation Helpers                       |
|   - Collections: scan_reports,        |      |   - Local Dev / Offline Fallback Mode             |
|     fingerprints, metrics, users      |      +---------------------------------------------------+
+---------------------------------------+
```

---

## 2. Directory Structure

```
.
├── requirements.txt              # Production and testing dependencies
├── config.py                     # Environment & runtime configuration profiles
├── run.py                        # Application entrypoint
├── .env.example                  # Template for environment variables
├── app/
│   ├── __init__.py               # Flask application factory, error handling, logging
│   ├── auth.py                   # PyJWT, bcrypt, RBAC decorators (@require_auth, @require_role)
│   ├── db.py                     # MongoDB 7.0 client, compound & TTL indexes, mongomock fallback
│   ├── ingestion.py              # 4 Ingestion modes, canonical Zip-Slip defense, SSRF IP blocker
│   ├── redactor.py               # Centralized redaction utility (first 4 chars), log filter
│   ├── routes.py                 # REST API endpoints (/api/v1/auth, /api/v1/scans, /api/v1/health)
│   ├── scanner_orchestrator.py   # ThreadPoolExecutor concurrency, state machine, lifecycle
│   ├── scoring.py                # Weighted risk scoring, SHA-256 fingerprinting, grading
│   ├── vault_client.py           # HashiCorp Vault hvac KV-v2 integration with fallback
│   └── engines/                  # Modular static analysis engine interfaces
│       ├── __init__.py
│       ├── base.py               # BaseEngine abstract class and finding models
│       ├── secret_engine.py      # Secret scanner (AWS, GitHub, Slack, Private Keys)
│       ├── sast_engine.py        # SAST scanner (Command Injection, SQLi, Insecure Deserialization)
│       ├── sca_engine.py         # SCA dependency scanner (requirements.txt, package.json)
│       └── container_engine.py   # Container & Dockerfile security analyzer
└── tests/
    ├── __init__.py
    ├── conftest.py               # Pytest fixtures, test users, tokens, isolated workspaces
    ├── test_auth_rbac.py         # Auth, registration, login, RBAC permission tests
    ├── test_db.py                # MongoDB indexing, TTL expiration, redaction persistence
    ├── test_ingestion.py         # Zip-Slip, Tar-Slip, Path traversal, and SSRF private IP tests
    ├── test_orchestrator.py      # Parallel engine concurrency, state transitions, cleanup
    ├── test_redactor.py          # Strict redaction tests (first 4 chars, logs, nested dicts)
    ├── test_routes_api.py        # REST API integration tests (submission, polling, results)
    ├── test_scoring.py           # Scoring weights, boundary tests, 20-finding / Grade F test
    └── test_vault_client.py      # Vault KV-v2, lease renewal, rotation, and fallback tests
```

---

## 3. Core Functional & Security Specifications

### 3.1 Security Ingestion & Defensive Controls
1. **Archive Ingestion (Zip-Slip & Tar-Slip Prevention)**:
   - Every archive member canonical path is verified using `os.path.realpath`.
   - Guaranteed that `os.path.commonpath([dest_dir, target_path]) == dest_dir` and `target_path.startswith(dest_dir + os.sep)`.
   - Members containing relative traversal (`../../evil.sh`), absolute paths (`/etc/passwd`), or symlink escapes trigger `ZipSlipError` and are rejected before any disk write.
2. **Local Path Ingestion**:
   - Validates that target paths are within `ALLOWED_LOCAL_SCAN_PATHS` whitelist.
   - Rejects directory traversal, null-byte injections, and paths pointing outside permitted directories.
3. **Git URL Ingestion (Anti-SSRF Protection)**:
   - Validates scheme: strictly `https://` (blocks `http://`, `file://`, `ssh://`, `git://`, `ftp://`).
   - Resolves target hostnames via `socket.getaddrinfo`.
   - Inspects all resolved IPv4 and IPv6 addresses against `ipaddress`:
     - Blocks **RFC 1918 Private Ranges** (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
     - Blocks **Loopback & Sub-loopback** (`127.0.0.0/8`, `::1`).
     - Blocks **Cloud Metadata & Link-Local** (`169.254.169.254`, `fe80::/10`, `metadata.google.internal`).
     - Blocks **IPv4-Mapped IPv6** (`::ffff:127.0.0.1`, `::ffff:10.0.0.1`).
     - Blocks **Multicast & Reserved** ranges (`224.0.0.0/4`, `fc00::/7`).
4. **Dockerfile Submission**:
   - Isolates content in ephemeral workspaces.
5. **Workspace Cleanup**:
   - Automatically purges workspaces inside a `finally` block upon job completion or failure.

### 3.2 Concurrency & Asynchronous Job Lifecycle
- Implements `ThreadPoolExecutor` to run the 4 security engines concurrently per scan job.
- Tracks discrete lifecycle states:
  - `PENDING`: Scan registered and queued.
  - `INGESTING`: Workspace created; archive extracted, git cloned, or Dockerfile parsed.
  - `SCANNING`: 4 engines (`SecretEngine`, `SASTEngine`, `SCAEngine`, `ContainerEngine`) executing in parallel.
  - `SCORING`: Findings deduplicated via SHA-256 fingerprint; score and grade assigned.
  - `COMPLETED`: Results sanitized, redacted, and saved in MongoDB.
  - `FAILED`: Ingestion or scanning error trapped, logged, and recorded.

### 3.3 Strict Credential Redaction
- Centralized `redact_secret(value)` utility preserves **only the first 4 characters**:
  - Example: `AKIA[20-CHAR-KEY]` (length 20) $\rightarrow$ `AKIA****************`
  - Example: `ghp_[40-CHAR-PAT]` $\rightarrow$ `ghp_********************`
  - Values of length $\le 4$ are masked completely (`****`).
- Enforced at **every data boundary**:
  1. **MongoDB Database Persistence**: Findings are redacted before `save_scan_report` and `record_finding_fingerprints`.
  2. **Application Logs**: `RedactingFormatter` and `RedactingFilter` scrub all outgoing log messages.
  3. **REST API JSON Responses**: Endpoints automatically sanitize dictionaries before returning HTTP responses.

### 3.4 Weighted Risk Scoring & Grading
- **Deduplication**: Findings are deduplicated by deterministic SHA-256 fingerprint:
  $$\text{Fingerprint} = \text{SHA256}(\text{rule\_id} : \text{file\_path} : \text{line\_number} : \text{evidence})$$
- **Severity Weights**:
  - **Critical**: 25 points
  - **High**: 10 points
  - **Medium**: 3 points
  - **Low**: 1 point
  - **Info**: 0 points
- **Score Capping**:
  $$\text{Final Score} = \min(100, \max(0, \text{Raw Score}))$$
- **Grade Scale**:
  - **A+**: 0 points
  - **A**: 1–10 points
  - **B**: 11–25 points
  - **C**: 26–50 points
  - **D**: 51–75 points
  - **F**: 76–100 points (e.g. 20 High findings = $20 \times 10 = 200 \rightarrow 100/100$ = **Grade F**)

### 3.5 MongoDB 7.0 Persistence & Indexing
- **Collections**:
  - `scan_reports`: Stores scan reports, metadata, scores, grade, and redacted findings.
  - `finding_fingerprints`: Deduplicated tracking with `occurrence_count`, `first_seen`, `last_seen`.
  - `project_configs`: Project metadata and scan options.
  - `historical_metrics`: Historical score trajectories over time.
  - `users`: User credentials and roles.
- **Indexes**:
  - Unique Index on `scan_reports.job_id`.
  - Compound Index on `scan_reports(project_id, created_at DESC)`.
  - Compound Unique Index on `finding_fingerprints(project_id, fingerprint)`.
  - **TTL Index**: Automatic expiration index on `expires_at` (`expireAfterSeconds=0`).

### 3.6 HashiCorp Vault 1.15.6 Integration
- Uses `hvac` with the KV-v2 engine (`client.secrets.kv.v2`).
- Stores JWT signing keys, MongoDB connection URIs, and API tokens.
- Supports dynamic leasing, lease renewal (`renew_lease`), and secret rotation (`rotate_secret`).
- Graceful offline fallback: Falls back to environment variables when Vault is unavailable.

---

## 4. REST API Reference

### Authentication Endpoints
| Method | Endpoint | Description | Permitted Roles |
|---|---|---|---|
| `POST` | `/api/v1/auth/register` | Register user account | Public / Admin |
| `POST` | `/api/v1/auth/login` | Authenticate & retrieve JWT | Public |
| `GET` | `/api/v1/auth/me` | Current user details | All authenticated |

### Scan Management Endpoints
| Method | Endpoint | Description | Permitted Roles |
|---|---|---|---|
| `POST` | `/api/v1/scans` | Submit a scan job | `admin`, `analyst` |
| `GET` | `/api/v1/scans/<job_id>/status` | Poll job execution status | `admin`, `analyst`, `viewer` |
| `GET` | `/api/v1/scans/<job_id>/results` | Retrieve final report & grade | `admin`, `analyst`, `viewer` |
| `GET` | `/api/v1/scans` | List scan history | `admin`, `analyst`, `viewer` |

### System & Metrics Endpoints
| Method | Endpoint | Description | Permitted Roles |
|---|---|---|---|
| `GET` | `/api/v1/health` | System health check (DB & Vault) | Public |
| `GET` | `/api/v1/projects/<id>/metrics` | Historical posture metrics | `admin`, `analyst`, `viewer` |
| `POST` | `/api/v1/vault/rotate-secret` | Trigger secret rotation | `admin` |

---

## 5. Verification & Test Suite

All 85 automated test cases run with `pytest`:

```bash
python -m pytest -v
```

### Test Coverage Summary:
- **`tests/test_scoring.py`**: Severity weight constants, grade boundaries (A+, A, B, C, D, F), 20-finding / 100-score / Grade F validation, SHA-256 fingerprint deduplication, cross-platform path normalization.
- **`tests/test_redactor.py`**: Strict 4-character prefix preservation (`AKIA****************`), token masks, recursive dictionary & list sanitization, finding record redaction, logging filter scrub.
- **`tests/test_ingestion.py`**: Zip-Slip relative path traversal attacks blocked, Tar-Slip attacks blocked, local directory traversal blocked, non-https schemes blocked, 12 private/loopback/cloud-metadata IPs blocked by SSRF, safe Dockerfile extraction, workspace cleanup.
- **`tests/test_auth_rbac.py`**: Bcrypt hashing & verification, JWT claim generation and decoding, role-based access control (Admin, Analyst, Viewer), permission matrix enforcement.
- **`tests/test_db.py`**: Compound index verification, TTL index creation, automatic redaction before persistence, fingerprint tracking, historical metrics storage.
- **`tests/test_vault_client.py`**: Vault KV-v2 read/write, dynamic lease renewal, rotation helpers, local environment fallback.
- **`tests/test_orchestrator.py`**: ThreadPoolExecutor parallel scan across all 4 engines, lifecycle state transitions, automatic workspace cleanup, failure state handling.
- **`tests/test_routes_api.py`**: Health endpoint, archive upload scan workflow, Dockerfile scan workflow, status polling, result retrieval, raw secret leak absence verification, RBAC permissions.
