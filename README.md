# Cybersecurity GRC & Compliance Management Platform
### Cross-Framework Governance, Risk Assessment & Control Management
**SOC 2 (TSC) &bull; ISO/IEC 27001:2022 &bull; NIST Cybersecurity Framework (CSF) 2.0**

---

## 1. Executive Summary & Objectives

The **Cybersecurity GRC & Compliance Management Platform** is an enterprise-grade platform built to help cybersecurity engineers, compliance analysts, risk officers, and auditors understand, compare, assess, and manage security controls across the industry's three leading cybersecurity and compliance standards:

1. **SOC 2 (AICPA Trust Services Criteria)**
2. **ISO/IEC 27001:2022 (ISMS & Annex A)**
3. **NIST Cybersecurity Framework (CSF) 2.0**

### Regulatory and Assurance Disclaimer
> **Important Note on Assurance Scope:**
> This platform assists organizations with internal readiness assessment, control mapping, risk quantification, and audit preparation.
> - **NIST CSF 2.0 is a voluntary risk-based framework and does not confer official certification.**
> - This platform **does not** issue official SOC 2 Type I/II examination reports (which require an independent CPA audit) or ISO/IEC 27001 certificates (which require an accredited third-party registrar).
> - Mappings and evidence hashes represent proposed operational relationships and integrity markers—they do not replace auditor professional judgment.

---

## 2. Framework Triad: Scope, Differences, and Overlaps

| Dimension | SOC 2 (AICPA) | ISO/IEC 27001:2022 | NIST CSF 2.0 |
| :--- | :--- | :--- | :--- |
| **Issuing Body** | AICPA (American Institute of CPAs) | ISO & IEC (International) | NIST (U.S. Dept of Commerce) |
| **Primary Scope** | Customer data security & trust for service organizations | Holistic Information Security Management System (ISMS) | Critical infrastructure & enterprise cybersecurity risk |
| **Core Structure** | 5 Trust Services Criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy) | Clauses 4–10 (Management system) + Annex A (93 controls in 4 themes) | 6 Core Functions (Govern, Identify, Protect, Detect, Respond, Recover) |
| **Assurance Type** | Independent CPA Attestation Report (Type I point-in-time / Type II period-of-time) | Accredited Third-Party Certification (3-year validity with annual surveillance) | Voluntary Self-Assessment / Implementation Tiers (1 to 4) |
| **Typical Use Case** | B2B SaaS and cloud vendors proving security to enterprise buyers | Global organizations establishing formal security governance and customer trust | Organizations structuring or benchmarking their cybersecurity posture |

---

## 3. Architecture & Technology Stack

The platform is engineered using modern, modular clean-architecture principles:

```
                    +--------------------------------------------+
                    |             Presentation Layer             |
                    |   Semantic HTML5, Jinja2 Templates,        |
                    |   Vanilla CSS Design System (Glassmorphic) |
                    |   Vanilla JS Real-Time Telemetry Client    |
                    +---------------------+----------------------+
                                          |
                                          v
                    +--------------------------------------------+
                    |             Application Layer              |
                    |   FastAPI ASGI Engine (Async I/O)          |
                    |   Pydantic v2 Schema Validation            |
                    |   OWASP Security Headers Middleware        |
                    |   Role-Based Access Control (RBAC)         |
                    |   Structured Security Audit Event Logger   |
                    +---------------------+----------------------+
                                          |
                                          v
                    +--------------------------------------------+
                    |              Data / ORM Layer              |
                    |   SQLAlchemy 2.x Declarative Models        |
                    |   Alembic Migration Engine                 |
                    |   Multi-Tenant Organization Filtering      |
                    |   Dual-Engine: SQLite (Dev) / Postgres (Prod)|
                    +---------------------+----------------------+
                                          |
                                          v
                    +--------------------------------------------+
                    |           Storage & Evidence Vault         |
                    |   Private Quarantined File Storage         |
                    |   SHA-256 Tamper Detection & Checksum      |
                    |   MIME-Type & Extension Allowlisting       |
                    +--------------------------------------------+
```

---

## 4. STRIDE Threat Model (GRC Platform Specific)

Because a GRC platform stores an enterprise's most sensitive vulnerabilities, control gaps, and audit records, it is an attractive target for adversaries. We have designed the system around the **STRIDE** methodology:

| Threat Category | Specific Threat in GRC Platform | Architectural Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates an auditor, control owner, or administrator | Secure session management, bcrypt/argon2 password hashing, HttpOnly SameSite cookies. |
| **Tampering** | Rogue actor alters audit test results or swaps uploaded evidence | Evidence files hashed with SHA-256 upon ingestion; append-only audit event logs for all state transitions. |
| **Repudiation** | User denies closing an unresolved audit finding or accepting a risk | Structured security event logger (`log_security_event`) captures actor, timestamp, client IP, resource, and before/after diff. |
| **Information Disclosure** | Cross-tenant data leakage between organizations | Strict organization ID scoping enforced in all database queries; gated access to evidence downloads. |
| **Denial of Service** | File upload bombs exhausting disk storage; auth brute force | Strict upload limits (10 MB max), file extension whitelisting, rate limiting on sensitive endpoints. |
| **Elevation of Privilege** | Read-only auditor or control owner attempts administrative action | Server-side RBAC dependencies evaluated on every route; no client-side role trust. |

---

## 5. 10-Phase Implementation Plan

- **Phase 1: Foundation (Completed)** &mdash; Project setup, Pydantic settings, security headers, logging, health endpoints, and automated tests.
- **Phase 2: Database Schema & Seeds** &mdash; SQLAlchemy 2.x normalized models (Organizations, Frameworks, Controls, Risks, Evidence, Tests, Findings), Alembic migrations, initial framework seed data.
- **Phase 3: Authentication & Multi-Tenant Isolation** &mdash; 5 user roles, session auth, password hashing, tenant data boundary enforcement.
- **Phase 4: Framework Comparison & Control Library** &mdash; Detailed multi-framework comparison view and centralized security control catalog.
- **Phase 5: Framework Mappings & Compliance Assessments** &mdash; Cross-framework mapping, reviewer approval workflow, and 6-state compliance gap analysis.
- **Phase 6: Risk Register & Treatment** &mdash; Risk matrix, 5x5 Likelihood/Impact calculator, inherent vs. residual risk, and treatment workflows.
- **Phase 7: Evidence Vault & Control Testing** &mdash; Secure file upload, SHA-256 validation, testing objectives, test execution, and pass/fail logging.
- **Phase 8: Audit Findings & Corrective Action Plans (CAPA)** &mdash; Severity classification, root-cause tracking, owner assignment, retesting, and closure sign-off.
- **Phase 9: Dashboards & Readiness Reporting** &mdash; Executive compliance scorecards, risk heatmaps, evidence review queues, and exportable audit reports.
- **Phase 10: Security Hardening & Job Interview Masterclass** &mdash; Automated test suite, Docker configuration, and 30+ scenario-based GRC interview Q&A guide.

---

## 6. Phase 1 Quickstart (Windows PowerShell)

### Prerequisites
- Python 3.12+ (or Python 3.13)
- Windows PowerShell

### Step 1: Create and Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Run Phase 1 Automated Tests
```powershell
pytest tests/test_phase1.py -v
```

Expected output:
```
tests/test_phase1.py::test_health_check_endpoint PASSED
tests/test_phase1.py::test_readiness_check_endpoint PASSED
tests/test_phase1.py::test_security_headers_applied PASSED
tests/test_phase1.py::test_root_index_page PASSED
tests/test_phase1.py::test_settings_properties PASSED
tests/test_phase1.py::test_security_audit_logger PASSED
tests/test_phase1.py::test_api_not_found_returns_json PASSED
7 passed in 0.05s
```

### Step 4: Launch the Local Development Server
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Navigate in your browser to:
- **Web Interface:** `http://127.0.0.1:8000/`
- **Interactive OpenAPI Documentation:** `http://127.0.0.1:8000/api/docs`
- **Health Check Endpoint:** `http://127.0.0.1:8000/api/health`
- **Readiness Check Endpoint:** `http://127.0.0.1:8000/api/ready`
