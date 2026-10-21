# Security Hardening Guide — Cybersecurity GRC Platform

> **Scope**: This document defines the security hardening baseline for deploying the
> Cybersecurity GRC & Compliance Management Platform in a production environment.
> Controls are mapped to NIST CSF 2.0, SOC 2 Trust Service Criteria (TSC), and
> ISO/IEC 27001:2022 Annex A where applicable.

---

## Table of Contents

1. [Secret & Credential Management](#1-secret--credential-management)
2. [Authentication & Session Security](#2-authentication--session-security)
3. [Network Security](#3-network-security)
4. [Database Hardening](#4-database-hardening)
5. [Container & Runtime Security](#5-container--runtime-security)
6. [Application Security (OWASP)](#6-application-security-owasp)
7. [Evidence Vault File Security](#7-evidence-vault-file-security)
8. [Audit Logging & Monitoring](#8-audit-logging--monitoring)
9. [Dependency Management](#9-dependency-management)
10. [Compliance-Specific Controls](#10-compliance-specific-controls)
11. [Pre-Production Security Checklist](#11-pre-production-security-checklist)

---

## 1. Secret & Credential Management

| Control | Action | Framework Ref |
|---------|--------|--------------|
| **Secret key strength** | Generate `SECRET_KEY` with `secrets.token_urlsafe(48)` (≥ 384 bits) | NIST CSF PR.AC-3 |
| **No secrets in VCS** | `.env` is in `.gitignore`; use `.env.example` as template | ISO 27001 A.8.10 |
| **Secret rotation** | Rotate `SECRET_KEY`, DB passwords, and TLS certs every 90 days | SOC 2 CC6.1 |
| **Secrets manager** | In cloud: AWS Secrets Manager / Azure Key Vault / HashiCorp Vault | SOC 2 CC6.1 |
| **Audit secret access** | Enable CloudTrail / Vault audit logs for all secret reads | NIST CSF DE.AE-2 |

```bash
# Generate a production-grade secret key
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## 2. Authentication & Session Security

| Control | Action | Framework Ref |
|---------|--------|--------------|
| **Strong passwords** | Enforce min 12 chars, complexity via frontend + backend | ISO 27001 A.9.4.3 |
| **bcrypt cost factor** | Default rounds ≥ 12 (bcrypt is already used in `app/core/security.py`) | SOC 2 CC6.1 |
| **JWT algorithm** | Use `HS256` (symmetric) or upgrade to `RS256` (asymmetric) for multi-service | NIST CSF PR.AC-7 |
| **Token expiry** | `ACCESS_TOKEN_EXPIRE_MINUTES=60`; reduce to 30 in high-security environments | SOC 2 CC6.2 |
| **Secure cookies** | `COOKIE_SECURE=true`, `COOKIE_HTTPONLY=true`, `COOKIE_SAMESITE=strict` | OWASP ASVS 3.4 |
| **Login rate limiting** | `RATE_LIMIT_LOGIN_PER_MINUTE=5` in app; also enforced at Nginx (`limit_req`) | SOC 2 CC6.7 |
| **Account lockout** | Extend rate limiter to per-username lockout after N failures | ISO 27001 A.9.4.2 |
| **MFA (future)** | Integrate TOTP (e.g., `pyotp`) for CISO/Admin roles | NIST CSF PR.AC-7 |

---

## 3. Network Security

| Control | Action | Framework Ref |
|---------|--------|--------------|
| **TLS everywhere** | Nginx terminates TLS 1.2+ (TLS 1.3 preferred) | NIST CSF PR.DS-2 |
| **HSTS** | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` | OWASP Top 10 A05 |
| **Internal network** | App + DB on `grc_internal` Docker bridge network (not internet-reachable) | ISO 27001 A.13.1 |
| **Port exposure** | Only Nginx ports 80/443 exposed; DB port 5432 is NOT exposed externally | SOC 2 CC6.6 |
| **Firewall rules** | Allow only 80, 443 inbound; block all others at cloud security group / WAF | NIST CSF PR.AC-5 |
| **WAF** | Enable AWS WAF / Cloudflare WAF OWASP Core Rule Set for public deployments | OWASP Top 10 |

---

## 4. Database Hardening

| Control | Action | Framework Ref |
|---------|--------|--------------|
| **Dedicated DB user** | `grc_user` with least privilege (`SELECT, INSERT, UPDATE, DELETE` on app tables only) | ISO 27001 A.9.2.3 |
| **No superuser** | App DB user must NOT be `postgres` or a superuser role | SOC 2 CC6.3 |
| **Strong DB password** | ≥ 24 random characters; rotated every 90 days | SOC 2 CC6.1 |
| **Connection encryption** | `sslmode=require` in `DATABASE_URL` for PostgreSQL | NIST CSF PR.DS-2 |
| **DB not internet-exposed** | PostgreSQL only on internal Docker network | ISO 27001 A.13.1 |
| **Encrypted backups** | Enable `pg_dump` + AES-256 encryption; test restore quarterly | SOC 2 A1.2 |
| **Parameterized queries** | SQLAlchemy ORM prevents raw SQL injection by design | OWASP A03 |

```bash
# PostgreSQL: create least-privilege application user
CREATE USER grc_user WITH PASSWORD 'strong_random_password';
GRANT CONNECT ON DATABASE grc_platform TO grc_user;
GRANT USAGE ON SCHEMA public TO grc_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO grc_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO grc_user;
```

---

## 5. Container & Runtime Security

| Control | Action | Framework Ref |
|---------|--------|--------------|
| **Non-root user** | App runs as `grc` system user (UID/GID via `useradd --system`) | CIS Docker Benchmark 4.1 |
| **Read-only filesystem** | Add `read_only: true` to `grc_app` service in compose (mount writable volumes) | ISO 27001 A.12.6.2 |
| **No privileged mode** | Never use `privileged: true` in docker-compose.yml | CIS Docker Benchmark 5.4 |
| **Image scanning** | Scan with `docker scout cves` or `trivy image grc_app:latest` in CI/CD | NIST CSF ID.RA-1 |
| **Minimal base image** | `python:3.12-slim` used; no full OS, no shell tools in runtime stage | ISO 27001 A.12.6.1 |
| **Resource limits** | Set `deploy.resources.limits` (CPU/Memory) to prevent DoS | SOC 2 A1.1 |
| **Secrets via env** | Use Docker secrets or external vault — NOT hardcoded in image layers | SOC 2 CC6.1 |

```yaml
# docker-compose.yml addition: resource limits + read-only FS
grc_app:
  read_only: true
  tmpfs:
    - /tmp
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 1G
```

---

## 6. Application Security (OWASP)

| OWASP Top 10 | Mitigation in Platform |
|---|---|
| **A01 Broken Access Control** | RBAC with 5 roles; `check_org_access()` enforces tenant isolation |
| **A02 Cryptographic Failures** | bcrypt password hashing; JWT HS256; HTTPS-only; SHA-256 evidence integrity |
| **A03 Injection** | SQLAlchemy ORM with parameterized queries; no raw `text()` with user input |
| **A04 Insecure Design** | Layered architecture; service/API separation; principle of least privilege |
| **A05 Security Misconfiguration** | `DEBUG=False` in prod; OpenAPI docs disabled; OWASP security headers middleware |
| **A06 Vulnerable Components** | `pip-audit` in CI; `dependabot` alerts; `trivy` image scanning |
| **A07 Auth Failures** | Rate-limited login; HttpOnly + Secure cookies; JWT expiry |
| **A08 Data Integrity Failures** | SHA-256 hash stored at upload; verified on retrieval; signed JWTs |
| **A09 Logging Failures** | `log_security_event()` for auth/CRUD events; structured JSON logs |
| **A10 SSRF** | No outbound HTTP calls; no URL-fetch APIs in current codebase |

**Security headers applied by `SecurityHeadersMiddleware`:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy` (restricted to self + Google Fonts)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

---

## 7. Evidence Vault File Security

| Control | Action | Framework Ref |
|---------|--------|--------------|
| **Extension allowlist** | Only `pdf,png,jpg,jpeg,docx,xlsx,csv,txt` accepted (no executables) | SOC 2 CC6.1 |
| **MIME validation** | Validate `content-type` header and magic bytes, not just extension | OWASP File Upload |
| **SHA-256 integrity** | Hash stored on upload; `verify_evidence_integrity()` detects tampering | SOC 2 CC9.2 |
| **No execution** | Upload directory (`/app/uploads`) has no `x` bit; served as static download only | ISO 27001 A.14.2 |
| **Antivirus scanning** | Integrate ClamAV (via `pyclamd`) on upload in high-security environments | ISO 27001 A.12.2.1 |
| **Tenant isolation** | Each file linked to `organization_id`; cross-tenant access returns 403 | SOC 2 CC6.3 |
| **Size limit** | `MAX_UPLOAD_SIZE_MB=25` prevents decompression / zip-bomb attacks | NIST CSF PR.DS-1 |

---

## 8. Audit Logging & Monitoring

| Control | Action | Framework Ref |
|---------|--------|--------------|
| **Security event logging** | `log_security_event()` captures LOGIN_SUCCESS, LOGIN_FAIL, UNAUTHORIZED_ACCESS | SOC 2 CC7.2 |
| **Immutable logs** | Ship logs to SIEM (Splunk, Elastic, CloudWatch) — not just local disk | ISO 27001 A.12.4.2 |
| **Log retention** | Retain security logs ≥ 90 days (SOC 2) / ≥ 1 year (ISO 27001) | SOC 2 CC7.2 |
| **Alerting** | Alert on: repeated LOGIN_FAIL, UNAUTHORIZED_ACCESS, anomalous upload volume | NIST CSF DE.CM-7 |
| **Structured format** | JSON log format for SIEM ingestion (already in `app/core/logging.py`) | ISO 27001 A.12.4.1 |
| **No PII in logs** | Passwords, tokens, and PII must never appear in log output | GDPR Art. 5(1)(f) |

---

## 9. Dependency Management

```bash
# Audit Python dependencies for known CVEs
pip install pip-audit
pip-audit

# Scan Docker image for OS + Python CVEs
trivy image grc_platform:latest

# Check outdated packages
pip list --outdated
```

**Recommended CI/CD gates:**
- Block merge if `pip-audit` finds HIGH/CRITICAL CVEs
- Weekly `dependabot` pull requests for dependency updates
- Monthly base image rebuild (`python:3.12-slim` digest pinning)

---

## 10. Compliance-Specific Controls

### SOC 2 Type II Readiness
- **CC6**: All access is role-gated; tenant isolation enforced; evidence integrity hashed
- **CC7**: Security event logging; anomaly alerting hooks
- **CC9**: Risk assessment module with 5x5 matrix and treatment workflows
- **A1**: Resource limits in Docker; backups defined; readiness probe at `/api/ready`

### ISO/IEC 27001:2022 Annex A
- **A.9** (Access Control): RBAC + bcrypt + JWT + rate limiting
- **A.12** (Operations): Logging, evidence integrity, dependency auditing
- **A.13** (Network): Internal Docker network; Nginx TLS; HSTS
- **A.14** (Development): OWASP Top 10 mitigations; parameterized queries

### NIST CSF 2.0 Function Mapping
- **IDENTIFY**: Asset inventory via control library; risk register
- **PROTECT**: RBAC; encryption; secure headers; rate limiting
- **DETECT**: Security event logging; integrity verification
- **RESPOND**: CAPA module; finding remediation workflows
- **RECOVER**: PostgreSQL backup; Docker volume persistence; Alembic migrations

---

## 11. Pre-Production Security Checklist

```
[ ] SECRET_KEY generated with secrets.token_urlsafe(48)
[ ] DEBUG=False
[ ] COOKIE_SECURE=true, COOKIE_SAMESITE=strict
[ ] DATABASE_URL uses PostgreSQL (not SQLite)
[ ] DB user has least-privilege grants only
[ ] POSTGRES_PASSWORD is ≥ 24 random characters
[ ] TLS certificate installed and HSTS header active
[ ] OpenAPI docs (/api/docs) returns 404 in production
[ ] App container runs as non-root user 'grc'
[ ] Docker image scanned with trivy/docker scout — no CRITICAL CVEs
[ ] pip-audit reports no HIGH/CRITICAL vulnerabilities
[ ] Evidence upload directory not web-browsable
[ ] Login rate limiting tested (5 attempts → 429)
[ ] Tenant isolation tested (cross-org access → 403)
[ ] Security logs shipping to SIEM
[ ] PostgreSQL backups automated and restore tested
[ ] All test suite passes: pytest -v (currently 64+ tests)
[ ] Regulatory disclaimer visible on all report pages
```

---

> **Legal Disclaimer**: This platform is a governance, risk, and compliance *management* tool.
> It does **not** issue official SOC 2 Type I/II examination reports, ISO 27001 certificates,
> or NIST CSF assessments. Those require engagement with an accredited auditor / certification body.
