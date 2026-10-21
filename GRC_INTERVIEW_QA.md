# GRC Platform — Cybersecurity & Compliance Interview Q&A Guide

> 50 senior-level interview questions with model answers covering SOC 2, ISO 27001,
> NIST CSF 2.0, GRC platform architecture, application security, and Python/FastAPI.
> Intended for: GRC Engineers, Security Architects, Compliance Managers, and AppSec Leads.

---

## Part 1: Framework Fundamentals (Q1–Q15)

---

**Q1. What are the five SOC 2 Trust Service Criteria (TSC) and which is mandatory?**

> **A:** The five TSC are: **Security** (Common Criteria — CC), **Availability** (A),
> **Confidentiality** (C), **Processing Integrity** (PI), and **Privacy** (P).
> **Security is the only mandatory criterion.** The others are included based on the
> commitments made in the service organization's system description.

---

**Q2. What is the difference between SOC 2 Type I and Type II?**

> **A:** A **Type I** report assesses whether controls are *suitably designed* as of a
> specific point in time — essentially a design review. A **Type II** report covers a
> *minimum 6-month observation period* and tests whether controls were *operating
> effectively* throughout that period. Type II is significantly more rigorous and is the
> standard requested by enterprise customers.

---

**Q3. What are the key differences between ISO 27001:2013 and ISO 27001:2022?**

> **A:** ISO 27001:2022 restructured Annex A from 114 controls across 14 domains to
> **93 controls across 4 themes** (Organizational, People, Physical, Technological).
> It introduced 11 new controls including threat intelligence, cloud security, data masking,
> and secure coding. The 2022 revision also aligns with the ISO High-Level Structure for
> consistency with ISO 9001 and ISO 22301.

---

**Q4. Explain the NIST CSF 2.0 structure and what's new compared to CSF 1.1.**

> **A:** CSF 2.0 introduced a **6th Function: GOVERN (GV)** — covering risk governance,
> supply chain risk, and roles & responsibilities. The original 5 functions remain:
> Identify, Protect, Detect, Respond, Recover. CSF 2.0 also expanded supply chain risk
> management (C-SCRM), added implementation tiers guidance, and made the framework
> applicable beyond critical infrastructure to *all* organizations.

---

**Q5. How do SOC 2, ISO 27001, and NIST CSF relate to each other? Can achieving one help with the others?**

> **A:** They share a large common control set. **NIST CSF** is a voluntary risk management
> framework — it maps directly to many ISO 27001 Annex A controls and SOC 2 CC controls.
> **ISO 27001** is a certifiable management system standard. **SOC 2** is a third-party
> audit attestation. An organization that implements ISO 27001 will satisfy 70–80% of
> SOC 2 CC controls. NIST CSF can serve as a gap assessment tool for both. Our platform's
> control mapping module implements these cross-framework relationships explicitly.

---

**Q6. What is the ISMS and why is it central to ISO 27001?**

> **A:** The **Information Security Management System (ISMS)** is the systematic approach
> defined in ISO 27001 Clauses 4–10 for establishing, implementing, maintaining, and
> continually improving information security. It is process-based (Plan-Do-Check-Act),
> risk-driven, and requires documented scope, risk assessment methodology, Statement of
> Applicability (SoA), and management commitment. The ISMS is the *certification scope*
> — Annex A controls support it.

---

**Q7. What is a Statement of Applicability (SoA) and what must it contain?**

> **A:** The SoA (required by ISO 27001 Clause 6.1.3) is a document listing all Annex A
> controls with: (1) whether each control is *applicable or excluded*, (2) the *justification*
> for inclusion/exclusion, and (3) whether the control is *implemented*. Exclusions require
> documented justification showing the residual risk is accepted. The SoA is a key artifact
> auditors review during certification.

---

**Q8. Describe the NIST CSF Tiers. How do they differ from maturity models?**

> **A:** CSF Tiers (Partial → Risk Informed → Repeatable → Adaptive) describe the *rigor
> and sophistication* of an organization's cybersecurity risk management practices — not
> a maturity score. Unlike CMMI maturity levels, Tiers are contextual: an organization
> might intentionally operate at Tier 2 in low-criticality areas. The goal isn't always
> Tier 4; it's the *appropriate tier* for the organization's risk profile and business needs.

---

**Q9. What are SOC 2 Common Criteria (CC) 6.1 through 6.8 about?**

> **A:** CC6 covers **Logical and Physical Access Controls**:
> - CC6.1: Logical access controls (authentication, authorization)
> - CC6.2: Prior to issuing credentials (provisioning process)
> - CC6.3: Role-based access, least privilege
> - CC6.4: Access removal (offboarding)
> - CC6.5: Physical access controls
> - CC6.6: System boundary protection (firewalls, network segmentation)
> - CC6.7: Encryption, secure transmission
> - CC6.8: Malware and vulnerability management

---

**Q10. What is the difference between a risk assessment and a risk treatment plan?**

> **A:** A **risk assessment** identifies, analyzes, and evaluates risks — producing a risk
> register with likelihood × impact scores. A **risk treatment plan** documents the chosen
> treatment option for each risk: **Mitigate** (implement controls), **Accept** (document
> acceptance), **Transfer** (insurance, contracts), or **Avoid** (stop the activity). ISO 27001
> requires both; the treatment plan must be approved by risk owners. Our platform implements
> the full 5×5 risk matrix with treatment workflows.

---

**Q11. What is a compensating control and when is it appropriate?**

> **A:** A compensating control is an alternative control that achieves the same security
> objective when the primary control cannot be implemented (due to technical, operational,
> or business constraints). For example, if MFA cannot be deployed on a legacy system,
> a compensating control might be network segmentation + enhanced monitoring. PCI DSS
> formalizes compensating controls; SOC 2 auditors assess whether they provide equivalent
> risk reduction. They must be documented and periodically re-evaluated.

---

**Q12. Explain the concept of continuous controls monitoring (CCM). How does it differ from point-in-time audits?**

> **A:** **Point-in-time audits** sample evidence at specific intervals (quarterly/annually)
> — leaving gaps where control failures go undetected. **CCM** uses automated tooling
> (SIEM, CASB, configuration scanners) to continuously validate control operation, alerting
> on deviations in near-real-time. CCM supports SOC 2 Type II's "throughout the period"
> requirement and is the foundation of modern GRC platforms replacing spreadsheet-based
> compliance.

---

**Q13. What is the role of a GRC platform in a security program?**

> **A:** A GRC platform centralizes: (1) **Governance** — policy management, frameworks,
> accountability structures; (2) **Risk** — risk register, scoring, treatment tracking;
> (3) **Compliance** — control mapping, gap assessments, audit evidence management,
> findings, and CAPA workflows. It replaces fragmented spreadsheets, reduces audit fatigue
> via control reuse across frameworks, and provides executive dashboards for leadership
> visibility.

---

**Q14. What does "audit readiness" mean and how is it measured?**

> **A:** Audit readiness is the degree to which an organization can demonstrate effective
> control operation to a third-party auditor without emergency preparation. It is measured
> by: control testing completion %, evidence coverage %, open finding age, and CAPA
> closure rate. Our platform's executive report aggregates these into a readiness score
> (0–100%) per framework with RAG status.

---

**Q15. What is the difference between vulnerability management and risk management?**

> **A:** **Vulnerability management** is operational: scanning, patching, and remediating
> known technical weaknesses (CVEs) in systems. **Risk management** is strategic: it
> considers threats, asset value, likelihood, and business impact to prioritize investments.
> A critical CVE on an internet-facing payment server represents a *high risk*; the same CVE
> on an air-gapped test system may be *low risk*. GRC platforms connect both: a vulnerability
> can trigger a risk record and associated corrective actions.

---

## Part 2: Application Security & Architecture (Q16–Q30)

---

**Q16. Why does this platform use bcrypt instead of SHA-256 for password hashing?**

> **A:** SHA-256 is a fast cryptographic hash — it can process billions of guesses/second
> on modern GPU hardware, making brute-force feasible. **Bcrypt** is a *slow, adaptive*
> password hashing function with a configurable cost factor. At cost=12, bcrypt takes ~250ms
> per hash, reducing brute-force to hundreds of guesses/second. It also incorporates a salt
> by design, preventing rainbow table attacks. OWASP recommends bcrypt, scrypt, or Argon2id
> for password storage.

---

**Q17. Explain JWT-based session management. What are its security tradeoffs versus server-side sessions?**

> **A:** **JWTs** are stateless: the server signs a token containing claims; the client
> presents it on every request. Pros: horizontal scalability (no shared session store),
> fast validation. Cons: tokens cannot be invalidated before expiry without a revocation
> list (blacklist/Redis). **Server-side sessions** (cookie + session store) allow instant
> revocation and reduce client-visible data exposure. For a GRC platform, short expiry
> (60 min) + HttpOnly/Secure cookies mitigate JWT risks. Adding a Redis-based token
> blacklist is a recommended production enhancement.

---

**Q18. What is multi-tenancy and how is it implemented in this platform?**

> **A:** Multi-tenancy means multiple organizations (tenants) share one application
> instance with strict data isolation. Our platform implements **row-level tenancy** via
> `organization_id` foreign keys on every data model. The `check_org_access()` function
> in `app/core/auth.py` raises `403 Forbidden` if a user's `organization_id` doesn't match
> the requested resource. Platform admins can access all tenants; org-scoped roles
> (Org Admin, GRC Analyst, Auditor, Viewer) are limited to their own organization's data.

---

**Q19. What OWASP Top 10 risks does this platform address and how?**

> **A:**
> - **A01 Broken Access Control**: RBAC with `require_role()` + `check_org_access()` tenant isolation
> - **A02 Cryptographic Failures**: bcrypt + JWT + SHA-256 file integrity + HTTPS-only
> - **A03 Injection**: SQLAlchemy ORM with parameterized queries throughout
> - **A05 Security Misconfiguration**: `DEBUG=False` + disabled OpenAPI in prod + OWASP headers
> - **A07 Auth Failures**: Rate-limited login + HttpOnly/Secure/SameSite cookies + JWT expiry
> - **A08 Data Integrity Failures**: SHA-256 hash on evidence upload, verified on retrieval
> - **A09 Logging Failures**: Structured `log_security_event()` for all auth and CRUD events

---

**Q20. What security headers does the platform apply and what does each prevent?**

> **A:**
> - `X-Content-Type-Options: nosniff` — Prevents MIME-type sniffing (browser executing JS as HTML)
> - `X-Frame-Options: DENY` — Prevents clickjacking via iframe embedding
> - `X-XSS-Protection: 1; mode=block` — XSS filter for legacy IE/Edge browsers
> - `Referrer-Policy: strict-origin-when-cross-origin` — Prevents leaking internal URLs via Referer header
> - `Content-Security-Policy` — Restricts script/style/font sources to self + Google Fonts, prevents XSS
> - `Permissions-Policy` — Blocks hardware API access (camera, mic, geolocation, payment)
> - `Strict-Transport-Security` (Nginx) — Forces HTTPS for 1 year, prevents SSL stripping

---

**Q21. How does SHA-256 evidence integrity verification work in the platform?**

> **A:** When evidence is uploaded (`POST /api/v1/evidence/upload`), the platform reads the
> file bytes and computes `hashlib.sha256(content).hexdigest()`. This hash is stored in the
> `sha256_hash` column of the `EvidenceFile` record. On every retrieval, `verify_evidence_integrity()`
> re-hashes the file on disk and compares to the stored hash. If they differ (file tampered,
> corrupted, or substituted), the API returns a `409 Conflict` with a tamper alert. This
> provides a cryptographic chain of custody for audit evidence.

---

**Q22. Explain the role-based access control (RBAC) model. What are the 5 roles?**

> **A:**
> 1. **Platform Admin** — Full system access across all organizations (SaaS operator)
> 2. **Org Admin** — Full CRUD within their organization; user management
> 3. **GRC Analyst** — Create/update controls, risks, assessments, evidence; close findings
> 4. **Auditor** — Read-only access to all data + ability to raise and sign off findings
> 5. **Viewer** — Read-only access to dashboards and reports
>
> Role hierarchy: Platform Admin > Org Admin > GRC Analyst > Auditor > Viewer.
> `require_role()` enforces minimum role level; `check_org_access()` enforces tenant isolation.

---

**Q23. What is rate limiting and how is it implemented at multiple layers in this platform?**

> **A:** Rate limiting prevents brute-force login attacks and API abuse.
> - **Application layer**: `InMemoryRateLimiter` in `app/core/rate_limit.py` — tracks login
>   attempts per IP using a sliding window; raises `429 Too Many Requests` after 5 attempts/minute
> - **Nginx layer**: `limit_req_zone` + `limit_req` directive rate-limits the `/api/v1/auth/login`
>   endpoint at the reverse proxy before requests reach the application
> - Defense-in-depth: both layers must be defeated independently, significantly raising the cost
>   of any brute-force attack.

---

**Q24. Why is `DEBUG=False` critical in production and what does it affect?**

> **A:** In FastAPI, `DEBUG=True` with `docs_url` enabled exposes:
> - `/api/docs` — Swagger UI (interactive API explorer)
> - `/api/redoc` — ReDoc documentation
> - `/api/openapi.json` — Full API schema (reveals all endpoints, parameters, models)
> This intelligence aids attackers in mapping the attack surface. Our platform conditionally
> sets `docs_url=None` when `DEBUG=False`, completely disabling these. Additionally, debug
> mode in Python frameworks can expose stack traces, internal variable values, and other
> sensitive diagnostics in HTTP error responses.

---

**Q25. What is the purpose of Alembic in this project?**

> **A:** **Alembic** is SQLAlchemy's database migration tool. It tracks schema changes as
> versioned migration scripts (in `alembic/versions/`), allowing controlled, repeatable
> schema evolution across environments. Key operations: `alembic upgrade head` (apply all
> pending migrations), `alembic revision --autogenerate` (generate migration from model diff),
> `alembic downgrade -1` (rollback one version). This is critical for compliance databases
> where schema changes must be auditable and reversible without data loss.

---

**Q26. How does the multi-stage Docker build improve security?**

> **A:** The **builder stage** contains `gcc`, `make`, and build tools — necessary to compile
> native Python wheels (e.g., cryptography, psycopg2). The **runtime stage** copies only the
> compiled virtual environment, with no build tools present. This means:
> - Attack surface is dramatically reduced (no compiler for exploitation)
> - Image size is 60–70% smaller
> - No accidental inclusion of build secrets or intermediate files
> - Container escape scenarios have fewer privilege escalation tools available

---

**Q27. What is tenant isolation bypass and how do you test for it?**

> **A:** A tenant isolation bypass (also called IDOR — Insecure Direct Object Reference)
> occurs when a user of Org A can access or modify data belonging to Org B by manipulating
> IDs in API requests. Testing approach:
> 1. Create users in two separate organizations (e.g., org_id=1 and org_id=2)
> 2. Log in as Org A user; attempt `GET /api/v1/risks/?org_id=2`
> 3. Expect `403 Forbidden`; a `200 OK` with Org B data = vulnerability
> Our `test_phase6_risks.py` and `test_phase7_evidence_testing.py` include cross-tenant
> isolation tests that validate this boundary.

---

**Q28. Explain the CAPA workflow and its significance for compliance.**

> **A:** **Corrective and Preventive Action (CAPA)** is a structured remediation process.
> In our platform: (1) an audit finding is raised with severity and root cause; (2) a
> CAPA record is created with responsible owner and due date; (3) remediation steps are
> documented; (4) evidence of fix is uploaded; (5) a GRC Analyst or Auditor performs
> closure sign-off and verification. For SOC 2, CAPA demonstrates that the organization
> detects, investigates, and remediates control failures — directly evidencing CC7.3 (incident
> response) and CC9.1 (risk mitigation).

---

**Q29. What is the difference between a control test and a risk assessment?**

> **A:** A **control test** evaluates whether a specific security control is operating
> effectively — e.g., testing whether MFA is actually enforced on admin accounts. It produces
> a pass/fail result with evidence. A **risk assessment** evaluates the overall likelihood
> and impact of a threat scenario materializing — it considers whether controls reduce the
> residual risk to an acceptable level. Control test results *feed into* risk assessments:
> a failing control increases the likelihood score of associated risks.

---

**Q30. How does the executive readiness report aggregate data from all modules?**

> **A:** The `ReportService.generate_readiness_report()` in `app/services/report_service.py`
> queries: (1) compliance assessment scores per framework; (2) risk register statistics
> (open/treated/accepted risks + risk reduction %); (3) evidence vault stats (files uploaded,
> integrity verified); (4) control testing results (pass/fail/untested counts); (5) audit
> findings (open/overdue CAPA items). These are normalized into a 0–100 readiness score
> with RAG status (Green ≥70, Amber 40–69, Red <40) and surfaced as a printable executive
> report with Markdown export.

---

## Part 3: Advanced GRC & Security Topics (Q31–Q50)

---

**Q31. What is the difference between inherent risk and residual risk?**

> **A:** **Inherent risk** is the risk level *before* any controls are applied — the raw
> exposure if the organization did nothing. **Residual risk** is the remaining risk *after*
> controls are implemented. A well-designed control should reduce inherent risk to a residual
> risk level within the organization's risk appetite. Risk appetite statements define the
> maximum acceptable residual risk score. GRC platforms track both values to measure
> control effectiveness over time.

---

**Q32. What is a control framework mapping and why is it valuable?**

> **A:** A control framework mapping shows which controls satisfy requirements across multiple
> frameworks simultaneously. Example: a password policy control may satisfy SOC 2 CC6.1,
> ISO 27001 A.9.4.3, and NIST CSF PR.AC-7 simultaneously. Maintaining this mapping prevents
> implementing duplicate controls, reduces audit preparation effort, and provides evidence
> reuse across multiple compliance programs. Our platform's control mapping module stores
> these relationships and the `ControlMapping` model tracks which requirement each control
> addresses.

---

**Q33. What are the implications of data residency and sovereignty for a cloud-hosted GRC platform?**

> **A:** Data residency requirements (GDPR, India DPDP Act, China MLPS) may mandate that
> compliance data — including audit evidence, risk assessments, and personal data —
> remain within specific geographic boundaries. For a GRC platform: (1) cloud region must
> match data residency requirements; (2) PostgreSQL backups must be encrypted and stored
> in-region; (3) third-party integrations (SIEM, Slack, email) must be assessed for data
> transfer; (4) the platform's SoA must document data flows. Docker/K8s deployments should
> use region-locked node pools and encrypted PVCs.

---

**Q34. Explain the concept of a "shared responsibility model" in cloud GRC.**

> **A:** In IaaS/PaaS/SaaS deployments, security responsibility is divided between the
> cloud provider and the customer. AWS/Azure/GCP are responsible for physical security,
> hypervisor, and managed service availability. The customer is responsible for: OS patching
> (IaaS), application security, IAM policies, data encryption, and compliance configuration.
> For a GRC platform: the cloud provider's SOC 2 report covers their infrastructure; the
> platform operator must separately address application-layer controls. Misunderstanding
> shared responsibility is a leading cause of cloud security incidents.

---

**Q35. What is a risk appetite statement and how does it relate to risk treatment decisions?**

> **A:** A risk appetite statement is a formal declaration — approved by the board/executive —
> of the maximum level of risk the organization is willing to accept in pursuit of its
> objectives. It defines thresholds (e.g., "No high risks may remain open beyond 30 days
> without CISO approval"). Risk treatment decisions are validated against it: a residual
> risk score above the appetite threshold *must* be mitigated or escalated; risks within
> appetite may be accepted. GRC platforms enforce this by blocking "Accepted" status on
> risks exceeding a configurable score threshold.

---

**Q36. What is vendor risk management (VRM) and how would you integrate it into this platform?**

> **A:** VRM identifies, assesses, and monitors cybersecurity risks introduced by third-party
> vendors and suppliers (NIST CSF GV.SC, ISO 27001 A.5.19–A.5.22). Integration into this
> platform would involve: (1) a `Vendor` model with criticality classification; (2) vendor
> risk assessments linked to the existing risk register; (3) contract/SLA evidence uploads
> to the evidence vault; (4) vendor control questionnaire templates; (5) vendor SOC 2 report
> ingestion and expiry tracking. This aligns with NIST CSF 2.0's expanded C-SCRM guidance.

---

**Q37. How would you implement segregation of duties (SoD) in a GRC platform?**

> **A:** SoD prevents any single individual from completing a sensitive transaction end-to-end
> without oversight. In a GRC platform: (1) the **GRC Analyst** raises a risk but cannot
> self-approve closure (requires Org Admin); (2) the **Auditor** raises findings but the
> **GRC Analyst** performs CAPA and a *different* Auditor signs off; (3) evidence uploads
> require a separate reviewer; (4) the platform enforces these via role checks on state
> transition endpoints. SoD is a core SOC 2 CC6.3 and ISO 27001 A.5.3 requirement.

---

**Q38. What are the key metrics for a compliance dashboard? How do you present them to executives?**

> **A:** Key metrics for an executive compliance dashboard:
> - **Overall readiness score** (0–100%) per framework with RAG status
> - **Open high/critical risks** (count + age trend)
> - **Control testing completion %** (pass/fail/untested)
> - **Audit finding closure rate** and average time-to-remediate
> - **Overdue CAPAs** (count + ownership)
> - **Evidence vault coverage** (% of controls with linked evidence)
> - **Framework-by-framework gap %**
>
> Executive presentation: use RAG (Red/Amber/Green) traffic lights; avoid technical jargon;
> compare current vs. prior period; highlight items requiring executive decision (risk acceptance,
> resource allocation).

---

**Q39. What is the NIST Risk Management Framework (RMF) and how does it differ from NIST CSF?**

> **A:** The **NIST RMF** (SP 800-37) is a 7-step process for federal information systems:
> Prepare → Categorize → Select → Implement → Assess → Authorize → Monitor. It is
> mandatory for US federal agencies (FISMA). **NIST CSF** is a voluntary, outcome-based
> framework for any organization to manage cybersecurity risk. CSF is broader and
> business-friendly; RMF is process-prescriptive and control-specific (references SP 800-53).
> Many organizations use CSF for program management and RMF methodology for specific system
> authorizations.

---

**Q40. Explain the significance of the NIST CSF 2.0 GOVERN function.**

> **A:** The GOVERN function (GV) is new in CSF 2.0 and addresses the organizational context
> that enables effective cybersecurity: GV.OC (organizational context), GV.RM (risk management
> strategy), GV.RR (roles, responsibilities, authorities), GV.PO (policy), GV.OV (oversight),
> and GV.SC (cybersecurity supply chain risk management). It reflects the industry realization
> that technical controls fail without executive sponsorship, clear accountability, and
> supplier risk management — all of which were under-addressed in CSF 1.1.

---

**Q41. How would you design an API rate limiter that is distributed across multiple application instances?**

> **A:** The in-memory `InMemoryRateLimiter` in this platform works for a single instance.
> For distributed deployments (multiple Uvicorn workers, Kubernetes pods): replace with a
> **Redis-based sliding window counter** using `INCR` + `EXPIRE` or a Lua script for
> atomicity. Libraries: `fastapi-limiter` (uses Redis + aioredis), `slowapi` (integrates
> with Starlette middleware). The Redis key encodes `{client_ip}:{endpoint}:{window}`;
> the counter is incremented atomically; TTL matches the rate window. This ensures all
> instances share a consistent rate limit view.

---

**Q42. What is SSRF and why is it particularly dangerous in a GRC platform?**

> **A:** **Server-Side Request Forgery (SSRF)** tricks the server into making HTTP requests
> to internal resources on behalf of the attacker — potentially reaching metadata APIs
> (`http://169.254.169.254/`), internal databases, or other microservices. A GRC platform
> is high-value: it contains risk registers, audit evidence, findings, and compliance posture
> data. SSRF could be used to exfiltrate cloud credentials (AWS/GCP metadata endpoints),
> pivot to internal database admin interfaces, or access unprotected internal APIs. Mitigation:
> validate/block all outbound URL inputs; use egress firewall rules; apply deny-by-default
> network policies.

---

**Q43. Describe a zero-trust architecture approach for deploying this GRC platform.**

> **A:** Zero-trust: "never trust, always verify." Applied to GRC platform deployment:
> 1. **Identity verification**: Every request requires valid JWT; no implicit trust based on network location
> 2. **Micro-segmentation**: App container on internal network; DB inaccessible from internet; Nginx as DMZ
> 3. **Least privilege**: DB user has only DML access; app runs as non-root `grc` user
> 4. **Continuous monitoring**: All access logged; anomaly alerts in SIEM
> 5. **Device posture** (enterprise): Integrate with device management — only managed devices can access the GRC portal
> 6. **mTLS** (advanced): Service-to-service calls (app → DB) use mutual TLS

---

**Q44. How do you handle secret rotation with zero downtime?**

> **A:** The main challenge: rotating `SECRET_KEY` invalidates all existing JWTs. Strategy:
> 1. **Dual-key validation**: Accept tokens signed by either old or new key during a transition window (e.g., 15 minutes)
> 2. Deploy new containers with new `SECRET_KEY` environment variable
> 3. Old containers continue serving with old key while new ones roll out (blue-green or rolling update)
> 4. After all sessions have expired/refreshed, retire old key
> For database password rotation: update the secret in the vault; use connection pooling with
> reconnect logic (`pool_pre_ping=True` in SQLAlchemy) so new connections use the new password.

---

**Q45. What are the compliance implications of storing audit evidence in the cloud?**

> **A:** Key considerations:
> - **Data residency**: Evidence may contain PII/PHI — must comply with GDPR, HIPAA, DPDP
> - **Encryption at rest**: Object storage (S3, GCS) must use AES-256; key management via KMS
> - **Access control**: Evidence access should be role-gated, logged, and limited to need-to-know
> - **Retention**: SOC 2 requires 1+ year; ISO 27001 audit records typically 3 years
> - **Integrity**: SHA-256 hash chain (as implemented) provides tamper evidence
> - **Right to erasure**: If evidence contains personal data, GDPR Art. 17 requires ability to delete without breaking audit trails

---

**Q46. How would you implement automated control testing using this platform's API?**

> **A:** Automated control testing sends API calls to `POST /api/v1/audits/{procedure_id}/execute`
> with `{"result": "pass", "notes": "Automated test via CI/CD"}`. Integration pattern:
> 1. A CI/CD pipeline (GitHub Actions, GitLab CI) runs security checks (SAST, dependency audit, config validation)
> 2. Results are mapped to control procedures in the GRC platform
> 3. Pipeline calls the GRC API with a service account JWT (Auditor role) to record pass/fail
> 4. Failures automatically trigger audit findings via `POST /api/v1/findings/`
> 5. Dashboard shows real-time automated vs. manual testing ratio
> This implements "compliance as code" and supports continuous control monitoring.

---

**Q47. What Python security best practices are demonstrated in this codebase?**

> **A:**
> - **Secret management**: `pydantic-settings` with field validation; no hardcoded secrets
> - **Password hashing**: `bcrypt` via the `bcrypt` library (not deprecated `passlib`)
> - **JWT**: `PyJWT[crypto]` with explicit algorithm specification
> - **Input validation**: Pydantic v2 models on all API inputs with field constraints
> - **SQL injection prevention**: SQLAlchemy ORM throughout; no raw `text()` with user input
> - **File upload safety**: Extension allowlist; size limit; content stored outside web root
> - **Cryptographic integrity**: `hashlib.sha256` for evidence chain of custody
> - **Dependency auditing**: `pip-audit` in CI pipeline

---

**Q48. Explain the compliance gap assessment process. What does a gap score of 40% mean?**

> **A:** A compliance gap assessment maps an organization's implemented controls against
> a framework's requirements. For each requirement: if a control is mapped and marked
> "implemented" → compliant; if not → gap. The gap % = (ungapped requirements / total
> requirements) × 100. A **40% gap score** means 40% of the framework's requirements have
> no implemented control mapped against them — the organization would fail a compliance
> audit on 40% of criteria. The platform's assessment module calculates this per-framework
> and surfaces it in the readiness report with a drill-down to specific ungapped requirements.

---

**Q49. What is the difference between a penetration test and a vulnerability scan, and how do both relate to SOC 2?**

> **A:** A **vulnerability scan** is automated — tools (Nessus, Qualys, Tenable) probe for
> known CVEs and misconfigurations. Fast, broad, but generates false positives and misses
> business logic flaws. A **penetration test** involves manual, adversarial testing by a
> skilled tester who chains vulnerabilities and tests business logic — finding what scanners
> miss. SOC 2 **doesn't mandate** pen testing, but auditors consider it strong evidence for
> CC4.1 (monitoring for vulnerabilities) and CC7.1 (detection of system vulnerabilities).
> Annual pen tests are industry standard for mature SOC 2 programs.

---

**Q50. If this GRC platform were being audited for SOC 2 Type II, what would be the top 5 evidence items an auditor would request?**

> **A:**
> 1. **User access reviews** — logs of provisioning/deprovisioning; RBAC role assignments
>    with business justification (CC6.2, CC6.4)
> 2. **Control testing results** — completed test procedures with pass/fail evidence across the
>    audit period, including automated test logs (CC4.1)
> 3. **Incident and finding logs** — audit finding records with CAPA closure evidence, root
>    cause analysis, and sign-off timestamps (CC7.3)
> 4. **Risk register and treatment documentation** — risk assessments with likelihood/impact
>    scores, treatment decisions, and approval records (CC9.1)
> 5. **Change management records** — evidence that code changes (Alembic migrations,
>    deployments) went through a review/approval process; git history + PR approvals (CC8.1)

---

> **Prepared for**: Senior GRC Engineer / Security Architect / Compliance Manager interviews
> **Platform**: Cybersecurity GRC & Compliance Management Platform v1.0
> **Frameworks covered**: SOC 2 TSP, ISO/IEC 27001:2022, NIST CSF 2.0
