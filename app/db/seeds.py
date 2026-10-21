import sys
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.core.security import hash_password
from app.core.logging import logger
from app.models import (
    Organization,
    User,
    UserRole,
    Framework,
    FrameworkRequirement,
    SecurityControl,
    ControlMapping,
    ComplianceAssessment,
    RiskAssessment,
    EvidenceRecord,
    AuditProject,
    ControlTest,
    AuditFinding,
    CorrectiveAction,
    AuditEvent,
    ImplementationStatus,
    TestingFrequency,
    MappingApprovalStatus,
    AssessmentStatus,
    RiskLevel,
    RiskTreatmentStrategy,
    RiskStatus,
    EvidenceReviewStatus,
    TestResult,
    FindingSeverity,
    FindingStatus,
    ActionStatus,
)


def seed_database(db: Session) -> None:
    """
    Populates the database with realistic industry-standard seed data:
    - 1 Fictional Cloud SaaS Organization (ApexCloud Technologies)
    - 5 Role-based Users (Platform Admin, Org Admin, GRC Analyst, Control Owner, Auditor)
    - 3 Frameworks (SOC 2, ISO/IEC 27001:2022, NIST CSF 2.0)
    - Official Framework Requirements
    - 9 Baseline Security Controls
    - Cross-Framework Control Mappings with Rationales
    - Initial Compliance Assessments
    - Risk Register Items (including Missing Privileged MFA scenario)
    - Control Test with Exception & Audit Finding
    - Corrective Action Plan (CAPA)
    - Audit Trail Events
    """
    logger.info("Starting database seeding...")

    # Check if already seeded
    existing_org = db.query(Organization).filter_by(slug="apexcloud").first()
    if existing_org:
        logger.info("Database already seeded with ApexCloud. Skipping...")
        return

    # 1. Organization
    apex_org = Organization(
        name="ApexCloud Technologies Inc.",
        slug="apexcloud",
        industry="Cloud Infrastructure & Financial SaaS"
    )
    db.add(apex_org)
    db.flush()

    # 2. Users across 5 Roles (Default Password: Password123!)
    default_pw_hash = hash_password("Password123!")

    platform_admin = User(
        email="admin@apexcloud.io",
        hashed_password=default_pw_hash,
        full_name="Alex Rivera (Platform Admin)",
        role=UserRole.PLATFORM_ADMIN,
        organization_id=None,  # Global platform administrator
        is_active=True
    )
    org_admin = User(
        email="security.lead@apexcloud.io",
        hashed_password=default_pw_hash,
        full_name="Sarah Chen (CISO / Org Admin)",
        role=UserRole.ORG_ADMIN,
        organization_id=apex_org.id,
        is_active=True
    )
    grc_analyst = User(
        email="analyst@apexcloud.io",
        hashed_password=default_pw_hash,
        full_name="Marcus Vance (Senior GRC Analyst)",
        role=UserRole.GRC_ANALYST,
        organization_id=apex_org.id,
        is_active=True
    )
    control_owner = User(
        email="it.owner@apexcloud.io",
        hashed_password=default_pw_hash,
        full_name="Elena Rostova (DevOps / Control Owner)",
        role=UserRole.CONTROL_OWNER,
        organization_id=apex_org.id,
        is_active=True
    )
    auditor = User(
        email="auditor@cpa-assurance.com",
        hashed_password=default_pw_hash,
        full_name="David Sterling (Lead CPA Auditor)",
        role=UserRole.AUDITOR,
        organization_id=apex_org.id,
        is_active=True
    )

    db.add_all([platform_admin, org_admin, grc_analyst, control_owner, auditor])
    db.flush()

    # 3. Frameworks
    fw_soc2 = Framework(
        code="SOC2",
        name="SOC 2 Trust Services Criteria",
        version="2017 (Revised 2022)",
        issuing_body="AICPA (American Institute of CPAs)",
        description=(
            "Standard for evaluating security, availability, processing integrity, "
            "confidentiality, and privacy of customer data in technology and cloud organizations. "
            "Assessed via independent CPA attestation (Type I or Type II examination)."
        ),
        is_certification=False,
        assurance_type="Independent CPA Attestation Examination"
    )

    fw_iso = Framework(
        code="ISO27001",
        name="ISO/IEC 27001:2022 Information Security Management",
        version="2022",
        issuing_body="ISO / IEC",
        description=(
            "International standard defining requirements for establishing, implementing, "
            "maintaining, and continually improving an Information Security Management System (ISMS). "
            "Includes Clauses 4–10 and 93 Annex A controls in 4 themes. Results in formal accredited 3-year certification."
        ),
        is_certification=True,
        assurance_type="Accredited Third-Party Certification (3-Year Cycle)"
    )

    fw_nist = Framework(
        code="NIST_CSF",
        name="NIST Cybersecurity Framework (CSF) 2.0",
        version="2.0",
        issuing_body="NIST (National Institute of Standards and Technology)",
        description=(
            "Outcome-driven taxonomy to help organizations understand, assess, prioritize, "
            "and communicate cybersecurity risks. Structured across 6 Core Functions: "
            "Govern, Identify, Protect, Detect, Respond, and Recover. Voluntary guidance; not an auditable certification."
        ),
        is_certification=False,
        assurance_type="Voluntary Self-Assessment & Implementation Tiers"
    )

    db.add_all([fw_soc2, fw_iso, fw_nist])
    db.flush()

    # 4. Framework Requirements
    # A. SOC 2 Trust Services Criteria (Common Criteria)
    soc2_reqs = [
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC1.1",
            title="Integrity and Ethical Values",
            category="Control Environment",
            description="The entity demonstrates a commitment to integrity and ethical values.",
            guidance="Codes of conduct, background checks, conflict of interest declarations."
        ),
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC6.1",
            title="Logical Access Security Controls",
            category="Logical and Physical Access Controls",
            description=(
                "The entity implements logical access security software, infrastructure, "
                "and architectures over protected information assets to protect them from security events."
            ),
            guidance="Multi-factor authentication (MFA), role-based permissions, network segmentation."
        ),
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC6.2",
            title="User Registration and Access Authorization",
            category="Logical and Physical Access Controls",
            description="Prior to issuing system credentials, the entity registers and authorizes new internal and external users.",
            guidance="Formal onboarding access approval, manager authorization, least privilege."
        ),
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC6.3",
            title="Access Revocation and Periodic Review",
            category="Logical and Physical Access Controls",
            description="The entity revokes access upon termination and periodically reviews user access privileges.",
            guidance="Automated offboarding, quarterly manager access certifications."
        ),
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC6.6",
            title="Boundary Protection & Encryption in Transit",
            category="Logical and Physical Access Controls",
            description="The entity implements logical boundaries and encrypts data transmitted over open public networks.",
            guidance="TLS 1.2+ / TLS 1.3 encryption, firewalls, VPC boundaries."
        ),
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC6.7",
            title="Data Protection at Rest",
            category="Logical and Physical Access Controls",
            description="The entity protects transmission, movement, and storage of data at rest.",
            guidance="AES-256 storage volume encryption, database column-level encryption, KMS key management."
        ),
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC7.1",
            title="Vulnerability Detection and Management",
            category="System Operations",
            description="The entity uses detection and monitoring procedures to identify susceptibility to vulnerabilities.",
            guidance="Vulnerability scanners, dynamic/static code analysis, penetration testing."
        ),
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC7.2",
            title="Security Event Monitoring and Logging",
            category="System Operations",
            description="The entity monitors system components to detect anomalies and unauthorized logical access.",
            guidance="SIEM integration, centralized audit logs, automated alert rules."
        ),
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC7.3",
            title="Security Incident Response",
            category="System Operations",
            description="The entity evaluates and responds to identified security events in accordance with defined procedures.",
            guidance="Incident response plan, post-mortem reviews, customer breach notifications."
        ),
        FrameworkRequirement(
            framework_id=fw_soc2.id,
            identifier="CC9.2",
            title="Vendor and Sub-processor Risk Assessment",
            category="Risk Mitigation",
            description="The entity assesses and manages risks associated with vendors and sub-processors.",
            guidance="Annual third-party security reviews, SOC 2 report inspections, vendor DPAs."
        ),
    ]

    # B. ISO/IEC 27001:2022
    iso_reqs = [
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="Clause 5.1",
            title="Leadership and Commitment",
            category="ISMS Management Clauses",
            description="Top management shall demonstrate leadership and commitment with respect to the ISMS.",
            guidance="Information security policy, resource allocation, steering committee oversight."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="Clause 6.1.2",
            title="Information Security Risk Assessment",
            category="ISMS Management Clauses",
            description="The organization shall define and apply an information security risk assessment process.",
            guidance="Methodology for risk identification, likelihood and consequence calculation, risk criteria."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="A.5.1",
            title="Policies for Information Security",
            category="Annex A: Organizational Controls (Theme 5)",
            description="Information security policy and topic-specific policies shall be defined, approved, and published.",
            guidance="Annual policy review, executive sign-off, employee distribution."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="A.5.19",
            title="Information Security in Supplier Relationships",
            category="Annex A: Organizational Controls (Theme 5)",
            description="Processes and procedures shall be defined and implemented to manage information security risks associated with supplier relationships.",
            guidance="Vendor questionnaires, SLAs, audit rights, data processing agreements."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="A.5.24",
            title="Information Security Incident Management Planning",
            category="Annex A: Organizational Controls (Theme 5)",
            description="The organization shall plan and prepare for managing information security incidents by defining processes, roles, and responsibilities.",
            guidance="Incident response plan, tabletop exercises, severity escalations."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="A.6.3",
            title="Information Security Awareness, Education and Training",
            category="Annex A: People Controls (Theme 6)",
            description="Personnel and relevant interested parties shall receive appropriate information security awareness, education, and training.",
            guidance="Mandatory new hire and annual training, phishing simulations."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="A.8.2",
            title="Privileged Access Rights",
            category="Annex A: Technological Controls (Theme 8)",
            description="The allocation and use of privileged access rights shall be restricted and managed.",
            guidance="Just-in-time elevation, bastion hosts, MFA, separate administrative accounts."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="A.8.5",
            title="Secure Authentication",
            category="Annex A: Technological Controls (Theme 8)",
            description="Secure authentication technologies and procedures shall be implemented based on information access restrictions and system access policy.",
            guidance="Multi-factor authentication (MFA), passwordless FIDO2 keys, brute-force throttling."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="A.8.8",
            title="Management of Technical Vulnerabilities",
            category="Annex A: Technological Controls (Theme 8)",
            description="Information about technical vulnerabilities of information systems being used shall be obtained and evaluated.",
            guidance="Automated vulnerability scans, CVSS scoring, defined patch SLA windows."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="A.8.15",
            title="Logging",
            category="Annex A: Technological Controls (Theme 8)",
            description="Logs that record activities, exceptions, faults, and other relevant events shall be produced, stored, protected, and analyzed.",
            guidance="Centralized log repository, immutable WORM storage, NTP synchronization."
        ),
        FrameworkRequirement(
            framework_id=fw_iso.id,
            identifier="A.8.24",
            title="Use of Cryptography",
            category="Annex A: Technological Controls (Theme 8)",
            description="Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
            guidance="Approved cipher suites, automated key rotation, secure key storage in HSM/KMS."
        ),
    ]

    # C. NIST Cybersecurity Framework (CSF) 2.0
    nist_reqs = [
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="GV.OC-01",
            title="Organizational Context Understood",
            category="GOVERN (GV) - Organizational Context",
            description="The organizational mission, objectives, stakeholders, and legal/regulatory requirements are understood and integrated into cybersecurity decisions.",
            guidance="GRC mandate, regulatory compliance register, business objectives alignment."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="GV.RM-01",
            title="Cybersecurity Risk Strategy Established",
            category="GOVERN (GV) - Risk Management Strategy",
            description="Risk management objectives, tolerance, and appetite statements are established, communicated, and agreed to.",
            guidance="Enterprise risk appetite policy, qualitative and quantitative scoring scales."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="ID.AM-01",
            title="Inventories of Hardware & Cloud Assets",
            category="IDENTIFY (ID) - Asset Management",
            description="Inventories of physical and virtual assets, hardware, and external resources are maintained.",
            guidance="Automated CMDB, cloud resource discovery, asset owners."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="ID.RA-01",
            title="Cybersecurity Vulnerabilities Identified",
            category="IDENTIFY (ID) - Risk Assessment",
            description="Vulnerabilities in assets are identified, validated, and documented.",
            guidance="Continuous scanning, threat intelligence feeds, threat modeling."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="PR.AA-01",
            title="Identities and Credentials Managed",
            category="PROTECT (PR) - Identity & Access",
            description="Identities and credentials for authorized users, services, and hardware are managed throughout their lifecycle.",
            guidance="Single Sign-On (SSO), SCIM deprovisioning, role-based access."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="PR.AA-03",
            title="Users Authenticated using MFA",
            category="PROTECT (PR) - Identity & Access",
            description="Users, services, and hardware are authenticated with credentials commensurate with the criticality of the service, including multi-factor authentication (MFA).",
            guidance="Hardware tokens, authenticator apps, conditional access policies."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="PR.DS-01",
            title="Data at Rest Protected",
            category="PROTECT (PR) - Data Security",
            description="The confidentiality, integrity, and availability of data-at-rest are protected.",
            guidance="AES-256 volume encryption, database column protection, KMS."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="PR.DS-02",
            title="Data in Transit Protected",
            category="PROTECT (PR) - Data Security",
            description="The confidentiality, integrity, and availability of data-in-transit are protected.",
            guidance="Mandatory HTTPS/TLS 1.3, internal mTLS service-to-service communication."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="DE.CM-01",
            title="Networks and Environments Monitored",
            category="DETECT (DE) - Continuous Monitoring",
            description="Networks, computing environments, and operational technology are monitored to detect potential cybersecurity events.",
            guidance="Vulnerability scanning, EDR endpoints, network flow telemetry."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="DE.AE-02",
            title="Anomalies and Events Analyzed",
            category="DETECT (DE) - Adverse Event Analysis",
            description="Potentially adverse events are analyzed to understand attack targets and methods.",
            guidance="Security Operation Center (SOC) triage, correlation rules, threat hunting."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="RS.MA-01",
            title="Incident Response Plan Executed",
            category="RESPOND (RS) - Incident Management",
            description="The incident response plan is executed in coordination with relevant parties.",
            guidance="Defined runbooks, communications protocols, legal escalation."
        ),
        FrameworkRequirement(
            framework_id=fw_nist.id,
            identifier="RC.RP-01",
            title="Recovery Plan Executed",
            category="RECOVER (RC) - Incident Recovery",
            description="Recovery processes and procedures are executed and maintained to ensure timely restoration of systems.",
            guidance="Disaster recovery plans, RTO/RPO targets, offsite backups."
        ),
    ]

    all_reqs = soc2_reqs + iso_reqs + nist_reqs
    db.add_all(all_reqs)
    db.flush()

    # Map for easy requirement lookup by identifier
    req_map = {r.identifier: r for r in all_reqs}

    # 5. Baseline Security Controls for ApexCloud
    controls_data = [
        SecurityControl(
            organization_id=apex_org.id,
            control_id="CTL-IAM-01",
            name="Multi-Factor Authentication (MFA) for Administrative & Cloud Console Access",
            description=(
                "Mandatory MFA enforcement for all cloud infrastructure consoles (AWS/GCP), "
                "identity provider logins, production Kubernetes clusters, and privileged database jump hosts. "
                "Hardware FIDO2 or TOTP authenticator required."
            ),
            owner_id=control_owner.id,
            implementation_status=ImplementationStatus.PARTIALLY_IMPLEMENTED,
            testing_frequency=TestingFrequency.MONTHLY,
            evidence_requirements="Identity provider MFA enforcement policy export, AWS IAM credential report, SSO audit log.",
            last_tested_at=datetime.now(timezone.utc) - timedelta(days=14)
        ),
        SecurityControl(
            organization_id=apex_org.id,
            control_id="CTL-IAM-02",
            name="Quarterly Privileged Access & User Entitlement Reviews",
            description=(
                "Formal quarterly certification of all active employee and service account access permissions. "
                "Department managers must review and re-authorize access; unused accounts are deactivated within 5 business days."
            ),
            owner_id=control_owner.id,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            testing_frequency=TestingFrequency.QUARTERLY,
            evidence_requirements="Completed manager sign-off spreadsheets, Jira access review tickets, deprovisioning logs.",
            last_tested_at=datetime.now(timezone.utc) - timedelta(days=45)
        ),
        SecurityControl(
            organization_id=apex_org.id,
            control_id="CTL-CRY-01",
            name="Strong Cryptography: AES-256 at Rest and TLS 1.3 in Transit",
            description=(
                "All customer data stored in cloud databases, S3 object buckets, and EBS block volumes must be "
                "encrypted using AES-256 with KMS customer-managed keys. All external and internal ingress endpoints "
                "must reject TLS versions older than 1.2 and prioritize TLS 1.3."
            ),
            owner_id=control_owner.id,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            testing_frequency=TestingFrequency.QUARTERLY,
            evidence_requirements="AWS KMS configuration audit, SSL Labs Qualys test report (Grade A+), terraform encryption modules.",
            last_tested_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        SecurityControl(
            organization_id=apex_org.id,
            control_id="CTL-VUL-01",
            name="Continuous Automated Vulnerability Scanning & Patch Management",
            description=(
                "Automated weekly vulnerability scans across all production container images, virtual machines, and public IP blocks. "
                "Critical vulnerabilities (CVSS >= 9.0) must be remediated within 14 days; High within 30 days."
            ),
            owner_id=control_owner.id,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            testing_frequency=TestingFrequency.MONTHLY,
            evidence_requirements="Weekly vulnerability scanner executive reports, patch deployment pipeline logs, Jira remediation tickets.",
            last_tested_at=datetime.now(timezone.utc) - timedelta(days=7)
        ),
        SecurityControl(
            organization_id=apex_org.id,
            control_id="CTL-IR-01",
            name="Cybersecurity Incident Response Plan & Annual Tabletop Simulation",
            description=(
                "Documented incident response plan defining classification severities (SEV1-SEV4), communication trees, "
                "legal counsel notification, and 72-hour breach disclosure protocols. Tested annually via simulated incident."
            ),
            owner_id=org_admin.id,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            testing_frequency=TestingFrequency.ANNUALLY,
            evidence_requirements="Incident Response Plan v3.2 PDF, annual tabletop exercise after-action report, post-mortem meeting minutes.",
            last_tested_at=datetime.now(timezone.utc) - timedelta(days=90)
        ),
        SecurityControl(
            organization_id=apex_org.id,
            control_id="CTL-BCP-01",
            name="Automated Immutable Cloud Backups & Periodic Restoration Drills",
            description=(
                "Daily automated incremental and weekly full backups of production relational databases and application states. "
                "Backups are stored with S3 Object Lock (WORM compliance) and tested semi-annually via table-level test restores."
            ),
            owner_id=control_owner.id,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            testing_frequency=TestingFrequency.SEMI_ANNUALLY,
            evidence_requirements="AWS Backup dashboard snapshot, semi-annual restoration test verification log.",
            last_tested_at=datetime.now(timezone.utc) - timedelta(days=60)
        ),
        SecurityControl(
            organization_id=apex_org.id,
            control_id="CTL-TRN-01",
            name="Mandatory Security Awareness & Anti-Phishing Training",
            description=(
                "Mandatory information security and privacy awareness training for all new employees within 14 days of start, "
                "refreshed annually. Monthly simulated phishing campaigns with targeted coaching for repeat clickers."
            ),
            owner_id=grc_analyst.id,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            testing_frequency=TestingFrequency.ANNUALLY,
            evidence_requirements="LMS employee completion report (target > 98%), quarterly phishing simulation metrics.",
            last_tested_at=datetime.now(timezone.utc) - timedelta(days=20)
        ),
        SecurityControl(
            organization_id=apex_org.id,
            control_id="CTL-LOG-01",
            name="Centralized Security Logging, SIEM Ingestion & Continuous Alerting",
            description=(
                "Aggregation of operating system, identity, API gateway, and cloud audit logs (AWS CloudTrail) into a "
                "centralized SIEM. 365-day retention policy; high-severity alerts page on-call security engineering 24/7."
            ),
            owner_id=control_owner.id,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            testing_frequency=TestingFrequency.CONTINUOUS,
            evidence_requirements="SIEM ingestion dashboard export, CloudTrail retention configuration, PagerDuty alert integration test.",
            last_tested_at=datetime.now(timezone.utc) - timedelta(days=5)
        ),
        SecurityControl(
            organization_id=apex_org.id,
            control_id="CTL-VRM-01",
            name="Third-Party Vendor Risk Management & Security Due Diligence",
            description=(
                "Security and privacy evaluation of all prospective sub-processors and software vendors prior to contracting. "
                "Annual review of vendor SOC 2 Type II reports, ISO 27001 certificates, and Data Processing Agreements (DPAs)."
            ),
            owner_id=grc_analyst.id,
            implementation_status=ImplementationStatus.NEEDS_IMPROVEMENT,
            testing_frequency=TestingFrequency.ANNUALLY,
            evidence_requirements="Vendor security risk register, completed vendor security questionnaires, active DPA files.",
            last_tested_at=datetime.now(timezone.utc) - timedelta(days=120)
        ),
    ]

    db.add_all(controls_data)
    db.flush()

    ctrl_map = {c.control_id: c for c in controls_data}

    # 6. Cross-Framework Control Mappings
    mappings_data = [
        # CTL-IAM-01 (MFA)
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-IAM-01"].id,
            requirement_id=req_map["CC6.1"].id,
            mapping_rationale="CTL-IAM-01 enforces multi-factor authentication as the baseline logical access control satisfying SOC 2 CC6.1.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-IAM-01"].id,
            requirement_id=req_map["A.8.5"].id,
            mapping_rationale="Fulfills ISO/IEC 27001:2022 Annex A Control A.8.5 (Secure Authentication) by requiring MFA for all access.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-IAM-01"].id,
            requirement_id=req_map["PR.AA-03"].id,
            mapping_rationale="Directly maps to NIST CSF 2.0 PR.AA-03 ('Users, services, and hardware are authenticated using MFA').",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),

        # CTL-IAM-02 (Access Reviews)
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-IAM-02"].id,
            requirement_id=req_map["CC6.3"].id,
            mapping_rationale="Quarterly reviews verify that terminated staff are deprovisioned and permissions adhere to least privilege.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-IAM-02"].id,
            requirement_id=req_map["A.8.2"].id,
            mapping_rationale="Addresses ISO 27001 A.8.2 requirement to restrict and periodically review privileged access rights.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-IAM-02"].id,
            requirement_id=req_map["PR.AA-01"].id,
            mapping_rationale="Demonstrates credential and identity lifecycle governance under NIST CSF 2.0 PR.AA-01.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),

        # CTL-CRY-01 (Encryption)
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-CRY-01"].id,
            requirement_id=req_map["CC6.6"].id,
            mapping_rationale="Enforces TLS 1.3 perimeter encryption over public internet connections per SOC 2 CC6.6.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-CRY-01"].id,
            requirement_id=req_map["CC6.7"].id,
            mapping_rationale="Guarantees AES-256 cryptographic protection of data at rest across all database engines per SOC 2 CC6.7.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-CRY-01"].id,
            requirement_id=req_map["A.8.24"].id,
            mapping_rationale="Provides organizational rules and technical enforcement for cryptography per ISO 27001 A.8.24.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-CRY-01"].id,
            requirement_id=req_map["PR.DS-01"].id,
            mapping_rationale="Protects data at rest under NIST CSF 2.0 PR.DS-01.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-CRY-01"].id,
            requirement_id=req_map["PR.DS-02"].id,
            mapping_rationale="Protects data in transit under NIST CSF 2.0 PR.DS-02.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),

        # CTL-LOG-01 (SIEM & Logging)
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-LOG-01"].id,
            requirement_id=req_map["CC7.2"].id,
            mapping_rationale="SIEM ingestion detects anomalies and security incidents satisfying SOC 2 CC7.2.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-LOG-01"].id,
            requirement_id=req_map["A.8.15"].id,
            mapping_rationale="Provides centralized log generation, protection, and review per ISO 27001 A.8.15.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-LOG-01"].id,
            requirement_id=req_map["DE.AE-02"].id,
            mapping_rationale="Satisfies NIST CSF 2.0 DE.AE-02 for analyzing adverse events and security anomalies.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),

        # CTL-VRM-01 (Vendor Risk)
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-VRM-01"].id,
            requirement_id=req_map["CC9.2"].id,
            mapping_rationale="Assesses third-party sub-processors and external SaaS risks per SOC 2 CC9.2.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
        ControlMapping(
            organization_id=apex_org.id,
            control_id=ctrl_map["CTL-VRM-01"].id,
            requirement_id=req_map["A.5.19"].id,
            mapping_rationale="Implements supplier security governance required by ISO 27001 A.5.19.",
            approval_status=MappingApprovalStatus.APPROVED,
            reviewed_by_id=grc_analyst.id,
            reviewed_at=datetime.now(timezone.utc) - timedelta(days=30)
        ),
    ]

    db.add_all(mappings_data)
    db.flush()

    # 7. Compliance Assessments
    assessments_data = [
        ComplianceAssessment(
            organization_id=apex_org.id,
            requirement_id=req_map["CC6.1"].id,
            status=AssessmentStatus.PARTIALLY_IMPLEMENTED,
            justification=None,
            assessed_by_id=grc_analyst.id,
            identified_gaps="Legacy administrative console still allows password-only authentication for 4 service accounts.",
            recommended_actions="Enforce conditional access policy requiring FIDO2 or TOTP across 100% of privileged users.",
            assessed_at=datetime.now(timezone.utc) - timedelta(days=14)
        ),
        ComplianceAssessment(
            organization_id=apex_org.id,
            requirement_id=req_map["CC6.6"].id,
            status=AssessmentStatus.IMPLEMENTED,
            justification=None,
            assessed_by_id=grc_analyst.id,
            identified_gaps="None identified. TLS 1.3 enforced across all load balancers.",
            recommended_actions="Maintain quarterly automated cipher validation tests.",
            assessed_at=datetime.now(timezone.utc) - timedelta(days=14)
        ),
        ComplianceAssessment(
            organization_id=apex_org.id,
            requirement_id=req_map["A.8.5"].id,
            status=AssessmentStatus.NEEDS_IMPROVEMENT,
            justification=None,
            assessed_by_id=grc_analyst.id,
            identified_gaps="MFA coverage is at 92% rather than 100% mandatory compliance.",
            recommended_actions="Migrate remaining legacy IAM users to Okta SSO with required MFA.",
            assessed_at=datetime.now(timezone.utc) - timedelta(days=14)
        ),
        ComplianceAssessment(
            organization_id=apex_org.id,
            requirement_id=req_map["PR.AA-03"].id,
            status=AssessmentStatus.PARTIALLY_IMPLEMENTED,
            justification=None,
            assessed_by_id=grc_analyst.id,
            identified_gaps="Missing MFA for staging and secondary operational portals.",
            recommended_actions="Standardize corporate identity policy across all cloud environments.",
            assessed_at=datetime.now(timezone.utc) - timedelta(days=14)
        ),
        ComplianceAssessment(
            organization_id=apex_org.id,
            requirement_id=req_map["CC9.2"].id,
            status=AssessmentStatus.NEEDS_IMPROVEMENT,
            justification=None,
            assessed_by_id=grc_analyst.id,
            identified_gaps="Vendor security reviews not completed for 5 recent marketing and analytics SaaS vendors.",
            recommended_actions="Block procurement without completed GRC vendor assessment sign-off.",
            assessed_at=datetime.now(timezone.utc) - timedelta(days=14)
        ),
    ]

    db.add_all(assessments_data)
    db.flush()

    # 8. Risk Register Seed Data (Including the Demonstration Scenario)
    risks_data = [
        RiskAssessment(
            organization_id=apex_org.id,
            risk_id="RSK-2026-001",
            title="Missing MFA on Privileged Administrative Cloud Accounts",
            affected_asset="AWS Production Infrastructure, IAM Roles & Customer RDS Database",
            threat_source="Credential Stuffing, Phishing, Stolen Session Tokens",
            vulnerability="4 legacy administrative accounts do not enforce mandatory Multi-Factor Authentication",
            business_impact=(
                "Total compromise of production cloud environment, unauthorized data exfiltration, "
                "regulatory fines under GDPR/CCPA, and breach notification obligations."
            ),
            owner_id=control_owner.id,
            inherent_likelihood=4,
            inherent_impact=5,
            inherent_score=20,
            inherent_level=RiskLevel.CRITICAL,
            existing_safeguards="Complex password policy (16+ chars), quarterly access reviews, basic CloudTrail logging.",
            residual_likelihood=2,
            residual_impact=2,
            residual_score=4,
            residual_level=RiskLevel.LOW,
            treatment_strategy=RiskTreatmentStrategy.MITIGATE,
            treatment_details="Enforce mandatory Okta SSO with FIDO2/TOTP hardware token across all AWS IAM identities (CTL-IAM-01).",
            status=RiskStatus.IN_TREATMENT
        ),
        RiskAssessment(
            organization_id=apex_org.id,
            risk_id="RSK-2026-002",
            title="Unencrypted Database Backup Snapshots Exposed to Internal Personnel",
            affected_asset="Production RDS PostgreSQL Backups & S3 Snapshot Buckets",
            threat_source="Rogue insider, compromised internal developer laptop",
            vulnerability="Default snapshot policy lacked customer-managed KMS key binding",
            business_impact="Exposure of customer PII and sensitive payment records; loss of customer trust.",
            owner_id=control_owner.id,
            inherent_likelihood=3,
            inherent_impact=4,
            inherent_score=12,
            inherent_level=RiskLevel.HIGH,
            existing_safeguards="VPC private subnets, AWS IAM access policies.",
            residual_likelihood=1,
            residual_impact=2,
            residual_score=2,
            residual_level=RiskLevel.LOW,
            treatment_strategy=RiskTreatmentStrategy.MITIGATE,
            treatment_details="Implemented CTL-CRY-01 forcing automatic AWS KMS AES-256 encryption on all snapshot triggers.",
            status=RiskStatus.TREATED
        ),
        RiskAssessment(
            organization_id=apex_org.id,
            risk_id="RSK-2026-003",
            title="Supply Chain Compromise via Unassessed Third-Party Analytics Vendor",
            affected_asset="Customer Web Application & Frontend Analytics Javascript",
            threat_source="Compromised external vendor repository / Magecart style script injection",
            vulnerability="Vendor lacked verified SOC 2 Type II attestation report",
            business_impact="Client-side data theft, reputation loss, breach of contractual customer SLAs.",
            owner_id=grc_analyst.id,
            inherent_likelihood=3,
            inherent_impact=4,
            inherent_score=12,
            inherent_level=RiskLevel.HIGH,
            existing_safeguards="Content Security Policy (CSP), sub-resource integrity hashes.",
            residual_likelihood=2,
            residual_impact=3,
            residual_score=6,
            residual_level=RiskLevel.MEDIUM,
            treatment_strategy=RiskTreatmentStrategy.MITIGATE,
            treatment_details="Conduct formal security questionnaire review and require SOC 2 report under CTL-VRM-01.",
            status=RiskStatus.IN_TREATMENT
        ),
    ]

    db.add_all(risks_data)
    db.flush()

    # 9. Audit Project & Demonstration Scenario Testing Workflow
    audit_project = AuditProject(
        organization_id=apex_org.id,
        name="2026 SOC 2 & ISO 27001 Annual Readiness Assessment",
        framework_id=fw_soc2.id,
        audit_type="INTERNAL_READINESS",
        period_start=datetime.now(timezone.utc) - timedelta(days=90),
        period_end=datetime.now(timezone.utc) + timedelta(days=90),
        lead_auditor_id=auditor.id,
        status="IN_PROGRESS"
    )
    db.add(audit_project)
    db.flush()

    # 10. Evidence Record (Sanitized AWS IAM Policy Export)
    evidence = EvidenceRecord(
        organization_id=apex_org.id,
        control_id=ctrl_map["CTL-IAM-01"].id,
        title="AWS IAM Credential Report & MFA Status Export",
        description="Sanitized export of all IAM user credentials, MFA enablement flags, and password age.",
        file_name="aws_iam_credential_report_sanitized.csv",
        stored_file_path="./uploads/aws_iam_credential_report_sanitized.csv",
        file_size_bytes=4218,
        mime_type="text/csv",
        sha256_hash="212816a278be7b1ec4065794fec7157d77312bb5a519880b11a8e06a4e94e594",
        uploaded_by_id=control_owner.id,
        review_status=EvidenceReviewStatus.PENDING_REVIEW,
        retention_date=datetime.now(timezone.utc) + timedelta(days=365)
    )
    db.add(evidence)
    db.flush()

    # 11. Control Test demonstrating the Scenario (Step 1 & 4: Failed Test identified)
    control_test = ControlTest(
        organization_id=apex_org.id,
        audit_project_id=audit_project.id,
        control_id=ctrl_map["CTL-IAM-01"].id,
        test_title="Audit Inspection of MFA Enforcement on Privileged IAM Accounts",
        test_objective="Verify that 100% of accounts with AdministratorAccess or power user privileges require MFA.",
        test_procedure="Inspect AWS IAM credential report, verify Okta MFA sign-in logs, sample 50 active administrator logins.",
        result=TestResult.FAIL,
        tested_by_id=auditor.id,
        tested_at=datetime.now(timezone.utc) - timedelta(days=10),
        sample_size=50,
        exceptions_identified=4,
        evidence_id=evidence.id,
        notes="Identified 4 service administrator accounts with active console access but no enrolled virtual/hardware MFA token."
    )
    db.add(control_test)
    db.flush()

    # 12. Audit Finding (Step 1 & 5: Finding Recorded)
    finding = AuditFinding(
        organization_id=apex_org.id,
        control_test_id=control_test.id,
        control_id=ctrl_map["CTL-IAM-01"].id,
        finding_id="FND-2026-001",
        title="4 Privileged Cloud Accounts Found Without Enforced MFA",
        severity=FindingSeverity.HIGH,
        root_cause="Legacy IAM accounts created prior to SSO rollout bypassed mandatory Okta conditional access enforcement.",
        business_impact="Significantly increases likelihood of administrative account takeover via credential stuffing or phishing.",
        owner_id=control_owner.id,
        due_date=datetime.now(timezone.utc) + timedelta(days=14),
        status=FindingStatus.REMEDIATION_IN_PROGRESS
    )
    db.add(finding)
    db.flush()

    # 13. Corrective Action Plan (CAPA) (Step 5: Assigned to IT Owner)
    corrective_action = CorrectiveAction(
        organization_id=apex_org.id,
        finding_id=finding.id,
        action_plan=(
            "1. Deactivate console access for the 4 legacy IAM accounts.\n"
            "2. Re-provision necessary administrative access through Okta SSO with mandatory FIDO2 hardware MFA.\n"
            "3. Enforce AWS SCP (Service Control Policy) denying all IAM actions if MFA is not authenticated.\n"
            "4. Retest control and verify zero exceptions."
        ),
        owner_id=control_owner.id,
        target_completion_date=datetime.now(timezone.utc) + timedelta(days=10),
        status=ActionStatus.IN_PROGRESS,
        notes="Remediation steps 1 and 2 completed. AWS SCP policy currently in staging verification."
    )
    db.add(corrective_action)
    db.flush()

    # 14. Audit Events (Immutable Security Log Trail)
    audit_events_data = [
        AuditEvent(
            organization_id=apex_org.id,
            user_id=org_admin.id,
            action="ORGANIZATION_INITIALIZED",
            resource_type="Organization",
            resource_id=apex_org.id,
            details='{"name": "ApexCloud Technologies Inc.", "industry": "Cloud SaaS"}',
            ip_address="10.0.1.5"
        ),
        AuditEvent(
            organization_id=apex_org.id,
            user_id=grc_analyst.id,
            action="CONTROL_MAPPING_APPROVED",
            resource_type="ControlMapping",
            resource_id=mappings_data[0].id,
            details='{"control_id": "CTL-IAM-01", "requirement": "CC6.1", "status": "APPROVED"}',
            ip_address="10.0.1.18"
        ),
        AuditEvent(
            organization_id=apex_org.id,
            user_id=auditor.id,
            action="CONTROL_TEST_FAILED",
            resource_type="ControlTest",
            resource_id=control_test.id,
            details='{"test_id": 1, "result": "FAIL", "exceptions": 4}',
            ip_address="198.51.100.44"
        ),
        AuditEvent(
            organization_id=apex_org.id,
            user_id=auditor.id,
            action="AUDIT_FINDING_CREATED",
            resource_type="AuditFinding",
            resource_id=finding.id,
            details='{"finding_id": "FND-2026-001", "severity": "HIGH", "owner": "it.owner@apexcloud.io"}',
            ip_address="198.51.100.44"
        ),
    ]

    db.add_all(audit_events_data)
    db.commit()

    logger.info("Database seeding successfully completed!")
    logger.info(f"Seeded Organization: {apex_org.name} (Slug: {apex_org.slug})")
    logger.info(f"Seeded Users: 5 (Default passwords: Password123!)")
    logger.info(f"Seeded Frameworks: 3 (SOC 2, ISO 27001, NIST CSF 2.0)")
    logger.info(f"Seeded Controls: {len(controls_data)}")
    logger.info(f"Seeded Mappings: {len(mappings_data)}")
    logger.info(f"Seeded Risks: {len(risks_data)}")
    logger.info(f"Seeded Findings: 1 (FND-2026-001, Missing MFA Scenario)")


if __name__ == "__main__":
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()
