from typing import List, Dict, Any


def get_framework_comparison_data() -> Dict[str, Any]:
    """
    Returns in-depth comparative data contrasting SOC 2, ISO/IEC 27001:2022, and NIST CSF 2.0.
    Provides precise domain definitions, structural breakdowns, overlaps, and differences.
    """
    return {
        "dimensions": [
            {
                "dimension": "Issuing Body & Governance",
                "soc2": "American Institute of CPAs (AICPA)",
                "iso27001": "International Organization for Standardization (ISO) and International Electrotechnical Commission (IEC)",
                "nist_csf": "National Institute of Standards and Technology (U.S. Department of Commerce)"
            },
            {
                "dimension": "Primary Purpose",
                "soc2": "Evaluate internal controls over security, availability, confidentiality, processing integrity, and privacy to build customer trust for service organizations.",
                "iso27001": "Establish, implement, maintain, and continually improve an Information Security Management System (ISMS) across the entire organization.",
                "nist_csf": "Provide an outcome-driven taxonomy and guidance for managing and reducing cybersecurity risk across critical infrastructure and commercial enterprises."
            },
            {
                "dimension": "Structural Architecture",
                "soc2": "5 Trust Services Criteria (TSC) with Common Criteria (CC1.0 - CC9.0) plus criteria for Availability, Processing Integrity, Confidentiality, and Privacy.",
                "iso27001": "Mandatory Clauses 4 through 10 (Plan-Do-Check-Act ISMS management framework) plus Annex A containing 93 controls organized into 4 themes.",
                "nist_csf": "6 Core Functions (Govern, Identify, Protect, Detect, Respond, Recover), subdivided into 22 Categories and 106 Subcategories, mapped to Implementation Tiers (1 to 4)."
            },
            {
                "dimension": "Assurance & Attestation Model",
                "soc2": "Attestation Report issued by an independent licensed CPA firm. Type I evaluates design at a point in time; Type II evaluates operational effectiveness over 3–12 months.",
                "iso27001": "Formal Certification issued by an accredited Third-Party Certification Body (Registrar). Valid for 3 years, requiring annual surveillance audits.",
                "nist_csf": "Voluntary Self-Assessment & Benchmarking framework. NIST does NOT issue certifications or conduct formal compliance audits."
            },
            {
                "dimension": "Scope Determination",
                "soc2": "Scoped specifically to the service/system delivering value to customers (e.g. AWS-hosted SaaS product), defined in the Management Assertion.",
                "iso27001": "Broad, organizational-wide scope defined in the Statement of Applicability (SoA) covering people, processes, offices, and technology.",
                "nist_csf": "Flexible; can be applied to an entire enterprise, a specific business unit, an IT environment, or a critical infrastructure asset."
            },
            {
                "dimension": "Audit & Reporting Artifacts",
                "soc2": "SOC 2 Type I or Type II Report containing CPA Independent Service Auditor's Report, Management Assertion, System Description, and detailed Control Testing Matrix.",
                "iso27001": "Certificate of Registration (ISO/IEC 27001:2022) accompanied by an ISMS Internal Audit Report, Statement of Applicability (SoA), and Management Review minutes.",
                "nist_csf": "Organizational Profile (Current State vs Target State), Risk Register, and Implementation Action Plan."
            },
            {
                "dimension": "Target Audience & Business Driver",
                "soc2": "B2B SaaS and cloud vendors responding to customer security questionnaires and enterprise procurement due diligence.",
                "iso27001": "Global enterprises seeking international credibility, government tenders, cross-border business, and structured security governance.",
                "nist_csf": "Organizations establishing or maturing their cybersecurity risk strategy, aligning technical controls to business risk, or complying with U.S. federal directives."
            }
        ],
        "framework_details": {
            "soc2": {
                "name": "SOC 2 (Trust Services Criteria)",
                "version": "2017 with 2022 Revised Points of Focus",
                "type": "Attestation Examination (CPA Firm)",
                "key_components": [
                    "Security (Common Criteria CC1.1 - CC9.2) - Mandatory baseline",
                    "Availability (A1.1 - A1.3) - System uptime and performance",
                    "Processing Integrity (PI1.1 - PI1.5) - Complete, valid, accurate processing",
                    "Confidentiality (C1.1 - C1.2) - Protection of sensitive business data",
                    "Privacy (P1.1 - P8.1) - Collection, use, retention of personal info"
                ],
                "type1_vs_type2": "Type I tests control design at a single point in time (e.g., as of June 30). Type II tests operational effectiveness over a review period (typically 6 or 12 months) with auditor sampling.",
                "strengths": "Directly required by North American enterprise buyers; provides granular test procedures and auditor test results in Section IV."
            },
            "iso27001": {
                "name": "ISO/IEC 27001:2022",
                "version": "2022 Revision (Streamlined from 114 to 93 controls)",
                "type": "Accredited Management System Certification",
                "key_components": [
                    "Clauses 4-10: Context, Leadership, Planning, Support, Operation, Evaluation, Improvement",
                    "Theme 5 (Organizational Controls): 37 controls (Policies, Supplier security, Incident planning)",
                    "Theme 6 (People Controls): 8 controls (Screening, Awareness, Remote work)",
                    "Theme 7 (Physical Controls): 14 controls (Perimeters, Physical entry, Clear desk)",
                    "Theme 8 (Technological Controls): 34 controls (Access rights, Secure auth, Cryptography, Logging)"
                ],
                "soa_explanation": "Statement of Applicability (SoA) lists all 93 controls, stating whether each is included or excluded, with formal justification and implementation status.",
                "strengths": "Globally recognized across Europe, Asia, and Latin America; focuses on ongoing management accountability and continuous improvement (PDCA cycle)."
            },
            "nist_csf": {
                "name": "NIST Cybersecurity Framework (CSF) 2.0",
                "version": "2.0 (Released February 2024)",
                "type": "Voluntary Risk-Based Guidance (Non-Certifiable)",
                "key_components": [
                    "GOVERN (GV): Cybersecurity strategy, roles, policy, and supply chain risk",
                    "IDENTIFY (ID): Asset management, risk assessment, and vulnerability discovery",
                    "PROTECT (PR): Identity, access control, awareness, data security, and resilience",
                    "DETECT (DE): Continuous monitoring, anomaly analysis, and adverse event alerts",
                    "RESPOND (RS): Incident management, triage, mitigation, and coordination",
                    "RECOVER (RC): Incident recovery, restoration planning, and public communication"
                ],
                "govern_addition": "CSF 2.0 introduced the GOVERN function, elevating cybersecurity governance, risk appetite, and third-party supply chain oversight to executive and board visibility.",
                "strengths": "Flexible, outcome-oriented taxonomy that bridges the gap between technical practitioners and executive leadership without prescriptive compliance overhead."
            }
        },
        "overlaps": [
            {
                "topic": "Authentication & Access Control",
                "soc2_ref": "CC6.1, CC6.2, CC6.3",
                "iso27001_ref": "A.5.15, A.5.18, A.8.2, A.8.5",
                "nist_csf_ref": "PR.AA-01, PR.AA-03",
                "overlap_summary": "All three frameworks demand least privilege, formal access approval, periodic entitlement reviews, and mandatory Multi-Factor Authentication (MFA) for administrative access."
            },
            {
                "topic": "Cryptography & Data Protection",
                "soc2_ref": "CC6.6, CC6.7",
                "iso27001_ref": "A.8.24",
                "nist_csf_ref": "PR.DS-01, PR.DS-02",
                "overlap_summary": "All three require strong encryption of customer data at rest (e.g. AES-256) and in transit over open networks (e.g. TLS 1.3), alongside secure key management lifecycle."
            },
            {
                "topic": "Incident Response & Reporting",
                "soc2_ref": "CC7.3, CC7.4",
                "iso27001_ref": "A.5.24, A.5.25, A.5.26",
                "nist_csf_ref": "RS.MA-01, RS.AN-03, RS.CO-02",
                "overlap_summary": "All three mandate a documented incident response plan, incident classification, root cause analysis, evidence preservation, and defined communication protocols."
            },
            {
                "topic": "Security Event Logging & Monitoring",
                "soc2_ref": "CC7.2",
                "iso27001_ref": "A.8.15, A.8.16",
                "nist_csf_ref": "DE.CM-01, DE.AE-02",
                "overlap_summary": "All three require centralized event logging, system clock synchronization (NTP), SIEM correlation, log protection against tampering, and active alert response."
            },
            {
                "topic": "Third-Party & Vendor Risk Management",
                "soc2_ref": "CC9.2",
                "iso27001_ref": "A.5.19, A.5.20, A.5.21",
                "nist_csf_ref": "GV.SC-04, GV.SC-06",
                "overlap_summary": "All three require screening suppliers, evaluating third-party SOC 2/ISO reports, establishing contractual security agreements (DPAs), and monitoring vendor risks."
            }
        ],
        "key_differences": [
            {
                "aspect": "Nature of Standard",
                "explanation": "ISO 27001 specifies requirements for an Information Security Management System (ISMS). SOC 2 evaluates operational security controls against AICPA Trust Services Criteria. NIST CSF provides a flexible risk-management language and outcome taxonomy."
            },
            {
                "aspect": "Certification vs Attestation",
                "explanation": "ISO 27001 results in a formal Certificate of Registration from an accredited certification body. SOC 2 results in an Independent Service Auditor's Attestation Report from a CPA firm. NIST CSF confers NO certification."
            },
            {
                "aspect": "Mandatory Management Clauses",
                "explanation": "ISO 27001 strictly requires Clauses 4-10 (Context, Leadership, Planning, Internal Audits, Management Reviews). SOC 2 and NIST CSF evaluate control outcomes without prescribing an ISO-style management framework."
            },
            {
                "aspect": "Testing Depth in Final Report",
                "explanation": "A SOC 2 Type II report publishes the auditor's exact sampling method and test results in Section IV. An ISO 27001 certificate is a 1-page document with no public testing detail (the detailed audit report remains confidential between the registrar and company)."
            }
        ]
    }
