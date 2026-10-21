from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.models import (
    Organization,
    Framework,
    SecurityControl,
    ControlTest,
    EvidenceRecord,
    AuditFinding,
    TestResult,
    FindingStatus,
    FindingSeverity,
    ImplementationStatus
)
from app.services.assessment_service import get_framework_readiness_summaries
from app.services.risk_service import get_risk_matrix_summary


def compile_executive_readiness_metrics(db: Session, org_id: int) -> Dict[str, Any]:
    """
    Aggregates compliance readiness across all modules:
    - Framework readiness percentages (SOC 2, ISO 27001, NIST CSF 2.0)
    - Inherent vs Residual risk reduction %
    - Evidence coverage of implemented controls
    - Audit testing pass/fail ratios
    - Open audit deficiencies and CAPA remediation metrics
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    org_name = org.name if org else "Enterprise Organization"

    # 1. Framework Readiness Summaries
    fw_summaries = get_framework_readiness_summaries(db, org_id)
    fw_dict = {f.framework_code: f for f in fw_summaries}

    # 2. Risk Reduction Metrics
    risk_summary = get_risk_matrix_summary(db, org_id)

    # 3. Security Controls & Evidence Coverage
    all_controls = db.query(SecurityControl).filter(SecurityControl.organization_id == org_id).all()
    total_controls = len(all_controls)
    implemented_controls = [c for c in all_controls if c.implementation_status == ImplementationStatus.IMPLEMENTED]
    partially_implemented = [c for c in all_controls if c.implementation_status == ImplementationStatus.PARTIALLY_IMPLEMENTED]

    # Controls with attached evidence
    controls_with_evidence = db.query(EvidenceRecord.control_id).filter(
        EvidenceRecord.organization_id == org_id,
        EvidenceRecord.control_id.isnot(None)
    ).distinct().count()

    evidence_coverage_pct = round((controls_with_evidence / total_controls * 100.0), 1) if total_controls > 0 else 0.0

    # 4. Control Testing Statistics
    all_tests = db.query(ControlTest).filter(ControlTest.organization_id == org_id).all()
    total_tests = len(all_tests)
    pass_tests = sum(1 for t in all_tests if t.result == TestResult.PASS)
    fail_tests = sum(1 for t in all_tests if t.result == TestResult.FAIL)
    pending_tests = sum(1 for t in all_tests if t.result == TestResult.PENDING)
    inconclusive_tests = sum(1 for t in all_tests if t.result == TestResult.INCONCLUSIVE)
    pass_rate_pct = round((pass_tests / total_tests * 100.0), 1) if total_tests > 0 else 0.0

    # 5. Audit Findings & Remediation Progress
    all_findings = db.query(AuditFinding).filter(AuditFinding.organization_id == org_id).all()
    total_findings = len(all_findings)
    open_findings = sum(1 for f in all_findings if f.status == FindingStatus.OPEN)
    in_remediation = sum(1 for f in all_findings if f.status == FindingStatus.REMEDIATION_IN_PROGRESS)
    retesting = sum(1 for f in all_findings if f.status == FindingStatus.RETESTING)
    closed_findings = sum(1 for f in all_findings if f.status == FindingStatus.CLOSED)
    risk_accepted_findings = sum(1 for f in all_findings if f.status == FindingStatus.RISK_ACCEPTED)

    critical_active = sum(1 for f in all_findings if f.severity == FindingSeverity.CRITICAL and f.status != FindingStatus.CLOSED)
    high_active = sum(1 for f in all_findings if f.severity == FindingSeverity.HIGH and f.status != FindingStatus.CLOSED)

    return {
        "organization_id": org_id,
        "organization_name": org_name,
        "generated_at": datetime.now(timezone.utc),
        "frameworks": fw_summaries,
        "framework_dict": fw_dict,
        "soc2_readiness": fw_dict.get("SOC2").weighted_readiness_pct if "SOC2" in fw_dict else 0.0,
        "iso27001_readiness": fw_dict.get("ISO27001").weighted_readiness_pct if "ISO27001" in fw_dict else 0.0,
        "nist_csf_readiness": fw_dict.get("NIST_CSF").weighted_readiness_pct if "NIST_CSF" in fw_dict else 0.0,
        "risk_summary": risk_summary,
        "risk_reduction_pct": risk_summary.risk_reduction_pct,
        "controls": {
            "total": total_controls,
            "implemented": len(implemented_controls),
            "partially_implemented": len(partially_implemented),
            "with_evidence": controls_with_evidence,
            "evidence_coverage_pct": evidence_coverage_pct
        },
        "tests": {
            "total": total_tests,
            "pass": pass_tests,
            "fail": fail_tests,
            "pending": pending_tests,
            "inconclusive": inconclusive_tests,
            "pass_rate_pct": pass_rate_pct
        },
        "findings": {
            "total": total_findings,
            "open": open_findings,
            "in_remediation": in_remediation,
            "retesting": retesting,
            "closed": closed_findings,
            "risk_accepted": risk_accepted_findings,
            "critical_active": critical_active,
            "high_active": high_active
        }
    }


def generate_markdown_readiness_report(metrics: Dict[str, Any]) -> str:
    """
    Generates a structured, audit-ready Markdown report suitable for CPA auditors or board presentations.
    """
    org_name = metrics["organization_name"]
    ts = metrics["generated_at"].strftime("%Y-%m-%d %H:%M UTC")
    soc2 = metrics["soc2_readiness"]
    iso = metrics["iso27001_readiness"]
    nist = metrics["nist_csf_readiness"]
    risk_red = metrics["risk_reduction_pct"]
    ev_cov = metrics["controls"]["evidence_coverage_pct"]

    md = f"""# Executive Cybersecurity Compliance & Audit Readiness Report
**Organization:** {org_name}  
**Assessment Date:** {ts}  
**Platform:** CyberGRC Compliance Management Platform  

---

> [!IMPORTANT]
> **Independent Assurance & Legal Boundary Notice**  
> This document represents an internal cybersecurity readiness self-assessment. **Software cannot issue an official SOC 2 Type I/II examination report** (which strictly requires an independent examination by a licensed CPA firm under AICPA SSAE 18 standards) or an **ISO/IEC 27001 certificate** (which requires an accredited certification body registrar). **NIST CSF 2.0 is a voluntary risk management framework and is non-certifiable.**

---

## 1. Executive Summary & Headline Indicators

| Metric / Benchmark | Score | Status / Target |
|:---|:---:|:---|
| **SOC 2 Type II Readiness** | **{soc2}%** | Target: &ge; 90% prior to external CPA testing window |
| **ISO/IEC 27001:2022 Readiness** | **{iso}%** | Target: &ge; 85% prior to Stage 1 Registrar Audit |
| **NIST CSF 2.0 Maturity Profile** | **{nist}%** | Target Tier 3 (Repeatable & Risk-Informed) |
| **Enterprise Risk Reduction** | **{risk_red}%** | Inherent Exposure reduced through active safeguards |
| **Control Evidence Vault Coverage** | **{ev_cov}%** | Percentage of controls with cryptographically verified artifacts |

---

## 2. Multi-Framework Compliance Crosswalk

| Framework Code | Issuing Body | Assurance Mechanism | Total Reqs | Implemented | Gaps | Strict % | Weighted % |
|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|
"""
    for fw in metrics["frameworks"]:
        md += f"| **{fw.framework_code}** | {fw.issuing_body} | {fw.assurance_type} | {fw.total_requirements} | {fw.implemented_count} | {fw.gap_count} | {fw.strict_readiness_pct}% | **{fw.weighted_readiness_pct}%** |\n"

    md += f"""
---

## 3. Threat Landscape & Risk Register Summary

- **Total Assessed Risk Scenarios:** {metrics["risk_summary"].total_risks}
- **Average Inherent Risk Score:** {metrics["risk_summary"].average_inherent_score}
- **Average Residual Risk Score Post-Treatment:** {metrics["risk_summary"].average_residual_score}
- **Net Enterprise Risk Reduction:** **{risk_red}%**
- **Risk Distribution (Inherent):**
  - Critical: {metrics["risk_summary"].inherent_critical_count}
  - High: {metrics["risk_summary"].inherent_high_count}
  - Medium: {metrics["risk_summary"].inherent_medium_count}
  - Low: {metrics["risk_summary"].inherent_low_count}

---

## 4. Control Testing & Evidence Verification

- **Total Testing Procedures Executed:** {metrics["tests"]["total"]}
- **Passed Tests (Effective):** {metrics["tests"]["pass"]} ({metrics["tests"]["pass_rate_pct"]}%)
- **Failed Tests (Exceptions):** {metrics["tests"]["fail"]}
- **Pending / Inconclusive:** {metrics["tests"]["pending"] + metrics["tests"]["inconclusive"]}
- **Controls Linked to Verified Evidence Vault:** {metrics["controls"]["with_evidence"]} of {metrics["controls"]["total"]} ({ev_cov}%)

---

## 5. Audit Findings & Corrective Action Plans (CAPA)

- **Total Non-Conformities Logged:** {metrics["findings"]["total"]}
- **Open Deficiencies:** {metrics["findings"]["open"]}
- **Active CAPA Remediation:** {metrics["findings"]["in_remediation"]}
- **Under Auditor Retesting:** {metrics["findings"]["retesting"]}
- **Closed & Verified:** {metrics["findings"]["closed"]}
- **Critical / High Severity Active:** {metrics["findings"]["critical_active"] + metrics["findings"]["high_active"]}

---

*Report generated by CyberGRC Platform &bull; Confidential & Proprietary.*
"""
    return md
