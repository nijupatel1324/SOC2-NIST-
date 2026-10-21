import os
import re
import hashlib
from pathlib import Path
from typing import Tuple, Optional
from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import EvidenceRecord, AuditProject, ControlTest
from app.schemas.evidence import EvidenceResponse, EvidenceIntegrityCheck
from app.schemas.audit import AuditProjectResponse, ControlTestResponse


DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "bash", "ps1", "vbs", "js", "jar",
    "msi", "com", "scr", "pif", "py", "php", "asp", "aspx"
}


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes filename to prevent directory traversal and special character injection.
    """
    # Strip any leading directory components
    base = Path(filename).name
    # Keep only alphanumeric, hyphens, underscores, and dots
    clean = re.sub(r"[^\w\.\-]", "_", base)
    return clean or "uploaded_evidence"


def calculate_bytes_sha256(content: bytes) -> str:
    """Computes SHA-256 cryptographic digest of in-memory bytes."""
    h = hashlib.sha256()
    h.update(content)
    return h.hexdigest()


def calculate_file_sha256(file_path: Path) -> str:
    """Computes SHA-256 cryptographic digest of a file on disk reading in 64KB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def validate_evidence_file(file_name: str, file_size: int, content_type: Optional[str] = None) -> str:
    """
    Validates uploaded file against size limits, whitelisted extensions, and security policies.
    Returns cleaned filename.
    """
    clean_name = sanitize_filename(file_name)
    ext = clean_name.split(".")[-1].lower() if "." in clean_name else ""

    if not ext:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a valid file extension."
        )

    if ext in DANGEROUS_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Executable and script files (.{ext}) are strictly prohibited in the Evidence Vault."
        )

    if ext not in settings.allowed_extensions_set:
        allowed = ", ".join(sorted(list(settings.allowed_extensions_set)))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension '.{ext}' is not permitted. Allowed extensions: {allowed}"
        )

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if file_size > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds maximum threshold of {settings.MAX_UPLOAD_SIZE_MB} MB."
        )

    return clean_name


def save_evidence_file(file_name: str, content: bytes, org_id: int) -> Tuple[Path, str, int]:
    """
    Persists file into quarantined evidence storage, computes SHA-256 fingerprint,
    and returns (stored_path, sha256_hash, file_size_bytes).
    """
    upload_dir = settings.resolved_upload_dir
    clean_name = validate_evidence_file(file_name, len(content))

    # Calculate SHA-256 hash before saving
    sha256_hash = calculate_bytes_sha256(content)

    # Prefix with timestamp and short hash to avoid collisions
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    stored_name = f"org{org_id}_{timestamp}_{sha256_hash[:8]}_{clean_name}"
    stored_path = upload_dir / stored_name

    with open(stored_path, "wb") as f:
        f.write(content)

    return stored_path, sha256_hash, len(content)


def verify_evidence_integrity(evidence: EvidenceRecord) -> EvidenceIntegrityCheck:
    """
    Performs cryptographic tamper detection by comparing the disk file hash
    with the database SHA-256 signature recorded at upload time.
    """
    file_path = Path(evidence.stored_file_path)
    if not file_path.is_absolute():
        file_path = settings.BASE_DIR / file_path

    if not file_path.exists():
        return EvidenceIntegrityCheck(
            evidence_id=evidence.id,
            file_name=evidence.file_name,
            database_hash=evidence.sha256_hash,
            calculated_hash="FILE_NOT_FOUND_ON_DISK",
            is_valid=False,
            status="FILE_MISSING",
            verified_at=datetime.now(timezone.utc)
        )

    current_hash = calculate_file_sha256(file_path)
    is_valid = (current_hash.lower() == evidence.sha256_hash.lower())

    return EvidenceIntegrityCheck(
        evidence_id=evidence.id,
        file_name=evidence.file_name,
        database_hash=evidence.sha256_hash,
        calculated_hash=current_hash,
        is_valid=is_valid,
        status="VERIFIED_INTACT" if is_valid else "INTEGRITY_COMPROMISED",
        verified_at=datetime.now(timezone.utc)
    )


def format_evidence_response(evidence: EvidenceRecord) -> EvidenceResponse:
    """Helper to convert EvidenceRecord ORM object into EvidenceResponse schema."""
    return EvidenceResponse(
        id=evidence.id,
        organization_id=evidence.organization_id,
        control_id=evidence.control_id,
        control_code=evidence.control.control_id if evidence.control else None,
        control_name=evidence.control.name if evidence.control else None,
        title=evidence.title,
        description=evidence.description,
        file_name=evidence.file_name,
        file_size_bytes=evidence.file_size_bytes,
        mime_type=evidence.mime_type,
        sha256_hash=evidence.sha256_hash,
        uploaded_by_id=evidence.uploaded_by_id,
        uploaded_by_name=evidence.uploaded_by.full_name if evidence.uploaded_by else None,
        review_status=evidence.review_status,
        reviewed_by_id=evidence.reviewed_by_id,
        reviewed_by_name=evidence.reviewed_by.full_name if evidence.reviewed_by else None,
        reviewed_at=evidence.reviewed_at,
        retention_date=evidence.retention_date,
        created_at=evidence.created_at,
        updated_at=evidence.updated_at
    )


def format_audit_project_response(project: AuditProject) -> AuditProjectResponse:
    """Helper to convert AuditProject ORM entity into AuditProjectResponse schema."""
    return AuditProjectResponse(
        id=project.id,
        organization_id=project.organization_id,
        name=project.name,
        framework_id=project.framework_id,
        framework_code=project.framework.code,
        framework_name=project.framework.name,
        audit_type=project.audit_type,
        period_start=project.period_start,
        period_end=project.period_end,
        lead_auditor_id=project.lead_auditor_id,
        lead_auditor_name=project.lead_auditor.full_name if project.lead_auditor else None,
        status=project.status,
        tests_count=len(project.tests),
        created_at=project.created_at
    )


def format_control_test_response(test: ControlTest) -> ControlTestResponse:
    """Helper to convert ControlTest ORM entity into ControlTestResponse schema."""
    return ControlTestResponse(
        id=test.id,
        organization_id=test.organization_id,
        audit_project_id=test.audit_project_id,
        audit_project_name=test.audit_project.name if test.audit_project else None,
        control_id=test.control_id,
        control_code=test.control.control_id,
        control_name=test.control.name,
        test_title=test.test_title,
        test_objective=test.test_objective,
        test_procedure=test.test_procedure,
        result=test.result,
        tested_by_id=test.tested_by_id,
        tested_by_name=test.tested_by.full_name if test.tested_by else None,
        tested_at=test.tested_at,
        sample_size=test.sample_size,
        exceptions_identified=test.exceptions_identified,
        evidence_id=test.evidence_id,
        evidence_file_name=test.evidence.file_name if test.evidence else None,
        evidence_hash=test.evidence.sha256_hash if test.evidence else None,
        notes=test.notes,
        created_at=test.created_at
    )
