from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Query, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.core.logging import log_security_event
from app.core.auth import get_current_user, get_current_user_optional, require_role, check_org_access
from app.db.session import get_db
from app.models import (
    EvidenceRecord,
    SecurityControl,
    User,
    UserRole,
    EvidenceReviewStatus,
    AuditEvent
)
from app.schemas.evidence import (
    EvidenceResponse,
    EvidenceReviewRequest,
    EvidenceIntegrityCheck
)
from app.services.evidence_service import (
    save_evidence_file,
    verify_evidence_integrity,
    format_evidence_response
)

router = APIRouter(tags=["Evidence Management Vault"])
templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)


# ==============================================================================
# Module F: REST API Endpoints
# ==============================================================================

@router.get(f"{settings.API_V1_STR}/evidence", response_model=List[EvidenceResponse])
async def api_list_evidence(
    control_id: Optional[int] = None,
    review_status: Optional[EvidenceReviewStatus] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists evidence artifacts for the user's organization.
    Supports filtering by linked control, review status, and search query.
    """
    org_id = current_user.organization_id or 1
    query = db.query(EvidenceRecord).filter(EvidenceRecord.organization_id == org_id).options(
        joinedload(EvidenceRecord.control),
        joinedload(EvidenceRecord.uploaded_by),
        joinedload(EvidenceRecord.reviewed_by)
    )

    if control_id:
        query = query.filter(EvidenceRecord.control_id == control_id)

    if review_status:
        query = query.filter(EvidenceRecord.review_status == review_status)

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (EvidenceRecord.title.ilike(s)) |
            (EvidenceRecord.file_name.ilike(s)) |
            (EvidenceRecord.description.ilike(s))
        )

    records = query.order_by(EvidenceRecord.created_at.desc()).all()
    return [format_evidence_response(e) for e in records]


@router.post(f"{settings.API_V1_STR}/evidence/upload", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def api_upload_evidence(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    control_id: Optional[int] = Form(None),
    file: UploadFile = File(...),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Secure file upload endpoint.
    Enforces extension whitelisting, file size restrictions, anti-traversal sanitization,
    quarantined storage, and automatic SHA-256 integrity hash calculation.
    """
    org_id = current_user.organization_id or 1

    # Verify control belongs to this org if linked
    if control_id:
        ctrl = db.query(SecurityControl).filter(
            SecurityControl.id == control_id,
            SecurityControl.organization_id == org_id
        ).first()
        if not ctrl:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked security control not found.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file cannot be empty.")

    stored_path, sha256_hash, file_size = save_evidence_file(file.filename, content, org_id)

    new_evidence = EvidenceRecord(
        organization_id=org_id,
        control_id=control_id,
        title=title.strip(),
        description=description.strip(),
        file_name=file.filename,
        stored_file_path=str(stored_path),
        file_size_bytes=file_size,
        mime_type=file.content_type or "application/octet-stream",
        sha256_hash=sha256_hash,
        uploaded_by_id=current_user.id,
        review_status=EvidenceReviewStatus.PENDING_REVIEW
    )
    db.add(new_evidence)
    db.flush()

    # Audit Event
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="EVIDENCE_UPLOADED",
        resource_type="EvidenceRecord",
        resource_id=new_evidence.id,
        details=f'{{"file_name": "{new_evidence.file_name}", "sha256": "{sha256_hash}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(new_evidence)

    log_security_event(
        event_type="EVIDENCE_UPLOADED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Evidence:{new_evidence.id}"
    )

    return format_evidence_response(new_evidence)


@router.get(f"{settings.API_V1_STR}/evidence/{{evidence_id}}", response_model=EvidenceResponse)
async def api_get_evidence(
    evidence_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves evidence metadata and verification details.
    """
    org_id = current_user.organization_id or 1
    evidence = db.query(EvidenceRecord).filter(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.organization_id == org_id
    ).options(
        joinedload(EvidenceRecord.control),
        joinedload(EvidenceRecord.uploaded_by),
        joinedload(EvidenceRecord.reviewed_by)
    ).first()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found.")

    check_org_access(current_user, evidence.organization_id, request=request)
    return format_evidence_response(evidence)


@router.get(f"{settings.API_V1_STR}/evidence/{{evidence_id}}/download")
async def api_download_evidence(
    evidence_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Secure evidence file streaming endpoint with tenant isolation checks.
    """
    org_id = current_user.organization_id or 1
    evidence = db.query(EvidenceRecord).filter(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.organization_id == org_id
    ).first()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file not found.")

    file_path = Path(evidence.stored_file_path)
    if not file_path.is_absolute():
        file_path = settings.BASE_DIR / file_path

    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File content missing from storage vault.")

    # Log audit event for evidence retrieval
    log_security_event(
        event_type="EVIDENCE_DOWNLOADED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"EvidenceFile:{evidence.file_name}"
    )

    return FileResponse(
        path=str(file_path),
        media_type=evidence.mime_type,
        filename=evidence.file_name
    )


@router.get(f"{settings.API_V1_STR}/evidence/{{evidence_id}}/verify", response_model=EvidenceIntegrityCheck)
@router.post(f"{settings.API_V1_STR}/evidence/{{evidence_id}}/verify", response_model=EvidenceIntegrityCheck)
async def api_verify_evidence(
    evidence_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Performs real-time cryptographic tamper detection.
    Recalculates the SHA-256 hash of the physical disk file and compares it
    to the recorded database checksum.
    """
    org_id = current_user.organization_id or 1
    evidence = db.query(EvidenceRecord).filter(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.organization_id == org_id
    ).first()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found.")

    check = verify_evidence_integrity(evidence)

    log_security_event(
        event_type="EVIDENCE_INTEGRITY_VERIFIED",
        status="SUCCESS" if check.is_valid else "COMPROMISED",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Evidence:{evidence.id}",
        severity="INFO" if check.is_valid else "CRITICAL"
    )

    return check


@router.post(f"{settings.API_V1_STR}/evidence/{{evidence_id}}/review", response_model=EvidenceResponse)
async def api_review_evidence(
    evidence_id: int,
    review_in: EvidenceReviewRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Auditor / GRC review sign-off endpoint for verifying or rejecting uploaded audit evidence.
    """
    org_id = current_user.organization_id or 1
    evidence = db.query(EvidenceRecord).filter(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.organization_id == org_id
    ).options(
        joinedload(EvidenceRecord.control),
        joinedload(EvidenceRecord.uploaded_by),
        joinedload(EvidenceRecord.reviewed_by)
    ).first()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found.")

    evidence.review_status = review_in.status
    evidence.reviewed_by_id = current_user.id
    evidence.reviewed_at = datetime.now(timezone.utc)
    evidence.updated_at = datetime.now(timezone.utc)

    # Audit Trail
    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="EVIDENCE_REVIEWED",
        resource_type="EvidenceRecord",
        resource_id=evidence.id,
        details=f'{{"status": "{review_in.status.value}", "notes": "{review_in.review_notes or ""}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()
    db.refresh(evidence)

    log_security_event(
        event_type="EVIDENCE_REVIEWED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Evidence:{evidence.id}->{review_in.status.value}"
    )

    return format_evidence_response(evidence)


@router.delete(f"{settings.API_V1_STR}/evidence/{{evidence_id}}", status_code=status.HTTP_204_NO_CONTENT)
async def api_delete_evidence(
    evidence_id: int,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Deletes an evidence artifact and removes the underlying file from the storage vault.
    """
    org_id = current_user.organization_id or 1
    evidence = db.query(EvidenceRecord).filter(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.organization_id == org_id
    ).first()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found.")

    file_path = Path(evidence.stored_file_path)
    if not file_path.is_absolute():
        file_path = settings.BASE_DIR / file_path

    # Safely remove file from disk
    if file_path.exists():
        try:
            os.remove(file_path)
        except Exception:
            pass

    fn = evidence.file_name
    db.delete(evidence)

    audit_evt = AuditEvent(
        organization_id=org_id,
        user_id=current_user.id,
        action="EVIDENCE_DELETED",
        resource_type="EvidenceRecord",
        resource_id=evidence_id,
        details=f'{{"file_name": "{fn}"}}',
        ip_address=request.client.host if request.client else "unknown"
    )
    db.add(audit_evt)
    db.commit()

    log_security_event(
        event_type="EVIDENCE_DELETED",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=org_id,
        resource=f"Evidence:{evidence_id}",
        severity="WARNING"
    )
    return None


# ==============================================================================
# Module F: Web UI HTML Views
# ==============================================================================

@router.get("/evidence", response_class=HTMLResponse)
async def web_evidence_vault(
    request: Request,
    status_filter: Optional[str] = Query(None),
    verified_id: Optional[int] = Query(None),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Renders Evidence Management Vault dashboard (Module F).
    """
    org_id = current_user.organization_id if current_user else 1
    query = db.query(EvidenceRecord).filter(EvidenceRecord.organization_id == org_id).options(
        joinedload(EvidenceRecord.control),
        joinedload(EvidenceRecord.uploaded_by),
        joinedload(EvidenceRecord.reviewed_by)
    )

    if status_filter and status_filter in [s.value for s in EvidenceReviewStatus]:
        query = query.filter(EvidenceRecord.review_status == EvidenceReviewStatus(status_filter))

    records = query.order_by(EvidenceRecord.created_at.desc()).all()
    all_controls = db.query(SecurityControl).filter(SecurityControl.organization_id == org_id).order_by(SecurityControl.control_id).all()

    # Verification banner if requested
    verification_result = None
    if verified_id:
        v_rec = db.query(EvidenceRecord).filter(EvidenceRecord.id == verified_id, EvidenceRecord.organization_id == org_id).first()
        if v_rec:
            verification_result = verify_evidence_integrity(v_rec)

    all_org_records = db.query(EvidenceRecord).filter(EvidenceRecord.organization_id == org_id).all()
    counts = {
        "ALL": len(all_org_records),
        "APPROVED": sum(1 for e in all_org_records if e.review_status == EvidenceReviewStatus.APPROVED),
        "PENDING_REVIEW": sum(1 for e in all_org_records if e.review_status == EvidenceReviewStatus.PENDING_REVIEW),
        "REJECTED": sum(1 for e in all_org_records if e.review_status == EvidenceReviewStatus.REJECTED),
        "EXPIRED": sum(1 for e in all_org_records if e.review_status == EvidenceReviewStatus.EXPIRED),
    }

    return templates.TemplateResponse(
        request=request,
        name="evidence.html",
        context={
            "request": request,
            "settings": settings,
            "user": current_user,
            "records": records,
            "controls": all_controls,
            "counts": counts,
            "active_status": status_filter or "ALL",
            "verification_result": verification_result,
            "title": "Evidence Management Vault | CyberGRC"
        }
    )


@router.post("/evidence/upload", response_class=RedirectResponse)
async def web_upload_evidence_form(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    control_id: Optional[int] = Form(None),
    file: UploadFile = File(...),
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.CONTROL_OWNER)),
    db: Session = Depends(get_db)
):
    """
    Processes HTML multipart upload form submission.
    """
    org_id = current_user.organization_id or 1
    content = await file.read()
    if content:
        stored_path, sha256_hash, file_size = save_evidence_file(file.filename, content, org_id)
        new_evidence = EvidenceRecord(
            organization_id=org_id,
            control_id=control_id or None,
            title=title.strip(),
            description=description.strip(),
            file_name=file.filename,
            stored_file_path=str(stored_path),
            file_size_bytes=file_size,
            mime_type=file.content_type or "application/octet-stream",
            sha256_hash=sha256_hash,
            uploaded_by_id=current_user.id,
            review_status=EvidenceReviewStatus.PENDING_REVIEW
        )
        db.add(new_evidence)
        db.commit()

    return RedirectResponse(url="/evidence", status_code=status.HTTP_302_FOUND)


@router.post("/evidence/{evidence_id}/review", response_class=RedirectResponse)
async def web_review_evidence_form(
    evidence_id: int,
    request: Request,
    action: str = Form(...),  # "APPROVE" or "REJECT"
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST, UserRole.AUDITOR)),
    db: Session = Depends(get_db)
):
    """
    Processes 1-click review decision from web UI.
    """
    org_id = current_user.organization_id or 1
    evidence = db.query(EvidenceRecord).filter(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.organization_id == org_id
    ).first()

    if evidence:
        evidence.review_status = EvidenceReviewStatus.APPROVED if action == "APPROVE" else EvidenceReviewStatus.REJECTED
        evidence.reviewed_by_id = current_user.id
        evidence.reviewed_at = datetime.now(timezone.utc)
        db.commit()

    return RedirectResponse(url="/evidence", status_code=status.HTTP_302_FOUND)


@router.post("/evidence/{evidence_id}/delete", response_class=RedirectResponse)
async def web_delete_evidence_form(
    evidence_id: int,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ORG_ADMIN, UserRole.GRC_ANALYST)),
    db: Session = Depends(get_db)
):
    """
    Processes delete action from web UI.
    """
    org_id = current_user.organization_id or 1
    evidence = db.query(EvidenceRecord).filter(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.organization_id == org_id
    ).first()

    if evidence:
        p = Path(evidence.stored_file_path)
        if not p.is_absolute():
            p = settings.BASE_DIR / p
        if p.exists():
            try:
                os.remove(p)
            except Exception:
                pass
        db.delete(evidence)
        db.commit()

    return RedirectResponse(url="/evidence", status_code=status.HTTP_302_FOUND)
