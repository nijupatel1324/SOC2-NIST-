from typing import List
from app.models import AuditFinding, CorrectiveAction
from app.schemas.finding import (
    FindingResponse,
    FindingDetailResponse,
    CorrectiveActionResponse
)


def format_action_response(action: CorrectiveAction) -> CorrectiveActionResponse:
    """Serializes a CorrectiveAction ORM instance to a Pydantic schema."""
    return CorrectiveActionResponse(
        id=action.id,
        organization_id=action.organization_id,
        finding_id=action.finding_id,
        action_plan=action.action_plan,
        owner_id=action.owner_id,
        owner_name=action.owner.full_name if action.owner else None,
        target_completion_date=action.target_completion_date,
        actual_completion_date=action.actual_completion_date,
        status=action.status,
        notes=action.notes,
        created_at=action.created_at,
        updated_at=action.updated_at
    )


def format_finding_response(finding: AuditFinding) -> FindingResponse:
    """Serializes an AuditFinding ORM instance to a summary Pydantic schema."""
    action_count = len(finding.corrective_actions) if hasattr(finding, "corrective_actions") and finding.corrective_actions else 0

    return FindingResponse(
        id=finding.id,
        organization_id=finding.organization_id,
        finding_id=finding.finding_id,
        title=finding.title,
        severity=finding.severity,
        status=finding.status,
        control_id=finding.control_id,
        control_code=finding.control.control_id if finding.control else None,
        control_name=finding.control.name if finding.control else None,
        control_test_id=finding.control_test_id,
        test_title=finding.control_test.test_title if finding.control_test else None,
        root_cause=finding.root_cause,
        business_impact=finding.business_impact,
        owner_id=finding.owner_id,
        owner_name=finding.owner.full_name if finding.owner else None,
        due_date=finding.due_date,
        closed_at=finding.closed_at,
        closed_by_id=finding.closed_by_id,
        closed_by_name=finding.closed_by.full_name if finding.closed_by else None,
        action_count=action_count,
        created_at=finding.created_at,
        updated_at=finding.updated_at
    )


def format_finding_detail_response(finding: AuditFinding) -> FindingDetailResponse:
    """Serializes an AuditFinding ORM instance with its full list of corrective action plans."""
    base = format_finding_response(finding)
    actions = [
        format_action_response(a)
        for a in (finding.corrective_actions or [])
    ]

    return FindingDetailResponse(
        **base.model_dump(),
        corrective_actions=actions
    )
