import enum


class UserRole(str, enum.Enum):
    PLATFORM_ADMIN = "PLATFORM_ADMIN"
    ORG_ADMIN = "ORG_ADMIN"
    GRC_ANALYST = "GRC_ANALYST"
    CONTROL_OWNER = "CONTROL_OWNER"
    AUDITOR = "AUDITOR"


class ImplementationStatus(str, enum.Enum):
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    PARTIALLY_IMPLEMENTED = "PARTIALLY_IMPLEMENTED"
    IMPLEMENTED = "IMPLEMENTED"
    NEEDS_IMPROVEMENT = "NEEDS_IMPROVEMENT"


class TestingFrequency(str, enum.Enum):
    __test__ = False  # Prevents pytest collection warning
    CONTINUOUS = "CONTINUOUS"
    MONTHLY = "MONTHLY"
    QUARTERLY = "QUARTERLY"
    SEMI_ANNUALLY = "SEMI_ANNUALLY"
    ANNUALLY = "ANNUALLY"


class MappingApprovalStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AssessmentStatus(str, enum.Enum):
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    PARTIALLY_IMPLEMENTED = "PARTIALLY_IMPLEMENTED"
    IMPLEMENTED = "IMPLEMENTED"
    NEEDS_IMPROVEMENT = "NEEDS_IMPROVEMENT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskTreatmentStrategy(str, enum.Enum):
    MITIGATE = "MITIGATE"
    ACCEPT = "ACCEPT"
    TRANSFER = "TRANSFER"
    AVOID = "AVOID"


class RiskStatus(str, enum.Enum):
    IDENTIFIED = "IDENTIFIED"
    IN_TREATMENT = "IN_TREATMENT"
    TREATED = "TREATED"
    ACCEPTED = "ACCEPTED"
    CLOSED = "CLOSED"


class EvidenceReviewStatus(str, enum.Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class TestResult(str, enum.Enum):
    __test__ = False  # Prevents pytest from attempting to collect this enum as a test class
    PENDING = "PENDING"
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    REMEDIATION_IN_PROGRESS = "REMEDIATION_IN_PROGRESS"
    RETESTING = "RETESTING"
    CLOSED = "CLOSED"
    RISK_ACCEPTED = "RISK_ACCEPTED"


class ActionStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    IMPLEMENTED = "IMPLEMENTED"
    VERIFIED = "VERIFIED"
    CANCELLED = "CANCELLED"
