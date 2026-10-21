from typing import Optional, List, Callable
import jwt
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import log_security_event
from app.db.session import get_db
from app.models import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=False
)


def extract_token_from_request(request: Request, bearer_token: Optional[str] = None) -> Optional[str]:
    """
    Extracts authentication token from:
    1. Authorization Bearer dependency or raw header
    2. Secure HttpOnly session cookie
    """
    if bearer_token and isinstance(bearer_token, str):
        return bearer_token
    
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    cookie_token = request.cookies.get(settings.COOKIE_NAME)
    if cookie_token:
        return cookie_token
    return None


async def get_current_user(
    request: Request,
    bearer_token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Validates token and returns current authenticated user.
    Enforces that user is active in the database.
    """
    token = extract_token_from_request(request, bearer_token)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token claims",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.PyJWTError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        log_security_event(
            event_type="INACTIVE_USER_BLOCKED",
            status="BLOCKED",
            user_email=user.email,
            org_id=user.organization_id,
            client_ip=request.client.host if request.client else "unknown",
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact your compliance administrator."
        )

    return user


async def get_current_user_optional(
    request: Request,
    bearer_token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Optional user dependency: returns authenticated User if logged in, or None if anonymous.
    Used for web pages and public documentation views.
    """
    try:
        return await get_current_user(request, bearer_token, db)
    except HTTPException:
        return None


def require_role(*allowed_roles: UserRole) -> Callable:
    """
    Role-Based Access Control (RBAC) dependency factory.
    Platform Administrator has global override rights.
    """
    async def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user)
    ) -> User:
        # Platform Admin has global administrative privileges
        if current_user.role == UserRole.PLATFORM_ADMIN:
            return current_user

        if current_user.role in allowed_roles:
            return current_user

        client_ip = request.client.host if request.client else "unknown"
        log_security_event(
            event_type="ACCESS_DENIED_INSUFFICIENT_ROLE",
            status="BLOCKED",
            user_email=current_user.email,
            org_id=current_user.organization_id,
            client_ip=client_ip,
            resource=request.url.path,
            details={
                "user_role": current_user.role.value,
                "required_roles": [r.value for r in allowed_roles]
            },
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access forbidden: requires one of roles {[r.value for r in allowed_roles]}"
        )

    return role_checker


def check_org_access(
    current_user: User,
    target_org_id: int,
    request: Optional[Request] = None
) -> None:
    """
    Validates organization boundary.
    Prevents cross-tenant data leakage between organizations.
    """
    # Platform Admin can view across organizations
    if current_user.role == UserRole.PLATFORM_ADMIN:
        return

    # User must belong to the target organization
    if current_user.organization_id == target_org_id:
        return

    client_ip = request.client.host if request and request.client else "unknown"
    path = request.url.path if request else "internal"
    log_security_event(
        event_type="CROSS_ORG_ACCESS_ATTEMPT",
        status="BLOCKED",
        user_email=current_user.email,
        org_id=current_user.organization_id,
        client_ip=client_ip,
        resource=path,
        details={
            "user_org_id": current_user.organization_id,
            "target_org_id": target_org_id
        },
        severity="CRITICAL"
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Cross-organization data access strictly prohibited."
    )
