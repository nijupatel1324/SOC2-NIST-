from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Form
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import verify_password, create_access_token
from app.core.logging import log_security_event
from app.core.rate_limit import login_rate_limiter
from app.core.auth import get_current_user, get_current_user_optional
from app.db.session import get_db
from app.models import User, UserRole, AuditEvent
from app.schemas.auth import LoginRequest, TokenResponse, UserResponse

router = APIRouter(tags=["Authentication"])
templates = Jinja2Templates(directory=settings.TEMPLATES_DIR)


# ==============================================================================
# REST API Endpoints (JSON / Tokens)
# ==============================================================================

@router.post(f"{settings.API_V1_STR}/auth/login", response_model=TokenResponse)
async def api_login(
    login_data: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Authenticates a user via JSON payload.
    Enforces rate-limiting, emits security audit logs, returns a JWT bearer token,
    and sets a secure HttpOnly session cookie.
    """
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{login_data.email.lower()}"
    login_rate_limiter.check_rate_limit(rate_key, client_ip=client_ip)

    user = db.query(User).filter(User.email == login_data.email.lower()).first()

    if not user or not verify_password(login_data.password, user.hashed_password):
        log_security_event(
            event_type="AUTH_FAILURE",
            status="FAILURE",
            user_email=login_data.email,
            client_ip=client_ip,
            resource="/api/v1/auth/login",
            details={"reason": "Invalid credentials"},
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        log_security_event(
            event_type="AUTH_BLOCKED_INACTIVE",
            status="BLOCKED",
            user_email=user.email,
            org_id=user.organization_id,
            client_ip=client_ip,
            resource="/api/v1/auth/login",
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact compliance administrator."
        )

    # Update last login timestamp
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token(subject=user.email)

    # Set secure HttpOnly session cookie
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )

    log_security_event(
        event_type="AUTH_SUCCESS",
        status="SUCCESS",
        user_email=user.email,
        org_id=user.organization_id,
        client_ip=client_ip,
        resource="/api/v1/auth/login",
        details={"role": user.role.value},
        severity="INFO"
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        user=UserResponse.model_validate(user)
    )


@router.post(f"{settings.API_V1_STR}/auth/logout")
async def api_logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user)
):
    """
    Terminates session, clears cookie, and logs logout audit event.
    """
    response.delete_cookie(key=settings.COOKIE_NAME, path="/")
    client_ip = request.client.host if request.client else "unknown"

    log_security_event(
        event_type="AUTH_LOGOUT",
        status="SUCCESS",
        user_email=current_user.email,
        org_id=current_user.organization_id,
        client_ip=client_ip,
        resource="/api/v1/auth/logout"
    )
    return {"message": "Successfully logged out"}


@router.get(f"{settings.API_V1_STR}/auth/me", response_model=UserResponse)
async def api_me(current_user: User = Depends(get_current_user)):
    """
    Returns current authenticated user profile and permissions.
    """
    return UserResponse.model_validate(current_user)


# ==============================================================================
# Web HTML Form Routes (Browser Session)
# ==============================================================================

@router.get("/login", response_class=HTMLResponse)
async def web_login_page(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Renders login HTML page. Redirects to homepage if already authenticated.
    """
    if current_user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"request": request, "settings": settings, "title": "Sign In - Cybersecurity GRC"}
    )


@router.post("/login", response_class=HTMLResponse)
async def web_login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Handles HTML login form submission with redirect or inline error alerts.
    """
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{email.strip().lower()}"

    try:
        login_rate_limiter.check_rate_limit(rate_key, client_ip=client_ip)
    except HTTPException as e:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "settings": settings,
                "error": e.detail,
                "email": email
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS
        )

    user = db.query(User).filter(User.email == email.strip().lower()).first()

    if not user or not verify_password(password, user.hashed_password):
        log_security_event(
            event_type="AUTH_FAILURE",
            status="FAILURE",
            user_email=email,
            client_ip=client_ip,
            resource="/login",
            details={"channel": "web_form"},
            severity="WARNING"
        )
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "settings": settings,
                "error": "Invalid email or password",
                "email": email
            },
            status_code=status.HTTP_401_UNAUTHORIZED
        )

    if not user.is_active:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "settings": settings,
                "error": "Account is deactivated. Contact compliance administrator.",
                "email": email
            },
            status_code=status.HTTP_403_FORBIDDEN
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token(subject=user.email)
    redirect_resp = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    redirect_resp.set_cookie(
        key=settings.COOKIE_NAME,
        value=token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )

    log_security_event(
        event_type="AUTH_SUCCESS",
        status="SUCCESS",
        user_email=user.email,
        org_id=user.organization_id,
        client_ip=client_ip,
        resource="/login",
        details={"channel": "web_form", "role": user.role.value}
    )

    return redirect_resp


@router.get("/logout")
async def web_logout(request: Request, response: Response):
    """
    Clears session cookie and redirects user to login page.
    """
    redirect_resp = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    redirect_resp.delete_cookie(key=settings.COOKIE_NAME, path="/")
    return redirect_resp
