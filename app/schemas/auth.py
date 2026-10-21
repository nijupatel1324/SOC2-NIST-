from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from app.models.enums import UserRole


class LoginRequest(BaseModel):
    """
    Credentials submitted for authentication.
    """
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User cleartext password")


class UserResponse(BaseModel):
    """
    Serialized user profile response without password hash.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: str
    role: UserRole
    organization_id: Optional[int]
    is_active: bool


class TokenResponse(BaseModel):
    """
    JSON response containing JWT bearer access token and user metadata.
    """
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: UserResponse


class UserCreate(BaseModel):
    """
    Schema for creating a new user within an organization.
    """
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=2)
    role: UserRole = UserRole.GRC_ANALYST
    organization_id: Optional[int] = None
