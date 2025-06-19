from pydantic import BaseModel, EmailStr, Field, field_validator
from pydantic import ValidationInfo
from typing import Optional, List, Any
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str

class UserData(UserBase):
    password: str

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    confirm_password: str

    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info: ValidationInfo) -> str:
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('passwords do not match')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(UserBase):
    id: int
    user_id: str
    is_active: bool
    roles: Optional[List[str]] = []  # List of role names
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}  # Updated from Config class in Pydantic v2

    @field_validator('roles', mode='before')
    @classmethod
    def roles_to_names(cls, v: Any) -> List[str]:
        if not v:
            return []
        if isinstance(v, list):
            if len(v) > 0 and hasattr(v[0], 'name'):
                return [role.name for role in v]
            return v
        return []

class TokenData(BaseModel):
    email: Optional[str] = None

class OTPSent(BaseModel):
    success: bool
    message: str

class VerifyUser(BaseModel):
    email: EmailStr
    otp: str

class RequestPasswordReset(BaseModel):
    email: EmailStr

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    email: EmailStr
    otp: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str

    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info: ValidationInfo) -> str:
        if 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('passwords do not match')
        return v

class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str

    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info: ValidationInfo) -> str:
        if 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('passwords do not match')
        return v


class RegistrationResponse(BaseModel):
    success: bool
    message: str

class UserCreateWithRole(UserCreate):
    """User creation with optional initial role assignment"""
    initial_roles: Optional[List[str]] = Field(default=[], description="List of role names to assign to the new user")
