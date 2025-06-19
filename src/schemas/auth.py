from pydantic import BaseModel
from src.schemas.user import User  # Import Pydantic schema, not SQLAlchemy model
from typing import Optional, List

class LoginSuccessResponse(BaseModel):
    success: bool
    message: str
    user: User
    session_id: str

class CurrentUser(BaseModel):
    id: int  # Changed from str to int to match the SQLAlchemy model
    user_id: str
    email: str
    first_name: str
    last_name: str
    is_active: bool
    roles: Optional[List[str]] = []  # List of role names
    permissions: Optional[List[str]] = []  # List of permission names

    model_config = {"from_attributes": True}  # Pydantic v2 syntax

class GetCurrentUserResponse(BaseModel):
    success: bool
    message: str
    user: CurrentUser

class SessionResponse(BaseModel):
    session_id: str
    user_agent: Optional[str]
    ip_address: Optional[str]
    created_at: str
    updated_at: str
    expires_at: Optional[str]

    model_config = {"from_attributes": True}  # Pydantic v2 syntax
