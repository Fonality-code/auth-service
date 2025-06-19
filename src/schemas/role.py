from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class PermissionBase(BaseModel):
    name: str = Field(..., description="Unique permission name")
    display_name: str = Field(..., description="Human-readable permission name")
    description: Optional[str] = None
    resource: str = Field(..., description="Resource this permission applies to")
    action: str = Field(..., description="Action this permission allows")

class PermissionCreate(PermissionBase):
    pass

class Permission(PermissionBase):
    permission_id: str
    is_system_permission: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

class RoleBase(BaseModel):
    name: str = Field(..., description="Unique role name")
    display_name: str = Field(..., description="Human-readable role name")
    description: Optional[str] = None

class RoleCreate(RoleBase):
    permission_ids: Optional[List[str]] = Field(default=[], description="List of permission IDs to assign to this role")

class RoleUpdate(BaseModel):
    display_name: Optional[str] = None
    description: Optional[str] = None
    permission_ids: Optional[List[str]] = None
    is_active: Optional[bool] = None

class Role(RoleBase):
    role_id: str
    is_system_role: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    permissions: List[Permission] = []

    model_config = {"from_attributes": True}

class RoleAssignmentBase(BaseModel):
    user_id: str
    role_id: str
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None

class RoleAssignmentCreate(RoleAssignmentBase):
    pass

class RoleAssignment(RoleAssignmentBase):
    assignment_id: str
    assigned_by: Optional[str] = None
    assigned_at: datetime
    is_active: bool
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    revoke_reason: Optional[str] = None

    model_config = {"from_attributes": True}

class UserWithRoles(BaseModel):
    user_id: str
    email: str
    first_name: str
    last_name: str
    is_active: bool
    roles: List[Role] = []
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

class RolePermissionUpdate(BaseModel):
    permission_ids: List[str] = Field(..., description="List of permission IDs to assign to the role")

class BulkRoleAssignment(BaseModel):
    user_ids: List[str] = Field(..., description="List of user IDs to assign the role to")
    role_id: str = Field(..., description="Role ID to assign")
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None
