from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from src.core.database import get_db
from src.services.role import get_role_service
from src.schemas.role import (
    Role, RoleCreate, RoleUpdate, Permission, PermissionCreate,
    RoleAssignmentCreate, UserWithRoles,
    RolePermissionUpdate, BulkRoleAssignment
)
from src.schemas.response import APIResponse
from src.models.user import User
from src.core.access_control import (
    require_admin, require_role_management, require_super_admin,
    access_control
)
from src.api.v1.endpoints.auth import get_current_user_from_token

router = APIRouter()
role_service = get_role_service()

# Role Management Endpoints

@router.post("/roles", response_model=Role)
@require_role_management
def create_role(
    role_data: RoleCreate,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> Role:
    """Create a new role (Admin only)"""
    # Check if role name already exists
    existing_role = role_service.get_role_by_name(db, role_data.name)
    if existing_role:
        raise HTTPException(
            status_code=400,
            detail=f"Role with name '{role_data.name}' already exists"
        )

    return role_service.create_role(db, role_data, current_user.user_id)

@router.get("/roles", response_model=List[Role])
def get_roles(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    active_only: bool = Query(True),
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> List[Role]:
    """Get all roles with pagination"""
    # Regular users can see roles but with limited info
    db_roles = role_service.get_roles(db, skip=skip, limit=limit, active_only=active_only)

    # Convert to Pydantic models
    roles = [Role.model_validate(role) for role in db_roles]

    # If user is not admin, filter out sensitive information
    if not current_user.has_role('admin') and not current_user.has_role('super_admin'):
        # Return basic role info only
        for role in roles:
            role.permissions = []  # Hide permissions from non-admin users

    return roles

@router.get("/roles/{role_id}", response_model=Role)
def get_role(
    role_id: str,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> Role:
    """Get a specific role by ID"""
    db_role = role_service.get_role(db, role_id)
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")

    role = Role.model_validate(db_role)

    # If user is not admin, filter out sensitive information
    if not current_user.has_role('admin') and not current_user.has_role('super_admin'):
        role.permissions = []  # Hide permissions from non-admin users

    return role

@router.put("/roles/{role_id}", response_model=Role)
@require_role_management
def update_role(
    role_id: str,
    role_data: RoleUpdate,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> Role:
    """Update a role (Admin only)"""
    updated_role = role_service.update_role(db, role_id, role_data)
    if not updated_role:
        raise HTTPException(status_code=404, detail="Role not found")

    return updated_role

@router.delete("/roles/{role_id}")
@require_role_management
def delete_role(
    role_id: str,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """Delete a role (Admin only)"""
    success = role_service.delete_role(db, role_id)
    if not success:
        raise HTTPException(
            status_code=400,
            detail="Role not found or cannot be deleted (system role)"
        )

    return APIResponse(success=True, message="Role deleted successfully")

# Permission Management Endpoints

@router.post("/permissions", response_model=Permission)
@require_admin
def create_permission(
    permission_data: PermissionCreate,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> Permission:
    """Create a new permission (Super Admin only)"""
    # Check if permission name already exists
    existing_permission = role_service.get_permission_by_name(db, permission_data.name)
    if existing_permission:
        raise HTTPException(
            status_code=400,
            detail=f"Permission with name '{permission_data.name}' already exists"
        )

    return role_service.create_permission(db, permission_data)

@router.get("/permissions", response_model=List[Permission])
def get_permissions(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    resource: Optional[str] = Query(None),
    active_only: bool = Query(True),
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> List[Permission]:
    """Get all permissions with optional filtering"""
    db_permissions = role_service.get_permissions(
        db, skip=skip, limit=limit, resource=resource, active_only=active_only
    )
    return [Permission.model_validate(perm) for perm in db_permissions]

@router.put("/roles/{role_id}/permissions", response_model=Role)
@require_role_management
def update_role_permissions(
    role_id: str,
    permission_update: RolePermissionUpdate,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> Role:
    """Update permissions for a role (Admin only)"""
    role_data = RoleUpdate(permission_ids=permission_update.permission_ids)
    updated_role = role_service.update_role(db, role_id, role_data)
    if not updated_role:
        raise HTTPException(status_code=404, detail="Role not found")

    return updated_role

# User Role Assignment Endpoints

@router.post("/users/{user_id}/roles", response_model=APIResponse)
@access_control.require_resource_permission("user", "manage")
def assign_role_to_user(
    user_id: str,
    assignment_data: RoleAssignmentCreate,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """Assign a role to a user (Admin only)"""
    assignment = role_service.assign_role_to_user(
        db=db,
        user_id=assignment_data.user_id,
        role_id=assignment_data.role_id,
        assigned_by=current_user.user_id,
        expires_at=assignment_data.expires_at,
        reason=assignment_data.reason
    )

    if not assignment:
        raise HTTPException(
            status_code=400,
            detail="Failed to assign role. User or role not found, or assignment already exists."
        )

    return APIResponse(success=True, message="Role assigned successfully")

@router.delete("/users/{user_id}/roles/{role_id}")
@access_control.require_resource_permission("user", "manage")
def revoke_role_from_user(
    user_id: str,
    role_id: str,
    reason: Optional[str] = Query(None, description="Reason for revoking the role"),
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """Revoke a role from a user (Admin only)"""
    success = role_service.revoke_role_from_user(
        db=db,
        user_id=user_id,
        role_id=role_id,
        revoked_by=current_user.user_id,
        reason=reason
    )

    if not success:
        raise HTTPException(
            status_code=400,
            detail="Failed to revoke role. Role assignment not found or already inactive."
        )

    return APIResponse(success=True, message="Role revoked successfully")

@router.get("/users/{user_id}/roles", response_model=List[Role])
@access_control.require_self_or_admin("user_id")
def get_user_roles(
    user_id: str,
    active_only: bool = Query(True),
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> List[Role]:
    """Get all roles for a user"""
    db_roles = role_service.get_user_roles(db, user_id, active_only=active_only)
    return [Role.model_validate(role) for role in db_roles]

@router.get("/users/{user_id}/permissions", response_model=List[Permission])
@access_control.require_self_or_admin("user_id")
def get_user_permissions(
    user_id: str,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> List[Permission]:
    """Get all permissions for a user through their roles"""
    db_permissions = role_service.get_user_permissions(db, user_id)
    return [Permission.model_validate(perm) for perm in db_permissions]

@router.get("/roles/{role_id}/users", response_model=List[UserWithRoles])
@require_admin
def get_role_users(
    role_id: str,
    active_only: bool = Query(True),
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> List[UserWithRoles]:
    """Get all users with a specific role (Admin only)"""
    users = role_service.get_role_users(db, role_id, active_only=active_only)
    return [UserWithRoles.model_validate(user) for user in users]

@router.post("/roles/{role_id}/users/bulk-assign")
@require_role_management
def bulk_assign_role(
    role_id: str,
    bulk_assignment: BulkRoleAssignment,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """Assign a role to multiple users (Admin only)"""
    assignments = role_service.bulk_assign_role(
        db=db,
        user_ids=bulk_assignment.user_ids,
        role_id=bulk_assignment.role_id,
        assigned_by=current_user.user_id,
        expires_at=bulk_assignment.expires_at,
        reason=bulk_assignment.reason
    )

    return APIResponse(
        success=True,
        message=f"Role assigned to {len(assignments)} users successfully"
    )

# Utility Endpoints

@router.post("/maintenance/cleanup-expired-assignments")
@require_admin
def cleanup_expired_assignments(
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """Clean up expired role assignments (Admin only)"""
    count = role_service.cleanup_expired_assignments(db)
    return APIResponse(
        success=True,
        message=f"Cleaned up {count} expired role assignments"
    )

@router.get("/users/{user_id}/access-check")
@access_control.require_self_or_admin("user_id")
def check_user_access(
    user_id: str,
    role: Optional[str] = Query(None, description="Role name to check"),
    permission: Optional[str] = Query(None, description="Permission name to check"),
    resource: Optional[str] = Query(None, description="Resource name to check"),
    action: Optional[str] = Query(None, description="Action name to check"),
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """Check if a user has specific access (role, permission, or resource-action)"""
    results = {}

    if role:
        results['has_role'] = role_service.user_has_role(db, user_id, role)

    if permission:
        results['has_permission'] = role_service.user_has_permission(db, user_id, permission)

    if resource and action:
        results['has_resource_permission'] = role_service.user_has_resource_permission(
            db, user_id, resource, action
        )

    return APIResponse(
        success=True,
        message="Access check completed",
        data=results
    )

# Admin endpoints for system management
@router.post("/admin/init-system")
@require_super_admin
def initialize_system(
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """Initialize or re-initialize the role and permission system (Super Admin only)"""
    try:
        from src.core.init_roles import init_default_roles_and_permissions
        result = init_default_roles_and_permissions(db)
        return APIResponse(
            success=True,
            message="System initialized successfully",
            data=result
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initialize system: {str(e)}"
        )

@router.post("/admin/migrate-users")
@require_super_admin
def migrate_existing_users(
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """Assign default roles to existing users who don't have any roles (Super Admin only)"""
    try:
        from src.utils.migrations import run_user_role_migration
        result = run_user_role_migration()
        return APIResponse(
            success=result["success"],
            message=f"Migration completed. Updated {result.get('users_updated', 0)} users",
            data=result
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to migrate users: {str(e)}"
        )
