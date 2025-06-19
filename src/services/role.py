from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from src.models.role import Role, Permission, UserRoleAssignment, user_roles, role_permissions
from src.models.user import User
from src.schemas.role import RoleCreate, RoleUpdate, PermissionCreate, RoleAssignmentCreate
import uuid

class RoleService:
    def __init__(self):
        pass

    # Role management methods
    def create_role(self, db: Session, role_data: RoleCreate, created_by: Optional[str] = None) -> Role:
        """Create a new role with permissions"""
        db_role = Role(
            name=role_data.name,
            display_name=role_data.display_name,
            description=role_data.description,
            created_by=created_by
        )
        db.add(db_role)
        db.flush()  # Get the ID without committing

        # Assign permissions if provided
        if role_data.permission_ids:
            permissions = db.query(Permission).filter(
                Permission.permission_id.in_(role_data.permission_ids)
            ).all()
            db_role.permissions.extend(permissions)

        db.commit()
        db.refresh(db_role)
        return db_role

    def get_role(self, db: Session, role_id: str) -> Optional[Role]:
        """Get role by ID"""
        return db.query(Role).filter(Role.role_id == role_id).first()

    def get_role_by_name(self, db: Session, name: str) -> Optional[Role]:
        """Get role by name"""
        return db.query(Role).filter(Role.name == name).first()

    def get_roles(self, db: Session, skip: int = 0, limit: int = 100, active_only: bool = True) -> List[Role]:
        """Get all roles with pagination"""
        query = db.query(Role)
        if active_only:
            query = query.filter(Role.is_active == True)
        return query.offset(skip).limit(limit).all()

    def update_role(self, db: Session, role_id: str, role_data: RoleUpdate) -> Optional[Role]:
        """Update a role"""
        db_role = self.get_role(db, role_id)
        if not db_role:
            return None

        if db_role.is_system_role:
            # Only allow updating description and status for system roles
            if role_data.description is not None:
                db_role.description = role_data.description
            if role_data.is_active is not None:
                db_role.is_active = role_data.is_active
        else:
            # Update all fields for custom roles
            if role_data.display_name is not None:
                db_role.display_name = role_data.display_name
            if role_data.description is not None:
                db_role.description = role_data.description
            if role_data.is_active is not None:
                db_role.is_active = role_data.is_active

        # Update permissions if provided
        if role_data.permission_ids is not None:
            # Clear existing permissions
            db_role.permissions.clear()
            # Add new permissions
            if role_data.permission_ids:
                permissions = db.query(Permission).filter(
                    Permission.permission_id.in_(role_data.permission_ids)
                ).all()
                db_role.permissions.extend(permissions)

        db.commit()
        db.refresh(db_role)
        return db_role

    def delete_role(self, db: Session, role_id: str) -> bool:
        """Delete a role (soft delete by deactivating)"""
        db_role = self.get_role(db, role_id)
        if not db_role or db_role.is_system_role:
            return False

        db_role.is_active = False
        db.commit()
        return True

    # Permission management methods
    def create_permission(self, db: Session, permission_data: PermissionCreate) -> Permission:
        """Create a new permission"""
        db_permission = Permission(
            name=permission_data.name,
            display_name=permission_data.display_name,
            description=permission_data.description,
            resource=permission_data.resource,
            action=permission_data.action
        )
        db.add(db_permission)
        db.commit()
        db.refresh(db_permission)
        return db_permission

    def get_permission(self, db: Session, permission_id: str) -> Optional[Permission]:
        """Get permission by ID"""
        return db.query(Permission).filter(Permission.permission_id == permission_id).first()

    def get_permission_by_name(self, db: Session, name: str) -> Optional[Permission]:
        """Get permission by name"""
        return db.query(Permission).filter(Permission.name == name).first()

    def get_permissions(self, db: Session, skip: int = 0, limit: int = 100,
                       resource: Optional[str] = None, active_only: bool = True) -> List[Permission]:
        """Get all permissions with optional filtering"""
        query = db.query(Permission)
        if active_only:
            query = query.filter(Permission.is_active == True)
        if resource:
            query = query.filter(Permission.resource == resource)
        return query.offset(skip).limit(limit).all()

    # User role assignment methods
    def assign_role_to_user(self, db: Session, user_id: str, role_id: str,
                           assigned_by: Optional[str] = None, expires_at: Optional[datetime] = None,
                           reason: Optional[str] = None) -> Optional[UserRoleAssignment]:
        """Assign a role to a user"""
        # Check if user and role exist
        user = db.query(User).filter(User.user_id == user_id).first()
        role = db.query(Role).filter(Role.role_id == role_id).first()

        if not user or not role:
            return None

        # Check if assignment already exists and is active
        existing = db.query(UserRoleAssignment).filter(
            and_(
                UserRoleAssignment.user_id == user_id,
                UserRoleAssignment.role_id == role_id,
                UserRoleAssignment.is_active == True
            )
        ).first()

        if existing:
            return existing

        # Create new assignment
        assignment = UserRoleAssignment(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by,
            expires_at=expires_at,
            reason=reason
        )
        db.add(assignment)
        db.commit()
        db.refresh(assignment)
        return assignment

    def revoke_role_from_user(self, db: Session, user_id: str, role_id: str,
                             revoked_by: Optional[str] = None, reason: Optional[str] = None) -> bool:
        """Revoke a role from a user"""
        assignment = db.query(UserRoleAssignment).filter(
            and_(
                UserRoleAssignment.user_id == user_id,
                UserRoleAssignment.role_id == role_id,
                UserRoleAssignment.is_active == True
            )
        ).first()

        if not assignment:
            return False

        assignment.is_active = False
        assignment.revoked_at = datetime.now()
        assignment.revoked_by = revoked_by
        assignment.revoke_reason = reason

        db.commit()
        return True

    def get_user_roles(self, db: Session, user_id: str, active_only: bool = True) -> List[Role]:
        """Get all roles for a user"""
        query = db.query(Role).join(user_roles).filter(user_roles.c.user_id == user_id)
        if active_only:
            query = query.filter(
                and_(
                    Role.is_active == True,
                    user_roles.c.is_active == True
                )
            )
        return query.all()

    def get_role_users(self, db: Session, role_id: str, active_only: bool = True) -> List[User]:
        """Get all users with a specific role"""
        query = db.query(User).join(user_roles).filter(user_roles.c.role_id == role_id)
        if active_only:
            query = query.filter(
                and_(
                    User.is_active == True,
                    user_roles.c.is_active == True
                )
            )
        return query.all()

    def user_has_role(self, db: Session, user_id: str, role_name: str) -> bool:
        """Check if a user has a specific role"""
        return db.query(User).join(user_roles).join(Role).filter(
            and_(
                User.user_id == user_id,
                Role.name == role_name,
                Role.is_active == True,
                user_roles.c.is_active == True
            )
        ).first() is not None

    def user_has_permission(self, db: Session, user_id: str, permission_name: str) -> bool:
        """Check if a user has a specific permission through their roles"""
        return db.query(Permission).join(role_permissions).join(Role).join(user_roles).filter(
            and_(
                user_roles.c.user_id == user_id,
                Permission.name == permission_name,
                Permission.is_active == True,
                Role.is_active == True,
                user_roles.c.is_active == True
            )
        ).first() is not None

    def user_has_resource_permission(self, db: Session, user_id: str, resource: str, action: str) -> bool:
        """Check if a user has permission for a specific resource and action"""
        return db.query(Permission).join(role_permissions).join(Role).join(user_roles).filter(
            and_(
                user_roles.c.user_id == user_id,
                Permission.resource == resource,
                Permission.action == action,
                Permission.is_active == True,
                Role.is_active == True,
                user_roles.c.is_active == True
            )
        ).first() is not None

    def get_user_permissions(self, db: Session, user_id: str) -> List[Permission]:
        """Get all permissions a user has through their roles"""
        return db.query(Permission).join(role_permissions).join(Role).join(user_roles).filter(
            and_(
                user_roles.c.user_id == user_id,
                Permission.is_active == True,
                Role.is_active == True,
                user_roles.c.is_active == True
            )
        ).distinct().all()

    def bulk_assign_role(self, db: Session, user_ids: List[str], role_id: str,
                        assigned_by: Optional[str] = None, expires_at: Optional[datetime] = None,
                        reason: Optional[str] = None) -> List[UserRoleAssignment]:
        """Assign a role to multiple users"""
        assignments = []
        for user_id in user_ids:
            assignment = self.assign_role_to_user(
                db, user_id, role_id, assigned_by, expires_at, reason
            )
            if assignment:
                assignments.append(assignment)
        return assignments

    def cleanup_expired_assignments(self, db: Session) -> int:
        """Clean up expired role assignments"""
        count = db.query(UserRoleAssignment).filter(
            and_(
                UserRoleAssignment.expires_at < datetime.now(),
                UserRoleAssignment.is_active == True
            )
        ).update({UserRoleAssignment.is_active: False})

        db.commit()
        return count

# Create a singleton instance
role_service = RoleService()

def get_role_service() -> RoleService:
    """Get the role service instance"""
    return role_service
