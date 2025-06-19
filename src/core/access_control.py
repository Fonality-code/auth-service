from functools import wraps
from typing import List, Optional, Union, Callable, Any
from fastapi import HTTPException, Depends, Request
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.services.role import get_role_service
from src.models.user import User
import inspect

class AccessControl:
    def __init__(self):
        self.role_service = get_role_service()

    def require_roles(self, required_roles: Union[str, List[str]], require_all: bool = False):
        """
        Decorator to require specific roles for accessing an endpoint

        Args:
            required_roles: Single role name or list of role names
            require_all: If True, user must have ALL roles. If False, user needs ANY role.
        """
        if isinstance(required_roles, str):
            required_roles = [required_roles]

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract current_user from function parameters
                current_user = None
                db = None

                # Look for current_user in kwargs (dependency injection)
                if 'current_user' in kwargs:
                    current_user = kwargs['current_user']
                elif 'db_user' in kwargs:
                    current_user = kwargs['db_user']

                # Look for db session
                if 'db' in kwargs:
                    db = kwargs['db']

                if not current_user or not isinstance(current_user, User):
                    raise HTTPException(
                        status_code=401,
                        detail="Authentication required"
                    )

                if not db:
                    raise HTTPException(
                        status_code=500,
                        detail="Database session not available"
                    )

                # Check roles
                user_roles = [role.name for role in current_user.roles if role.is_active]

                if require_all:
                    # User must have ALL required roles
                    if not all(role in user_roles for role in required_roles):
                        missing_roles = [role for role in required_roles if role not in user_roles]
                        raise HTTPException(
                            status_code=403,
                            detail=f"Insufficient permissions. Missing roles: {', '.join(missing_roles)}"
                        )
                else:
                    # User must have AT LEAST ONE required role
                    if not any(role in user_roles for role in required_roles):
                        raise HTTPException(
                            status_code=403,
                            detail=f"Insufficient permissions. Required roles: {', '.join(required_roles)}"
                        )

                # Call the original function
                if inspect.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            return wrapper
        return decorator

    def require_permissions(self, required_permissions: Union[str, List[str]], require_all: bool = False):
        """
        Decorator to require specific permissions for accessing an endpoint

        Args:
            required_permissions: Single permission name or list of permission names
            require_all: If True, user must have ALL permissions. If False, user needs ANY permission.
        """
        if isinstance(required_permissions, str):
            required_permissions = [required_permissions]

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract current_user from function parameters
                current_user = None
                db = None

                # Look for current_user in kwargs (dependency injection)
                if 'current_user' in kwargs:
                    current_user = kwargs['current_user']
                elif 'db_user' in kwargs:
                    current_user = kwargs['db_user']

                # Look for db session
                if 'db' in kwargs:
                    db = kwargs['db']

                if not current_user or not isinstance(current_user, User):
                    raise HTTPException(
                        status_code=401,
                        detail="Authentication required"
                    )

                if not db:
                    raise HTTPException(
                        status_code=500,
                        detail="Database session not available"
                    )

                # Check permissions
                user_permissions = self.role_service.get_user_permissions(db, current_user.user_id)
                user_permission_names = [perm.name for perm in user_permissions]

                if require_all:
                    # User must have ALL required permissions
                    if not all(perm in user_permission_names for perm in required_permissions):
                        missing_perms = [perm for perm in required_permissions if perm not in user_permission_names]
                        raise HTTPException(
                            status_code=403,
                            detail=f"Insufficient permissions. Missing permissions: {', '.join(missing_perms)}"
                        )
                else:
                    # User must have AT LEAST ONE required permission
                    if not any(perm in user_permission_names for perm in required_permissions):
                        raise HTTPException(
                            status_code=403,
                            detail=f"Insufficient permissions. Required permissions: {', '.join(required_permissions)}"
                        )

                # Call the original function
                if inspect.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            return wrapper
        return decorator

    def require_resource_permission(self, resource: str, action: str):
        """
        Decorator to require resource-action permission for accessing an endpoint

        Args:
            resource: The resource name (e.g., 'user', 'role', 'session')
            action: The action name (e.g., 'create', 'read', 'update', 'delete')
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract current_user from function parameters
                current_user = None
                db = None

                # Look for current_user in kwargs (dependency injection)
                if 'current_user' in kwargs:
                    current_user = kwargs['current_user']
                elif 'db_user' in kwargs:
                    current_user = kwargs['db_user']

                # Look for db session
                if 'db' in kwargs:
                    db = kwargs['db']

                if not current_user or not isinstance(current_user, User):
                    raise HTTPException(
                        status_code=401,
                        detail="Authentication required"
                    )

                if not db:
                    raise HTTPException(
                        status_code=500,
                        detail="Database session not available"
                    )

                # Check resource permission
                has_permission = self.role_service.user_has_resource_permission(
                    db, current_user.user_id, resource, action
                )

                if not has_permission:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Insufficient permissions. Required: {action} access to {resource}"
                    )

                # Call the original function
                if inspect.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            return wrapper
        return decorator

    def require_self_or_admin(self, user_id_param: str = "user_id"):
        """
        Decorator to require that the user is either accessing their own data or has admin role

        Args:
            user_id_param: The name of the parameter that contains the user_id being accessed
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract current_user from function parameters
                current_user = None
                target_user_id = None

                # Look for current_user in kwargs (dependency injection)
                if 'current_user' in kwargs:
                    current_user = kwargs['current_user']
                elif 'db_user' in kwargs:
                    current_user = kwargs['db_user']

                # Look for the target user_id
                if user_id_param in kwargs:
                    target_user_id = kwargs[user_id_param]

                if not current_user or not isinstance(current_user, User):
                    raise HTTPException(
                        status_code=401,
                        detail="Authentication required"
                    )

                # Check if user is accessing their own data or has admin role
                is_self = current_user.user_id == target_user_id
                is_admin = current_user.has_role('admin') or current_user.has_role('super_admin')

                if not (is_self or is_admin):
                    raise HTTPException(
                        status_code=403,
                        detail="Access denied. You can only access your own data or need admin privileges."
                    )

                # Call the original function
                if inspect.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            return wrapper
        return decorator

# Create a singleton instance
access_control = AccessControl()

# Convenience functions for common access control patterns
def require_admin(func: Callable) -> Callable:
    """Shortcut decorator for admin-only endpoints"""
    return access_control.require_roles("admin")(func)

def require_super_admin(func: Callable) -> Callable:
    """Shortcut decorator for super admin-only endpoints"""
    return access_control.require_roles("super_admin")(func)

def require_super_admin(func: Callable) -> Callable:
    """Shortcut decorator for super admin-only endpoints"""
    return access_control.require_roles("super_admin")(func)

def require_admin_or_moderator(func: Callable) -> Callable:
    """Shortcut decorator for admin or moderator access"""
    return access_control.require_roles(["admin", "moderator"], require_all=False)(func)

def require_user_management(func: Callable) -> Callable:
    """Shortcut decorator for user management permissions"""
    return access_control.require_resource_permission("user", "manage")(func)

def require_role_management(func: Callable) -> Callable:
    """Shortcut decorator for role management permissions"""
    return access_control.require_resource_permission("role", "manage")(func)
