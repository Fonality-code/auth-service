from sqlalchemy.orm import Session
from src.models.role import Role, Permission
from src.services.role import get_role_service
from src.schemas.role import RoleCreate, PermissionCreate
from datetime import datetime
from typing import List, Dict, Any

class RoleInitializer:
    def __init__(self):
        self.role_service = get_role_service()

    def create_default_permissions(self, db: Session) -> Dict[str, Permission]:
        """Create default permissions for the system"""
        default_permissions = [
            # User management permissions
            {"name": "user.create", "display_name": "Create Users", "description": "Create new user accounts", "resource": "user", "action": "create"},
            {"name": "user.read", "display_name": "Read Users", "description": "View user information", "resource": "user", "action": "read"},
            {"name": "user.update", "display_name": "Update Users", "description": "Update user information", "resource": "user", "action": "update"},
            {"name": "user.delete", "display_name": "Delete Users", "description": "Delete user accounts", "resource": "user", "action": "delete"},
            {"name": "user.manage", "display_name": "Manage Users", "description": "Full user management access", "resource": "user", "action": "manage"},

            # Role management permissions
            {"name": "role.create", "display_name": "Create Roles", "description": "Create new roles", "resource": "role", "action": "create"},
            {"name": "role.read", "display_name": "Read Roles", "description": "View role information", "resource": "role", "action": "read"},
            {"name": "role.update", "display_name": "Update Roles", "description": "Update role information", "resource": "role", "action": "update"},
            {"name": "role.delete", "display_name": "Delete Roles", "description": "Delete roles", "resource": "role", "action": "delete"},
            {"name": "role.manage", "display_name": "Manage Roles", "description": "Full role management access", "resource": "role", "action": "manage"},

            # Permission management permissions
            {"name": "permission.create", "display_name": "Create Permissions", "description": "Create new permissions", "resource": "permission", "action": "create"},
            {"name": "permission.read", "display_name": "Read Permissions", "description": "View permission information", "resource": "permission", "action": "read"},
            {"name": "permission.update", "display_name": "Update Permissions", "description": "Update permission information", "resource": "permission", "action": "update"},
            {"name": "permission.delete", "display_name": "Delete Permissions", "description": "Delete permissions", "resource": "permission", "action": "delete"},
            {"name": "permission.manage", "display_name": "Manage Permissions", "description": "Full permission management access", "resource": "permission", "action": "manage"},

            # Session management permissions
            {"name": "session.read", "display_name": "Read Sessions", "description": "View session information", "resource": "session", "action": "read"},
            {"name": "session.manage", "display_name": "Manage Sessions", "description": "Manage user sessions", "resource": "session", "action": "manage"},
            {"name": "session.revoke", "display_name": "Revoke Sessions", "description": "Revoke user sessions", "resource": "session", "action": "revoke"},

            # System administration permissions
            {"name": "system.admin", "display_name": "System Administration", "description": "Full system administration access", "resource": "system", "action": "admin"},
            {"name": "system.audit", "display_name": "System Audit", "description": "View system audit logs", "resource": "system", "action": "audit"},
            {"name": "system.maintenance", "display_name": "System Maintenance", "description": "Perform system maintenance tasks", "resource": "system", "action": "maintenance"},

            # Profile management permissions
            {"name": "profile.read", "display_name": "Read Profile", "description": "View own profile", "resource": "profile", "action": "read"},
            {"name": "profile.update", "display_name": "Update Profile", "description": "Update own profile", "resource": "profile", "action": "update"},

            # Authentication permissions
            {"name": "auth.login", "display_name": "Login", "description": "Login to the system", "resource": "auth", "action": "login"},
            {"name": "auth.logout", "display_name": "Logout", "description": "Logout from the system", "resource": "auth", "action": "logout"},
            {"name": "auth.password_reset", "display_name": "Password Reset", "description": "Reset password", "resource": "auth", "action": "password_reset"},
        ]

        created_permissions = {}

        for perm_data in default_permissions:
            # Check if permission already exists
            existing = self.role_service.get_permission_by_name(db, perm_data["name"])
            if not existing:
                permission_create = PermissionCreate(**perm_data)
                permission = self.role_service.create_permission(db, permission_create)
                # Mark as system permission
                permission.is_system_permission = True
                db.commit()
                created_permissions[perm_data["name"]] = permission
                print(f"Created permission: {perm_data['name']}")
            else:
                created_permissions[perm_data["name"]] = existing
                print(f"Permission already exists: {perm_data['name']}")

        return created_permissions

    def create_default_roles(self, db: Session, permissions: Dict[str, Permission]) -> Dict[str, Role]:
        """Create default roles for the system"""

        # Define default roles and their permissions
        default_roles = {
            "super_admin": {
                "display_name": "Super Administrator",
                "description": "Full system access with all permissions",
                "permissions": list(permissions.keys())  # All permissions
            },
            "admin": {
                "display_name": "Administrator",
                "description": "Administrative access for user and role management",
                "permissions": [
                    "user.create", "user.read", "user.update", "user.delete", "user.manage",
                    "role.create", "role.read", "role.update", "role.delete", "role.manage",
                    "session.read", "session.manage", "session.revoke",
                    "system.audit", "system.maintenance",
                    "profile.read", "profile.update",
                    "auth.login", "auth.logout", "auth.password_reset"
                ]
            },
            "moderator": {
                "display_name": "Moderator",
                "description": "Limited administrative access for user management",
                "permissions": [
                    "user.read", "user.update",
                    "role.read",
                    "session.read",
                    "profile.read", "profile.update",
                    "auth.login", "auth.logout", "auth.password_reset"
                ]
            },
            "user": {
                "display_name": "Regular User",
                "description": "Basic user access for own profile and authentication",
                "permissions": [
                    "profile.read", "profile.update",
                    "auth.login", "auth.logout", "auth.password_reset"
                ]
            },
            "guest": {
                "display_name": "Guest User",
                "description": "Limited access for unauthenticated operations",
                "permissions": [
                    "auth.login", "auth.password_reset"
                ]
            }
        }

        created_roles = {}

        for role_name, role_data in default_roles.items():
            # Check if role already exists
            existing_role = self.role_service.get_role_by_name(db, role_name)
            if not existing_role:
                # Get permission IDs for this role
                permission_ids = []
                for perm_name in role_data["permissions"]:
                    if perm_name in permissions:
                        permission_ids.append(permissions[perm_name].permission_id)

                role_create = RoleCreate(
                    name=role_name,
                    display_name=role_data["display_name"],
                    description=role_data["description"],
                    permission_ids=permission_ids
                )

                role = self.role_service.create_role(db, role_create)
                # Mark as system role
                role.is_system_role = True
                db.commit()
                created_roles[role_name] = role
                print(f"Created role: {role_name} with {len(permission_ids)} permissions")
            else:
                created_roles[role_name] = existing_role
                print(f"Role already exists: {role_name}")

        return created_roles

    def assign_default_user_role(self, db: Session, user_id: str, role_name: str = "user") -> bool:
        """Assign default role to a new user"""
        try:
            role = self.role_service.get_role_by_name(db, role_name)
            if not role:
                print(f"Default role '{role_name}' not found")
                return False

            assignment = self.role_service.assign_role_to_user(
                db=db,
                user_id=user_id,
                role_id=role.role_id,
                reason="Default role assignment for new user"
            )

            if assignment:
                print(f"Assigned default role '{role_name}' to user {user_id}")
                return True
            else:
                print(f"Failed to assign default role '{role_name}' to user {user_id}")
                return False

        except Exception as e:
            print(f"Error assigning default role: {e}")
            return False

    def initialize_system(self, db: Session) -> Dict[str, Any]:
        """Initialize the entire role and permission system"""
        print("Initializing role and permission system...")

        # Create permissions
        permissions = self.create_default_permissions(db)

        # Create roles
        roles = self.create_default_roles(db, permissions)

        result = {
            "permissions_created": len(permissions),
            "roles_created": len(roles),
            "permissions": list(permissions.keys()),
            "roles": list(roles.keys())
        }

        print(f"Role system initialization complete:")
        print(f"- Created {len(permissions)} permissions")
        print(f"- Created {len(roles)} roles")

        return result

    def update_role_permissions(self, db: Session, role_name: str, permission_names: List[str]) -> bool:
        """Update permissions for an existing role"""
        try:
            role = self.role_service.get_role_by_name(db, role_name)
            if not role:
                print(f"Role '{role_name}' not found")
                return False

            # Get permission IDs
            permission_ids = []
            for perm_name in permission_names:
                permission = self.role_service.get_permission_by_name(db, perm_name)
                if permission:
                    permission_ids.append(permission.permission_id)
                else:
                    print(f"Permission '{perm_name}' not found")

            from src.schemas.role import RoleUpdate
            role_update = RoleUpdate(permission_ids=permission_ids)
            updated_role = self.role_service.update_role(db, role.role_id, role_update)

            if updated_role:
                print(f"Updated role '{role_name}' with {len(permission_ids)} permissions")
                return True
            else:
                print(f"Failed to update role '{role_name}'")
                return False

        except Exception as e:
            print(f"Error updating role permissions: {e}")
            return False

# Create a singleton instance
role_initializer = RoleInitializer()

def get_role_initializer() -> RoleInitializer:
    """Get the role initializer instance"""
    return role_initializer

def init_default_roles_and_permissions(db: Session) -> Dict[str, Any]:
    """Convenience function to initialize default roles and permissions"""
    return role_initializer.initialize_system(db)
