from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table, Text
from sqlalchemy.orm import relationship, Mapped, mapped_column
from datetime import datetime
from typing import Optional, List
import uuid
from src.core.database import Base

# Association table for many-to-many relationship between users and roles
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', String(36), ForeignKey('users.user_id'), primary_key=True),
    Column('role_id', String(36), ForeignKey('roles.role_id'), primary_key=True),
    Column('assigned_at', DateTime, default=datetime.now),
    Column('expires_at', DateTime, nullable=True),
    Column('is_active', Boolean, default=True)
)

# Association table for many-to-many relationship between roles and permissions
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', String(36), ForeignKey('roles.role_id'), primary_key=True),
    Column('permission_id', String(36), ForeignKey('permissions.permission_id'), primary_key=True),
    Column('granted_at', DateTime, default=datetime.now)
)

class Role(Base):
    __tablename__ = 'roles'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    role_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_system_role: Mapped[bool] = mapped_column(Boolean, default=False)  # For built-in roles that can't be deleted
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey('users.user_id'), nullable=True)

    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")
    creator = relationship("User", foreign_keys=[created_by])

    def __repr__(self):
        return f"<Role(name='{self.name}', role_id='{self.role_id}')>"

class Permission(Base):
    __tablename__ = 'permissions'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    permission_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resource: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., 'user', 'role', 'session'
    action: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g., 'create', 'read', 'update', 'delete'
    is_system_permission: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now, onupdate=datetime.now)

    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")

    def __repr__(self):
        return f"<Permission(name='{self.name}', resource='{self.resource}', action='{self.action}')>"

class UserRoleAssignment(Base):
    """
    Detailed tracking of role assignments with metadata
    """
    __tablename__ = 'user_role_assignments'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assignment_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey('users.user_id'), nullable=False)
    role_id: Mapped[str] = mapped_column(String(36), ForeignKey('roles.role_id'), nullable=False)
    assigned_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey('users.user_id'), nullable=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revoked_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey('users.user_id'), nullable=True)
    revoke_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    role = relationship("Role")
    assigner = relationship("User", foreign_keys=[assigned_by])
    revoker = relationship("User", foreign_keys=[revoked_by])

    def __repr__(self):
        return f"<UserRoleAssignment(user_id='{self.user_id}', role_id='{self.role_id}', active='{self.is_active}')>"
