from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship, Mapped, mapped_column
import uuid
from datetime import datetime
from typing import Dict, Union, Optional, List
from src.core.database import Base

class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    first_name: Mapped[str] = mapped_column(String(255), nullable=False)
    last_name: Mapped[str] = mapped_column(String(255), nullable=False)
    dob: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now, onupdate=datetime.now)

    # Relationship with sessions
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")

    # Relationship with roles (many-to-many)
    roles = relationship("Role", secondary="user_roles", back_populates="users")

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role"""
        return any(role.name == role_name and role.is_active for role in self.roles)

    def has_permission(self, permission_name: str) -> bool:
        """Check if user has a specific permission through their roles"""
        for role in self.roles:
            if role.is_active:
                for permission in role.permissions:
                    if permission.name == permission_name and permission.is_active:
                        return True
        return False

    def has_resource_permission(self, resource: str, action: str) -> bool:
        """Check if user has permission for a specific resource and action"""
        for role in self.roles:
            if role.is_active:
                for permission in role.permissions:
                    if (permission.resource == resource and
                        permission.action == action and
                        permission.is_active):
                        return True
        return False

    def get_active_roles(self) -> List[str]:
        """Get list of active role names for the user"""
        return [role.name for role in self.roles if role.is_active]

    def get_all_permissions(self) -> List[str]:
        """Get all permissions the user has through their roles"""
        permissions = set()
        for role in self.roles:
            if role.is_active:
                for permission in role.permissions:
                    if permission.is_active:
                        permissions.add(permission.name)
        return list(permissions)
    def to_dict(self) -> Dict[str, Union[str, bool, datetime, List[str]]]:
        """Return a dictionary representation of the user."""
        return {
            'user_id': self.user_id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'roles': self.get_active_roles(),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


    def __repr__(self):
        return f"<User(email='{self.email}', user_id='{self.user_id}')>"
