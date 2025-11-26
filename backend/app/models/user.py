"""
User model for authentication and authorization.
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base


class UserRole(enum.Enum):
    """User roles for RBAC."""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class User(Base):
    """
    User model for authentication and authorization.
    
    Attributes:
        id: Primary key
        username: Unique username
        email: User email address
        hashed_password: Bcrypt hashed password
        full_name: User's full name
        role: User role (admin/operator/viewer)
        is_active: Whether the user account is active
        is_verified: Whether the user email is verified
        created_at: Account creation timestamp
        updated_at: Last update timestamp
        last_login: Last login timestamp
    """
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True))
    
    # Relationships
    certificates = relationship("Certificate", back_populates="created_by_user")
    # Temporarily disabled: alerts = relationship("Alert", back_populates="user")
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role.value}')>"
    
    def has_permission(self, action: str) -> bool:
        """
        Check if user has permission for a specific action.
        
        Args:
            action: Action to check (create, read, update, delete, admin)
            
        Returns:
            bool: True if user has permission
        """
        if not self.is_active:
            return False
            
        role_permissions = {
            UserRole.ADMIN: ["create", "read", "update", "delete", "admin"],
            UserRole.OPERATOR: ["create", "read", "update"],
            UserRole.VIEWER: ["read"]
        }
        
        return action in role_permissions.get(self.role, [])
    
    def can_manage_users(self) -> bool:
        """Check if user can manage other users."""
        return self.role == UserRole.ADMIN and self.is_active
    
    def can_issue_certificates(self) -> bool:
        """Check if user can issue certificates."""
        return self.role in [UserRole.ADMIN, UserRole.OPERATOR] and self.is_active
    
    def can_revoke_certificates(self) -> bool:
        """Check if user can revoke certificates."""
        return self.role in [UserRole.ADMIN, UserRole.OPERATOR] and self.is_active
    
    def can_manage_ca(self) -> bool:
        """Check if user can manage Certificate Authority."""
        return self.role == UserRole.ADMIN and self.is_active