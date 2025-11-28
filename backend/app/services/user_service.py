"""
User service for user management operations.
"""

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from typing import Optional, Protocol
import structlog

from app.models.user import User, UserRole
from app.core.auth import get_password_hash
from app.core.config import settings
from app.core.password_validator import validate_password, get_password_requirements_message

logger = structlog.get_logger(__name__)


class UserCreateInput(Protocol):
    """Protocol for user creation input data."""
    username: str
    email: str
    password: str
    full_name: Optional[str]
    role: UserRole


class UserUpdateInput(Protocol):
    """Protocol for user update input data."""
    def dict(self, *, exclude_unset: bool = False) -> dict: ...


async def create_default_admin():
    """
    Create default admin user if it doesn't exist.
    This is called during application startup.
    DEPRECATED: Enrollment is now done via UI.
    """
    pass
    # from app.core.database import SessionLocal
    
    # db = SessionLocal()
    # try:
    #     # Check if admin user already exists
    #     existing_admin = db.query(User).filter(
    #         User.username == settings.ADMIN_USERNAME
    #     ).first()
    #     
    #     if existing_admin:
    #         logger.info("Default admin user already exists", username=settings.ADMIN_USERNAME)
    #         return
    #     
    #     # Create default admin user
    #     admin_user = User(
    #         username=settings.ADMIN_USERNAME,
    #         email=settings.ADMIN_EMAIL,
    #         hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
    #         full_name="Default Administrator",
    #         role=UserRole.ADMIN,
    #         is_active=True,
    #         is_verified=True
    #     )
    #     
    #     db.add(admin_user)
    #     db.commit()
    #     
    #     logger.info("Default admin user created successfully", username=settings.ADMIN_USERNAME)
    #     
    # except IntegrityError:
    #     db.rollback()
    #     logger.error("Failed to create default admin user: IntegrityError")
    # except Exception as e:
    #     db.rollback()
    #     logger.error("Failed to create default admin user", error=str(e))

def create_user(db: Session, user_in: UserCreateInput) -> User:
    """Create a new user."""
    # Check if username exists
    if db.query(User).filter(User.username == user_in.username).first():
        raise ValueError("Username already registered")
    
    # Check if email exists
    if db.query(User).filter(User.email == user_in.email).first():
        raise ValueError("Email already registered")
    
    # Validate password complexity
    is_valid, errors = validate_password(user_in.password)
    if not is_valid:
        raise ValueError(f"Password does not meet requirements: {'; '.join(errors)}. {get_password_requirements_message()}")
    
    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=user_in.role,
        is_active=True,
        is_verified=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def update_user(db: Session, user_id: int, user_in: UserUpdateInput) -> Optional[User]:
    """Update a user."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None
    
    update_data = user_in.dict(exclude_unset=True)
    
    # Check username uniqueness if changing
    if "username" in update_data and update_data["username"] != user.username:
        if db.query(User).filter(User.username == update_data["username"]).first():
            raise ValueError("Username already registered")
            
    # Check email uniqueness if changing
    if "email" in update_data and update_data["email"] != user.email:
        if db.query(User).filter(User.email == update_data["email"]).first():
            raise ValueError("Email already registered")

    if "password" in update_data:
        # Validate password complexity when changing password
        is_valid, errors = validate_password(update_data["password"])
        if not is_valid:
            raise ValueError(f"Password does not meet requirements: {'; '.join(errors)}. {get_password_requirements_message()}")
        update_data["hashed_password"] = get_password_hash(update_data.pop("password"))
    
    for field, value in update_data.items():
        setattr(user, field, value)
    
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def delete_user(db: Session, user_id: int) -> bool:
    """Delete a user."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return False
    
    if user.is_superuser:
        raise ValueError("Cannot delete superuser account")
    
    db.delete(user)
    db.commit()
    return True