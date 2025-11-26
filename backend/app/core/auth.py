"""
Authentication and authorization module using JWT tokens.
"""

from datetime import datetime, timedelta
from typing import Optional, Union
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import hashlib
import secrets
import base64
from sqlalchemy.orm import Session
import structlog

from app.core.config import settings
from app.core.database import get_db
from app.models.user import User, UserRole

logger = structlog.get_logger(__name__)

# Simple password hashing using Python's built-in hashlib
def _hash_password_internal(password: str, salt: bytes) -> str:
    """Internal password hashing function using PBKDF2."""
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(salt + hashed).decode('utf-8')

def _verify_password_internal(password: str, hashed_password: str) -> bool:
    """Internal password verification function."""
    try:
        decoded = base64.b64decode(hashed_password.encode('utf-8'))
        salt = decoded[:32]  # First 32 bytes are salt
        stored_hash = decoded[32:]  # Rest is the hash
        new_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return secrets.compare_digest(stored_hash, new_hash)
    except Exception:
        return False

# JWT token security
security = HTTPBearer(auto_error=False)


def _build_dev_user() -> User:
    """Return a mock admin user when auth is disabled."""
    return User(
        id=0,
        username="dev-admin",
        email=settings.ADMIN_EMAIL,
        full_name="Development Admin",
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
        hashed_password="",
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.
    
    Args:
        plain_password: Plain text password
        hashed_password: Base64 encoded hashed password
        
    Returns:
        bool: True if password matches
    """
    return _verify_password_internal(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using PBKDF2.
    
    Args:
        password: Plain text password
        
    Returns:
        str: Base64 encoded hashed password
    """
    salt = secrets.token_bytes(32)  # Generate 32-byte salt
    return _hash_password_internal(password, salt)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Data to encode in the token
        expires_delta: Token expiration time
        
    Returns:
        str: JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """
    Create a JWT refresh token.
    
    Args:
        data: Data to encode in the token
        
    Returns:
        str: JWT refresh token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token to verify
        
    Returns:
        dict: Token payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError as e:
        logger.error("JWT verification failed", error=str(e))
        return None


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """
    Authenticate a user with username and password.
    
    Args:
        db: Database session
        username: Username or email address
        password: Plain text password
        
    Returns:
        User: User object if authentication successful, None otherwise
    """
    # Try to find user by username first, then by email
    user = db.query(User).filter(User.username == username).first()
    if not user:
        user = db.query(User).filter(User.email == username).first()
    
    if not user:
        logger.warning("Authentication failed - user not found", username=username)
        return None
    
    if not user.is_active:
        logger.warning("Authentication failed - user inactive", username=username)
        return None
    
    if not verify_password(password, user.hashed_password):
        logger.warning("Authentication failed - invalid password", username=username)
        return None
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    logger.info("User authenticated successfully", username=username, user_id=user.id)
    return user


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Bearer credentials
        db: Database session
        
    Returns:
        User: Current authenticated user
        
    Raises:
        HTTPException: If authentication fails
    """
    if settings.AUTH_DISABLED:
        return _build_dev_user()

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if credentials is None:
        raise credentials_exception
    
    try:
        payload = verify_token(credentials.credentials)
        
        if payload is None:
            raise credentials_exception
            
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        
        if username is None or user_id is None:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id).first()
    
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled"
        )
    
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Get current active user (wrapper for dependency injection).
    
    Args:
        current_user: Current user from JWT token
        
    Returns:
        User: Current active user
    """
    return current_user


def require_role(required_role: UserRole):
    """
    Create a dependency that requires a specific user role.
    
    Args:
        required_role: Required user role
        
    Returns:
        Dependency function
    """
    def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if settings.AUTH_DISABLED:
            return current_user or _build_dev_user()
        role_hierarchy = {
            UserRole.VIEWER: 1,
            UserRole.OPERATOR: 2,
            UserRole.ADMIN: 3
        }
        
        user_level = role_hierarchy.get(current_user.role, 0)
        required_level = role_hierarchy.get(required_role, 999)
        
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires {required_role.value} role or higher"
            )
        
        return current_user
    
    return role_checker


def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Require admin role for endpoint access.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User: Current user if admin
        
    Raises:
        HTTPException: If user is not admin
    """
    if settings.AUTH_DISABLED:
        return current_user or _build_dev_user()
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires admin privileges"
        )
    return current_user


def require_operator_or_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Require operator or admin role for endpoint access.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User: Current user if operator or admin
        
    Raises:
        HTTPException: If user doesn't have sufficient privileges
    """
    if settings.AUTH_DISABLED:
        return current_user or _build_dev_user()
    if current_user.role not in [UserRole.OPERATOR, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires operator or admin privileges"
        )
    return current_user


def check_permission(user: User, action: str) -> bool:
    """
    Check if user has permission for a specific action.
    
    Args:
        user: User to check
        action: Action to check permission for
        
    Returns:
        bool: True if user has permission
    """
    return user.has_permission(action)


def audit_log_auth_event(user_id: Optional[int], event: str, details: dict = None):
    """
    Log authentication/authorization events for audit purposes.
    
    Args:
        user_id: User ID (if available)
        event: Event type (login, logout, permission_denied, etc.)
        details: Additional event details
    """
    logger.info(
        "Authentication event",
        user_id=user_id,
        event_type=event,
        details=details or {},
        timestamp=datetime.utcnow().isoformat()
    )