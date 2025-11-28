from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, EmailStr
from typing import Any

from app.core.database import get_db
from app.models.user import User, UserRole
from app.core.auth import get_password_hash
from app.core.rate_limit import limiter, RATE_LIMITS
from app.core.password_validator import validate_password, get_password_requirements_message
import structlog

logger = structlog.get_logger(__name__)

router = APIRouter()

class SetupStatus(BaseModel):
    setup_required: bool

class SetupRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str = None

@router.get("/status", response_model=SetupStatus)
async def check_setup_status(db: Session = Depends(get_db)) -> Any:
    """
    Check if the system needs setup (i.e., if no users exist).
    """
    user_count = db.query(User).count()
    return {"setup_required": user_count == 0}

@router.post("/", status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMITS["setup"])
async def setup_initial_admin(
    request: Request,
    setup_data: SetupRequest,
    db: Session = Depends(get_db)
) -> Any:
    """
    Create the initial admin user.
    Only allowed if no users exist.
    Uses advisory lock to prevent race conditions.
    Rate limited to prevent abuse.
    """
    try:
        # Acquire advisory lock to prevent race conditions
        # Lock ID 1 is reserved for setup operations
        db.execute(text("SELECT pg_advisory_lock(1)"))
        
        try:
            user_count = db.query(User).count()
            if user_count > 0:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Setup already completed"
                )
            
            # Validate password complexity
            is_valid, errors = validate_password(setup_data.password)
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Password does not meet requirements: {'; '.join(errors)}. {get_password_requirements_message()}"
                )
            
            # Create admin user
            admin_user = User(
                username=setup_data.username,
                email=setup_data.email,
                hashed_password=get_password_hash(setup_data.password),
                full_name=setup_data.full_name,
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True,
                is_superuser=True
            )
            
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            
            logger.info("Initial admin user created", username=admin_user.username)
            
            return {"message": "Setup completed successfully"}
        finally:
            # Always release the advisory lock
            db.execute(text("SELECT pg_advisory_unlock(1)"))
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this username or email already exists"
        )


class PasswordRequirementsResponse(BaseModel):
    min_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_digit: bool
    require_special: bool
    message: str


@router.get("/password-requirements", response_model=PasswordRequirementsResponse)
async def get_password_requirements() -> Any:
    """
    Get the current password requirements configuration.
    This endpoint is public since it's needed during setup.
    """
    from app.core.password_validator import get_password_requirements, get_password_requirements_message
    
    requirements = get_password_requirements()
    requirements["message"] = get_password_requirements_message()
    return requirements
