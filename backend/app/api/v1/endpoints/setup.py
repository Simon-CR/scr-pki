from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Any

from app.core.database import get_db
from app.models.user import User, UserRole
from app.core.auth import get_password_hash
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
async def setup_initial_admin(
    setup_data: SetupRequest,
    db: Session = Depends(get_db)
) -> Any:
    """
    Create the initial admin user.
    Only allowed if no users exist.
    """
    user_count = db.query(User).count()
    if user_count > 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setup already completed"
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
