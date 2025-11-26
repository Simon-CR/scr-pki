from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Enum, JSON
from sqlalchemy.sql import func
import enum
from datetime import datetime, timezone
from typing import Optional, List

from app.database import Base

class CertificateStatus(enum.Enum):
    """Certificate status enumeration."""
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"

class Certificate(Base):
    __tablename__ = "certificates"
    
    id = Column(Integer, primary_key=True, index=True)
    common_name = Column(String(255), nullable=False, index=True)
    status = Column(Enum(CertificateStatus), default=CertificateStatus.PENDING, index=True)
    
    # Timestamps
    not_valid_after = Column(DateTime(timezone=True), index=True)
    
    # Monitoring
    monitoring_enabled = Column(Boolean, default=False, nullable=False)
    monitoring_channels = Column(JSON)
    
    @property
    def days_until_expiry(self) -> int:
        """Get number of days until certificate expires."""
        if self.not_valid_after:
            # Ensure timezone awareness
            expiry = self.not_valid_after
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            delta = expiry - now
            return max(0, int(delta.total_seconds() // 86400))
        return 0
    
    @property
    def is_expired(self) -> bool:
        if self.not_valid_after:
            expiry = self.not_valid_after
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) > expiry
        return False

class SystemConfig(Base):
    __tablename__ = "system_config"

    key = Column(String, primary_key=True, index=True)
    value = Column(Text, nullable=False)
    description = Column(String, nullable=True)
