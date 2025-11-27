from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Enum, JSON, ForeignKey, Float
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
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

class CheckResult(enum.Enum):
    """Health check result enumeration."""
    SUCCESS = "success"
    WARNING = "warning"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"

class MonitoringStatus(enum.Enum):
    """Monitoring service status enumeration."""
    ACTIVE = "active"
    PAUSED = "paused" 
    DISABLED = "disabled"

class Certificate(Base):
    __tablename__ = "certificates"
    
    id = Column(Integer, primary_key=True, index=True)
    common_name = Column(String(255), nullable=False, index=True)
    serial_number = Column(String(100), unique=True, nullable=False, index=True)
    status = Column(Enum(CertificateStatus), default=CertificateStatus.PENDING, index=True)
    
    # Timestamps
    not_valid_after = Column(DateTime(timezone=True), index=True)
    
    # Monitoring
    monitoring_enabled = Column(Boolean, default=False, nullable=False)
    monitoring_target_url = Column(String(512))
    monitoring_target_port = Column(Integer)
    monitoring_channels = Column(JSON)
    
    monitoring_services = relationship("MonitoringService", back_populates="certificate")
    
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

class MonitoringService(Base):
    """
    Monitoring service model for tracking monitored services.
    """
    __tablename__ = "monitoring_services"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    service_type = Column(String(50), default="web")
    url = Column(String(500), nullable=False)
    
    # Check configuration
    check_interval = Column(Integer, default=300)
    timeout = Column(Integer, default=10)
    retry_count = Column(Integer, default=3)
    status = Column(Enum(MonitoringStatus), default=MonitoringStatus.ACTIVE)
    
    # Associated certificate
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    
    # Check results
    last_check_at = Column(DateTime(timezone=True))
    last_check_result = Column(Enum(CheckResult))
    last_check_duration = Column(Float)
    last_error_message = Column(Text)
    
    # Statistics
    uptime_percentage = Column(Float, default=0.0)
    consecutive_failures = Column(Integer, default=0)
    total_checks = Column(Integer, default=0)
    successful_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    average_response_time = Column(Float, default=0.0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    certificate = relationship("Certificate", back_populates="monitoring_services")

    def update_statistics(self, result: CheckResult, duration: float):
        self.total_checks += 1
        
        if result == CheckResult.SUCCESS:
            self.successful_checks += 1
            self.consecutive_failures = 0
        else:
            self.failed_checks += 1
            self.consecutive_failures += 1
            
        # Update average response time (simple moving average)
        if self.total_checks == 1:
            self.average_response_time = duration
        else:
            # Weighted average to prefer recent history slightly, or just cumulative
            # Using cumulative average: new_avg = old_avg + (new_val - old_avg) / count
            self.average_response_time = self.average_response_time + (duration - self.average_response_time) / self.total_checks
            
        # Calculate uptime percentage
        if self.total_checks > 0:
            self.uptime_percentage = (self.successful_checks / self.total_checks) * 100.0

class SystemConfig(Base):
    __tablename__ = "system_config"

    key = Column(String, primary_key=True, index=True)
    value = Column(Text, nullable=False)
    description = Column(String, nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
