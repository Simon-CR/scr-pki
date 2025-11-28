"""
Monitoring models for service health checks and monitoring.
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Enum, ForeignKey, Float, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from datetime import datetime, timezone

from app.core.database import Base


class MonitoringStatus(enum.Enum):
    """Monitoring service status enumeration."""
    ACTIVE = "active"
    PAUSED = "paused" 
    DISABLED = "disabled"


class CheckResult(enum.Enum):
    """Health check result enumeration."""
    SUCCESS = "success"
    WARNING = "warning"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


class AlertChannelType(enum.Enum):
    """Supported alert delivery channels."""
    DISCORD = "discord"
    EMAIL = "email"
    TELEGRAM = "telegram"
    PUSHBULLET = "pushbullet"
    OTHER = "other"


class MonitoringService(Base):
    """
    Monitoring service model for tracking monitored services.
    
    Attributes:
        id: Primary key
        name: Service name
        description: Service description
        service_type: Type of service (web, api, database, etc.)
        url: Service URL to monitor
        check_interval: Check interval in seconds
        timeout: Request timeout in seconds
        retry_count: Number of retries on failure
        status: Monitoring status
        certificate_id: Associated certificate ID
        last_check_at: Last health check timestamp
        last_check_result: Last check result
        last_check_duration: Last check duration in seconds
        last_error_message: Last error message
        uptime_percentage: Uptime percentage (30 days)
        consecutive_failures: Current consecutive failure count
        total_checks: Total number of checks performed
        successful_checks: Number of successful checks
        failed_checks: Number of failed checks
        average_response_time: Average response time in seconds
        created_at: Record creation timestamp
        updated_at: Record update timestamp
    """
    
    __tablename__ = "monitoring_services"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    service_type = Column(String(50), default="web")  # web, api, database, etc.
    url = Column(String(500), nullable=False)
    
    # Check configuration
    check_interval = Column(Integer, default=300)  # 5 minutes
    timeout = Column(Integer, default=10)  # 10 seconds
    retry_count = Column(Integer, default=3)
    status = Column(Enum(MonitoringStatus), default=MonitoringStatus.ACTIVE)
    
    # Associated certificate
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    
    # Check results
    last_check_at = Column(DateTime(timezone=True))
    last_check_result = Column(Enum(CheckResult))
    last_check_duration = Column(Float)  # seconds
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
    check_history = relationship("CheckHistory", back_populates="service", cascade="all, delete-orphan")
    alert_channels = relationship(
        "MonitoringAlertChannel",
        back_populates="service",
        cascade="all, delete-orphan"
    )
    # Temporarily disabled: alerts = relationship("Alert", back_populates="service")
    
    def __repr__(self):
        return f"<MonitoringService(id={self.id}, name='{self.name}', status='{self.status.value}')>"
    
    @property
    def is_healthy(self) -> bool:
        """Check if service is currently healthy."""
        return (
            self.last_check_result == CheckResult.SUCCESS and
            self.consecutive_failures == 0
        )
    
    @property
    def has_certificate(self) -> bool:
        """Check if service has an associated certificate."""
        return self.certificate_id is not None
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_checks == 0:
            return 0.0
        return (self.successful_checks / self.total_checks) * 100
    
    def update_statistics(self, check_result: CheckResult, duration: float):
        """Update service statistics after a health check."""
        self.total_checks += 1
        self.last_check_at = datetime.now(timezone.utc)
        self.last_check_result = check_result
        self.last_check_duration = duration
        
        if check_result == CheckResult.SUCCESS:
            self.successful_checks += 1
            self.consecutive_failures = 0
        else:
            self.failed_checks += 1
            self.consecutive_failures += 1
        
        # Update average response time
        if self.total_checks == 1:
            self.average_response_time = duration
        else:
            # Exponential moving average
            alpha = 0.1
            self.average_response_time = (
                alpha * duration + 
                (1 - alpha) * self.average_response_time
            )
        
        # Update uptime percentage (simplified - could be more sophisticated)
        self.uptime_percentage = self.success_rate
    
    def needs_check(self) -> bool:
        """Check if service needs a health check."""
        if self.status != MonitoringStatus.ACTIVE:
            return False
            
        if not self.last_check_at:
            return True
            
        time_since_last_check = datetime.now(timezone.utc) - self.last_check_at
        return time_since_last_check.total_seconds() >= self.check_interval


class CheckHistory(Base):
    """
    Health check history for detailed monitoring records.
    
    Attributes:
        id: Primary key
        service_id: Foreign key to monitoring service
        check_timestamp: When the check was performed
        result: Check result
        duration: Check duration in seconds
        status_code: HTTP status code (if applicable)
        response_size: Response size in bytes
        error_message: Error message if check failed
        ssl_cert_expiry: SSL certificate expiry date (if checked)
        ssl_cert_valid: Whether SSL certificate is valid
    """
    
    __tablename__ = "check_history"
    
    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("monitoring_services.id"), nullable=False)
    check_timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    result = Column(Enum(CheckResult), nullable=False)
    duration = Column(Float)  # seconds
    status_code = Column(Integer)  # HTTP status code
    response_size = Column(Integer)  # bytes
    error_message = Column(Text)
    
    # SSL certificate information
    ssl_cert_expiry = Column(DateTime(timezone=True))
    ssl_cert_valid = Column(Boolean)
    
    # Relationships
    service = relationship("MonitoringService", back_populates="check_history")
    
    def __repr__(self):
        return f"<CheckHistory(id={self.id}, service_id={self.service_id}, result='{self.result.value}')>"
    
    @property
    def is_successful(self) -> bool:
        """Check if this check was successful."""
        return self.result == CheckResult.SUCCESS
    
    @property
    def has_ssl_info(self) -> bool:
        """Check if SSL certificate information is available."""
        return self.ssl_cert_expiry is not None


class MonitoringAlertChannel(Base):
    """Alert channel configuration for monitoring notifications."""

    __tablename__ = "monitoring_alert_channels"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("monitoring_services.id"), nullable=True)
    channel_type = Column(Enum(AlertChannelType), nullable=False)
    target = Column(String(512), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    config = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    service = relationship("MonitoringService", back_populates="alert_channels")

    def __repr__(self) -> str:
        return f"<MonitoringAlertChannel(id={self.id}, channel='{self.channel_type.value}', enabled={self.enabled})>"