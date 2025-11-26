"""
Database models for the PKI Platform.

This package contains all SQLAlchemy models for:
- User management and authentication
- Certificate Authority management  
- Certificate lifecycle management
- Monitoring and health checks
- Alert and notification management

All models inherit from the common Base class defined in app.core.database.
"""

# Import all models to ensure they are registered with SQLAlchemy
from .user import User, UserRole
from .ca import CertificateAuthority, CAStatus  
from .certificate import Certificate, CertificateStatus, CertificateType
from .monitoring import (
    MonitoringService,
    MonitoringStatus,
    CheckResult,
    MonitoringAlertChannel,
    AlertChannelType,
)
from .system import SystemConfig
# Temporarily commented out due to SQLAlchemy metadata conflict
# from .alert import Alert, AlertType, AlertStatus, AlertRule

__all__ = [
    # User models
    "User",
    "UserRole", 
    
    # CA models
    "CertificateAuthority",
    "CAStatus",
    
    # Certificate models
    "Certificate", 
    "CertificateStatus",
    "CertificateType",
    
    # Monitoring models
    "MonitoringService",
    "MonitoringStatus", 
    "CheckResult",
    "MonitoringAlertChannel",
    "AlertChannelType",
    
    # System models
    "SystemConfig",
    
    # Alert models - temporarily disabled
    # "Alert",
    # "AlertType",
    # "AlertStatus", 
    # "AlertRule",
]