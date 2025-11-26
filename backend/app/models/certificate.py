"""
Certificate model for SSL/TLS certificate management.
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from datetime import datetime, timezone
from typing import Optional, List

from app.core.database import Base


class CertificateStatus(enum.Enum):
    """Certificate status enumeration."""
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class CertificateType(enum.Enum):
    """Certificate type enumeration."""
    SERVER = "server"
    WILDCARD = "wildcard"
    IP = "ip"


class Certificate(Base):
    """
    Certificate model for SSL/TLS certificate management.
    
    Attributes:
        id: Primary key
        common_name: Certificate common name (CN)
        subject_alt_names: JSON array of subject alternative names
        certificate_type: Type of certificate (server/wildcard/ip)
        key_size: RSA key size in bits
        signature_algorithm: Signature algorithm (SHA256, SHA384, SHA512)
        serial_number: Certificate serial number
        status: Certificate status
        pem_certificate: PEM encoded certificate
        pem_private_key_vault_path: Vault path to private key
        issuer_ca_id: Foreign key to issuing CA
        deployment_locations: JSON array of deployment locations
        notes: Additional notes
        created_by: Foreign key to user who created the certificate
        issued_at: Certificate issuance timestamp
        not_valid_before: Certificate validity start
        not_valid_after: Certificate validity end
        revoked_at: Certificate revocation timestamp
        revocation_reason: Reason for revocation
        created_at: Record creation timestamp
        updated_at: Record update timestamp
    """
    
    __tablename__ = "certificates"
    
    id = Column(Integer, primary_key=True, index=True)
    common_name = Column(String(255), nullable=False, index=True)
    subject_alt_names = Column(Text)  # JSON array as text
    certificate_type = Column(Enum(CertificateType), default=CertificateType.SERVER)
    key_size = Column(Integer, default=4096)
    signature_algorithm = Column(String(50), default="SHA256")
    serial_number = Column(String(100), unique=True, nullable=False, index=True)
    status = Column(Enum(CertificateStatus), default=CertificateStatus.PENDING, index=True)
    
    # Certificate data
    pem_certificate = Column(Text)
    pem_private_key_vault_path = Column(String(255))  # Path in Vault
    
    # Relationships
    issuer_ca_id = Column(Integer, ForeignKey("certificate_authorities.id"))
    created_by = Column(Integer, ForeignKey("users.id"))
    
    # Deployment and management
    deployment_locations = Column(Text)  # JSON array as text
    notes = Column(Text)
    monitoring_enabled = Column(Boolean, default=False, nullable=False)
    monitoring_target_url = Column(String(512))
    monitoring_target_port = Column(Integer)
    monitoring_channels = Column(JSON)
    monitoring_notes = Column(Text)
    
    # Timestamps
    issued_at = Column(DateTime(timezone=True))
    not_valid_before = Column(DateTime(timezone=True))
    not_valid_after = Column(DateTime(timezone=True), index=True)  # For expiry queries
    revoked_at = Column(DateTime(timezone=True))
    revocation_reason = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    issuer_ca = relationship("CertificateAuthority", back_populates="issued_certificates")
    created_by_user = relationship("User", back_populates="certificates")
    monitoring_services = relationship("MonitoringService", back_populates="certificate")
    # Temporarily disabled: alerts = relationship("Alert", back_populates="certificate")
    
    def __repr__(self):
        return f"<Certificate(id={self.id}, cn='{self.common_name}', status='{self.status.value}')>"
    
    @staticmethod
    def _utc_now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _ensure_aware(value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @property
    def is_valid(self) -> bool:
        """Check if certificate is currently valid."""
        now = self._utc_now()
        valid_from = self._ensure_aware(self.not_valid_before)
        valid_to = self._ensure_aware(self.not_valid_after)
        if not valid_from or not valid_to:
            return False
        return self.status == CertificateStatus.ACTIVE and valid_from <= now <= valid_to
    
    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        valid_to = self._ensure_aware(self.not_valid_after)
        if not valid_to:
            return False
        return self._utc_now() > valid_to
    
    @property
    def is_revoked(self) -> bool:
        """Check if certificate is revoked."""
        return self.status == CertificateStatus.REVOKED
    
    @property
    def days_until_expiry(self) -> int:
        """Get number of days until certificate expires."""
        valid_to = self._ensure_aware(self.not_valid_after)
        if valid_to:
            delta = valid_to - self._utc_now()
            return max(0, int(delta.total_seconds() // 86400))
        return 0
    
    @property
    def needs_renewal(self, days_threshold: int = 30) -> bool:
        """Check if certificate needs renewal within threshold."""
        return self.days_until_expiry <= days_threshold
    
    def get_subject_alt_names_list(self) -> list:
        """Get subject alternative names as a list."""
        if self.subject_alt_names:
            import json
            try:
                return json.loads(self.subject_alt_names)
            except json.JSONDecodeError:
                return []
        return []
    
    def set_subject_alt_names_list(self, san_list: list):
        """Set subject alternative names from a list."""
        import json
        self.subject_alt_names = json.dumps(san_list) if san_list else None

    def get_monitoring_channels(self) -> List[str]:
        return list(self.monitoring_channels or [])

    def set_monitoring_channels(self, channels: List[str]):
        self.monitoring_channels = channels or None
    
    def get_deployment_locations_list(self) -> list:
        """Get deployment locations as a list."""
        if self.deployment_locations:
            import json
            try:
                return json.loads(self.deployment_locations)
            except json.JSONDecodeError:
                return []
        return []
    
    def set_deployment_locations_list(self, locations: list):
        """Set deployment locations from a list."""
        import json
        self.deployment_locations = json.dumps(locations) if locations else None
    
    def can_be_renewed(self) -> bool:
        """Check if certificate can be renewed."""
        return self.status in [CertificateStatus.ACTIVE, CertificateStatus.EXPIRED]
    
    def can_be_revoked(self) -> bool:
        """Check if certificate can be revoked."""
        return self.status == CertificateStatus.ACTIVE