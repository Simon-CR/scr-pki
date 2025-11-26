"""
Certificate Authority model for CA management.
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Enum, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from datetime import datetime, timezone
from typing import Optional

from app.core.database import Base


class CAStatus(enum.Enum):
    """Certificate Authority status enumeration."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class CertificateAuthority(Base):
    """
    Certificate Authority model for CA management.
    
    Attributes:
        id: Primary key
        common_name: CA common name
        organization: Organization name
        organizational_unit: Organizational unit
        country: Country code
        state: State or province
        locality: City or locality
        email: Contact email
        key_size: RSA key size in bits
        signature_algorithm: Signature algorithm
        serial_number: CA certificate serial number
        status: CA status
        pem_certificate: PEM encoded CA certificate
        pem_crl: PEM encoded Certificate Revocation List
        private_key_vault_path: Vault path to CA private key
        next_crl_update: Next CRL update timestamp
        issued_at: CA certificate issuance timestamp
        not_valid_before: CA certificate validity start
        not_valid_after: CA certificate validity end
        created_at: Record creation timestamp
        updated_at: Record update timestamp
    """
    
    __tablename__ = "certificate_authorities"
    
    id = Column(Integer, primary_key=True, index=True)
    common_name = Column(String(255), nullable=False, unique=True)
    organization = Column(String(255), nullable=False)
    organizational_unit = Column(String(255))
    country = Column(String(2), nullable=False)  # ISO country code
    state = Column(String(255))
    locality = Column(String(255))
    email = Column(String(255))
    
    # Key and algorithm information
    key_size = Column(Integer, default=4096)
    signature_algorithm = Column(String(50), default="SHA256")
    serial_number = Column(String(100), unique=True, nullable=False)
    status = Column(Enum(CAStatus), default=CAStatus.INITIALIZING)
    is_root = Column(Boolean, default=False, nullable=False)
    is_offline = Column(Boolean, default=False, nullable=False)
    parent_ca_id = Column(Integer, ForeignKey("certificate_authorities.id"), nullable=True)
    revocation_reason = Column(String(255))
    revoked_at = Column(DateTime(timezone=True))
    
    # Certificate data
    pem_certificate = Column(Text)
    pem_crl = Column(Text)  # Certificate Revocation List
    private_key_vault_path = Column(String(255))  # Path in Vault
    
    # CRL management
    next_crl_update = Column(DateTime(timezone=True))
    
    # Timestamps
    issued_at = Column(DateTime(timezone=True))
    not_valid_before = Column(DateTime(timezone=True))
    not_valid_after = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    issued_certificates = relationship("Certificate", back_populates="issuer_ca")
    parent_ca = relationship(
        "CertificateAuthority",
        remote_side=[id],
        back_populates="child_cas"
    )
    child_cas = relationship(
        "CertificateAuthority",
        back_populates="parent_ca"
    )
    
    def __repr__(self):
        return f"<CertificateAuthority(id={self.id}, cn='{self.common_name}', status='{self.status.value}')>"
    
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
    def is_active(self) -> bool:
        """Check if CA is active and valid."""
        expiry = self._ensure_aware(self.not_valid_after)
        if not expiry:
            return False
        return self.status == CAStatus.ACTIVE and self._utc_now() < expiry
    
    @property
    def is_expired(self) -> bool:
        """Check if CA certificate is expired."""
        expiry = self._ensure_aware(self.not_valid_after)
        if not expiry:
            return False
        return self._utc_now() > expiry
    
    @property
    def days_until_expiry(self) -> int:
        """Get number of days until CA expires."""
        expiry = self._ensure_aware(self.not_valid_after)
        if expiry:
            delta = expiry - self._utc_now()
            return max(0, int(delta.total_seconds() // 86400))
        return 0
    
    @property
    def certificate_count(self) -> int:
        """Get total number of certificates issued by this CA."""
        return len(self.issued_certificates)
    
    @property
    def active_certificate_count(self) -> int:
        """Get number of active certificates issued by this CA."""
        from app.models.certificate import CertificateStatus
        return len([
            cert for cert in self.issued_certificates 
            if cert.status == CertificateStatus.ACTIVE
        ])

    @property
    def chain_depth(self) -> int:
        """Return depth in CA hierarchy."""
        depth = 0
        parent = self.parent_ca
        while parent:
            depth += 1
            parent = parent.parent_ca
        return depth
    
    @property
    def needs_crl_update(self) -> bool:
        """Check if CRL needs to be updated."""
        next_update = self._ensure_aware(self.next_crl_update)
        if not next_update:
            return True
        return self._utc_now() >= next_update
    
    def get_subject_dict(self) -> dict:
        """Get CA subject information as dictionary."""
        return {
            'common_name': self.common_name,
            'organization': self.organization,
            'organizational_unit': self.organizational_unit,
            'country': self.country,
            'state': self.state,
            'locality': self.locality,
            'email': self.email
        }
    
    def can_issue_certificates(self) -> bool:
        """Check if CA can issue certificates."""
        return (
            self.status == CAStatus.ACTIVE and
            not self.is_expired and
            self.pem_certificate is not None
        )
    
    def can_revoke_certificates(self) -> bool:
        """Check if CA can revoke certificates."""
        return (
            self.status == CAStatus.ACTIVE and
            not self.is_expired
        )