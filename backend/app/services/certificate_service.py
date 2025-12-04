"""
Certificate service for managing certificate lifecycle operations.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from cryptography import x509
import json
import structlog

from app.models.certificate import Certificate, CertificateStatus, CertificateType
from app.models.ca import CertificateAuthority
from app.services.pki_service import pki_service
from app.core.vault import vault_client
from app.core.config import settings
from app.services.ca_service import ca_service
from cryptography.hazmat.primitives import serialization

logger = structlog.get_logger(__name__)


class CertificateService:
    """Service for certificate lifecycle management."""
    
    def __init__(self):
        self.pki = pki_service
        self.vault = vault_client
    
    def issue_certificate(
        self,
        db: Session,
        common_name: str,
        subject_alt_names: List[str] = None,
        certificate_type: CertificateType = CertificateType.SERVER,
        key_size: int = None,
        validity_days: int = None,
        deployment_locations: List[str] = None,
        notes: str = None,
        created_by_user_id: int = None,
        monitoring_enabled: bool = False,
        monitoring_target_url: Optional[str] = None,
        monitoring_target_port: Optional[int] = None,
        monitoring_channels: Optional[List[str]] = None,
    ) -> Certificate:
        """
        Issue a new certificate.
        
        Args:
            db: Database session
            common_name: Certificate common name
            subject_alt_names: List of subject alternative names
            certificate_type: Type of certificate
            key_size: RSA key size in bits
            validity_days: Certificate validity in days
            deployment_locations: List of deployment locations
            notes: Additional notes
            created_by_user_id: ID of user creating the certificate
            
        Returns:
            Certificate: Created certificate record
        """
        if key_size is None:
            key_size = settings.CERT_DEFAULT_KEY_SIZE
        
        if validity_days is None:
            validity_days = settings.CERT_DEFAULT_VALIDITY_DAYS
        
        # Log info about validity for compliance tracking
        # ≤398 days: Full Apple PKI compliance
        # ≤825 days: macOS 10.15/iOS 13 compatible  
        # >825 days: Works with Firefox, Chrome, Opera (Safari may show warnings)
        if validity_days > 825:
            logger.info(
                "Certificate validity exceeds macOS/iOS strict limit (825 days). "
                "Works with Chrome/Firefox/Opera. Safari may show 'not standards compliant'.",
                requested_days=validity_days,
                common_name=common_name,
            )
        elif validity_days > 398:
            logger.info(
                "Certificate validity exceeds Apple PKI limit (398 days). "
                "Compatible with macOS 10.15/iOS 13+.",
                requested_days=validity_days,
                common_name=common_name,
            )
        
        if subject_alt_names is None:
            subject_alt_names = []
        
        logger.info(
            "Issuing new certificate",
            common_name=common_name,
            certificate_type=certificate_type.value,
            monitoring_enabled=monitoring_enabled,
        )
        
        try:
            # Get CA certificate and private key
            ca = self._get_active_ca(db)
            if not ca:
                raise ValueError("No active Certificate Authority found")
            
            ca_cert = x509.load_pem_x509_certificate(ca.pem_certificate.encode('utf-8'))
            ca_private_key = self.vault.retrieve_private_key(ca.private_key_vault_path)
            
            if not ca_private_key:
                raise ValueError("Failed to retrieve CA private key from Vault")
            
            # Generate certificate
            cert, private_key = self.pki.create_server_certificate(
                common_name=common_name,
                subject_alt_names=subject_alt_names,
                ca_cert=ca_cert,
                ca_private_key=ca_private_key,
                validity_days=validity_days,
                key_size=key_size,
                certificate_type=certificate_type.value
            )
            
            # Store private key in Vault
            key_vault_path = f"certificates/{cert.serial_number}"
            if not self.vault.store_private_key(key_vault_path, private_key):
                raise ValueError("Failed to store private key in Vault")
            
            # Create database record
            cert_record = Certificate(
                common_name=common_name,
                certificate_type=certificate_type,
                key_size=key_size,
                signature_algorithm=settings.CERT_SIGNATURE_ALGORITHM,
                serial_number=str(cert.serial_number),
                status=CertificateStatus.ACTIVE,
                pem_certificate=self.pki.certificate_to_pem(cert),
                pem_private_key_vault_path=key_vault_path,
                issuer_ca_id=ca.id,
                created_by=created_by_user_id,
                issued_at=datetime.now(timezone.utc),
                not_valid_before=cert.not_valid_before,
                not_valid_after=cert.not_valid_after,
                notes=notes,
                monitoring_enabled=monitoring_enabled,
                monitoring_target_url=monitoring_target_url if monitoring_enabled else None,
                monitoring_target_port=(monitoring_target_port or 443) if monitoring_enabled else None,
            )
            
            # Set subject alternative names
            cert_record.set_subject_alt_names_list(subject_alt_names)
            
            # Set deployment locations
            if deployment_locations:
                cert_record.set_deployment_locations_list(deployment_locations)

            if monitoring_channels:
                cert_record.set_monitoring_channels(monitoring_channels)
            
            db.add(cert_record)
            db.commit()
            db.refresh(cert_record)
            
            logger.info("Certificate issued successfully", 
                       certificate_id=cert_record.id,
                       serial_number=cert_record.serial_number,
                       common_name=common_name)
            
            return cert_record
            
        except Exception as e:
            db.rollback()
            logger.error("Failed to issue certificate", 
                        common_name=common_name, 
                        error=str(e))
            raise
    
    def renew_certificate(
        self,
        db: Session,
        certificate_id: int,
        validity_days: int = None,
        created_by_user_id: int = None
    ) -> Certificate:
        """
        Renew an existing certificate.
        
        Args:
            db: Database session
            certificate_id: ID of certificate to renew
            validity_days: New certificate validity in days
            created_by_user_id: ID of user renewing the certificate
            
        Returns:
            Certificate: Renewed certificate record
        """
        logger.info("Renewing certificate", certificate_id=certificate_id)
        
        # Get existing certificate
        old_cert = db.query(Certificate).filter(Certificate.id == certificate_id).first()
        if not old_cert:
            raise ValueError(f"Certificate with ID {certificate_id} not found")
        
        if not old_cert.can_be_renewed():
            raise ValueError(f"Certificate {certificate_id} cannot be renewed")
        
        try:
            # Issue new certificate with same parameters
            new_cert = self.issue_certificate(
                db=db,
                common_name=old_cert.common_name,
                subject_alt_names=old_cert.get_subject_alt_names_list(),
                certificate_type=old_cert.certificate_type,
                key_size=old_cert.key_size,
                validity_days=validity_days,
                deployment_locations=old_cert.get_deployment_locations_list(),
                notes=f"Renewed from certificate ID {old_cert.id}",
                created_by_user_id=created_by_user_id,
                monitoring_enabled=old_cert.monitoring_enabled,
                monitoring_target_url=old_cert.monitoring_target_url,
                monitoring_target_port=old_cert.monitoring_target_port,
                monitoring_channels=old_cert.get_monitoring_channels(),
            )
            
            # Mark old certificate as expired
            old_cert.status = CertificateStatus.EXPIRED
            db.commit()
            
            logger.info("Certificate renewed successfully", 
                       old_certificate_id=certificate_id,
                       new_certificate_id=new_cert.id)
            
            return new_cert
            
        except Exception as e:
            db.rollback()
            logger.error("Failed to renew certificate", 
                        certificate_id=certificate_id, 
                        error=str(e))
            raise
    
    def revoke_certificate(
        self,
        db: Session,
        certificate_id: int,
        reason: str = "unspecified",
        created_by_user_id: int = None
    ) -> bool:
        """
        Revoke a certificate.
        
        Args:
            db: Database session
            certificate_id: ID of certificate to revoke
            reason: Revocation reason
            created_by_user_id: ID of user revoking the certificate
            
        Returns:
            bool: True if successful
        """
        logger.info("Revoking certificate", certificate_id=certificate_id, reason=reason)
        
        try:
            cert = db.query(Certificate).filter(Certificate.id == certificate_id).first()
            if not cert:
                raise ValueError(f"Certificate with ID {certificate_id} not found")
            
            if not cert.can_be_revoked():
                raise ValueError(f"Certificate {certificate_id} cannot be revoked")
            
            # Update certificate status
            cert.status = CertificateStatus.REVOKED
            cert.revoked_at = datetime.now(timezone.utc)
            cert.revocation_reason = reason

            if cert.monitoring_enabled:
                cert.monitoring_enabled = False
                cert.monitoring_target_url = None
                cert.monitoring_target_port = None
                cert.set_monitoring_channels([])
            
            db.commit()
            
            # We do NOT delete the private key from Vault upon revocation.
            # The key should be retained until the certificate is permanently deleted.
            # This allows for audit/decryption of past traffic and prevents "missing key" errors
            # if the certificate record still exists.
            
            logger.info("Certificate revoked successfully", 
                       certificate_id=certificate_id,
                       serial_number=cert.serial_number)
            
            return True
            
        except Exception as e:
            db.rollback()
            logger.error("Failed to revoke certificate", 
                        certificate_id=certificate_id, 
                        error=str(e))
            raise
    
    def list_certificates(
        self,
        db: Session,
        skip: int = 0,
        limit: int = 100,
        status: CertificateStatus = None,
        certificate_type: CertificateType = None,
        search: str = None,
        expiring_days: int = None,
        user_id: int = None
    ) -> List[Certificate]:
        """
        List certificates with filtering options.
        
        Args:
            db: Database session
            skip: Number of records to skip for pagination
            limit: Maximum number of records to return
            status: Filter by certificate status
            certificate_type: Filter by certificate type
            search: Search term for common name
            expiring_days: Filter certificates expiring within N days
            user_id: Filter by creator user ID
            
        Returns:
            List[Certificate]: List of certificate records
        """
        query = db.query(Certificate)
        
        if user_id:
            query = query.filter(Certificate.created_by == user_id)

        if status:
            query = query.filter(Certificate.status == status)
            
        if certificate_type:
            query = query.filter(Certificate.certificate_type == certificate_type)
            
        if search:
            search_term = f"%{search}%"
            query = query.filter(Certificate.common_name.ilike(search_term))
            
        if expiring_days:
            expiry_date = datetime.now(timezone.utc) + timedelta(days=expiring_days)
            query = query.filter(
                Certificate.status == CertificateStatus.VALID,
                Certificate.not_valid_after <= expiry_date
            )
            
        return query.order_by(Certificate.created_at.desc()).offset(skip).limit(limit).all()
    
    def get_certificate_details(self, db: Session, certificate_id: int) -> Optional[Certificate]:
        """
        Get detailed certificate information.
        
        Args:
            db: Database session
            certificate_id: Certificate ID
            
        Returns:
            Certificate: Certificate details or None if not found
        """
        return db.query(Certificate).filter(Certificate.id == certificate_id).first()
    
    def update_deployment_locations(
        self,
        db: Session,
        certificate_id: int,
        deployment_locations: List[str]
    ) -> bool:
        """
        Update certificate deployment locations.
        
        Args:
            db: Database session
            certificate_id: Certificate ID
            deployment_locations: List of deployment locations
            
        Returns:
            bool: True if successful
        """
        try:
            cert = db.query(Certificate).filter(Certificate.id == certificate_id).first()
            if not cert:
                raise ValueError(f"Certificate with ID {certificate_id} not found")
            
            cert.set_deployment_locations_list(deployment_locations)
            db.commit()
            
            logger.info("Certificate deployment locations updated", 
                       certificate_id=certificate_id,
                       locations=deployment_locations)
            
            return True
            
        except Exception as e:
            db.rollback()
            logger.error("Failed to update deployment locations", 
                        certificate_id=certificate_id, 
                        error=str(e))
            raise
    
    def get_expiring_certificates(
        self,
        db: Session,
        days_threshold: int = 30
    ) -> List[Certificate]:
        """
        Get certificates expiring within the specified number of days.
        
        Args:
            db: Database session
            days_threshold: Number of days to look ahead
            
        Returns:
            List[Certificate]: List of expiring certificates
        """
        expiry_threshold = datetime.now(timezone.utc) + timedelta(days=days_threshold)
        
        return db.query(Certificate).filter(
            Certificate.not_valid_after <= expiry_threshold,
            Certificate.status == CertificateStatus.ACTIVE
        ).order_by(Certificate.not_valid_after).all()

    def delete_certificate(
        self,
        db: Session,
        certificate_id: int,
        created_by_user_id: int = None
    ) -> bool:
        """Permanently delete a certificate record once it is no longer active."""

        logger.info(
            "Deleting certificate",
            certificate_id=certificate_id,
            requested_by=created_by_user_id,
        )

        try:
            cert = db.query(Certificate).filter(Certificate.id == certificate_id).first()
            if not cert:
                raise ValueError(f"Certificate with ID {certificate_id} not found")

            if cert.status == CertificateStatus.ACTIVE:
                raise ValueError("Active certificates must be revoked before deletion")

            key_path = cert.pem_private_key_vault_path

            # Attempt to delete from Vault first to prevent orphaned data
            if key_path:
                if not self.vault.delete_key(key_path):
                    # If delete_key returns False, it failed (e.g. Vault sealed)
                    # We should abort the database deletion to prevent inconsistency
                    raise ValueError("Failed to delete private key from Vault. Ensure Vault is unsealed and accessible.")

            db.delete(cert)
            db.commit()

            logger.info("Certificate deleted", certificate_id=certificate_id)
            return True

        except Exception as exc:
            db.rollback()
            logger.error(
                "Failed to delete certificate",
                certificate_id=certificate_id,
                error=str(exc),
            )
            raise

    def update_monitoring_preferences(
        self,
        db: Session,
        certificate_id: int,
        monitoring_enabled: bool,
        monitoring_target_url: Optional[str] = None,
        monitoring_target_port: Optional[int] = None,
        monitoring_channels: Optional[List[str]] = None,
    ) -> Certificate:
        """Enable/disable monitoring metadata for a certificate."""

        cert = db.query(Certificate).filter(Certificate.id == certificate_id).first()
        if not cert:
            raise ValueError(f"Certificate with ID {certificate_id} not found")

        if monitoring_enabled:
            if not monitoring_target_url:
                raise ValueError("Monitoring target URL is required when enabling monitoring")
            cert.monitoring_enabled = True
            cert.monitoring_target_url = monitoring_target_url
            cert.monitoring_target_port = monitoring_target_port or 443
            cert.set_monitoring_channels(monitoring_channels or [])
        else:
            cert.monitoring_enabled = False
            cert.monitoring_target_url = None
            cert.monitoring_target_port = None
            cert.set_monitoring_channels([])

        db.commit()
        db.refresh(cert)
        logger.info("Certificate monitoring preferences updated", certificate_id=certificate_id, enabled=monitoring_enabled)
        return cert
    
    def _get_active_ca(self, db: Session) -> Optional[CertificateAuthority]:
        """Return the CA that should issue new certificates."""
        return ca_service.get_active_issuing_ca(db)

    def export_private_key_pem(self, certificate: Certificate) -> Optional[str]:
        """Return the PEM-encoded private key for a certificate if available."""

        if not certificate.pem_private_key_vault_path:
            return None

        private_key = self.vault.retrieve_private_key(certificate.pem_private_key_vault_path)
        if not private_key:
            return None

        try:
            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "Failed to serialize private key for export",
                certificate_id=certificate.id,
                error=str(exc),
            )
            return None

        return pem_data


# Global certificate service instance
certificate_service = CertificateService()