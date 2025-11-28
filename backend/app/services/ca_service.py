"""
Certificate Authority service for managing CA hierarchy and lifecycle events.
"""

from datetime import datetime, timezone
from typing import List, Optional, Sequence, Dict, Any

from sqlalchemy.orm import Session
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import structlog

from app.models.ca import CertificateAuthority, CAStatus
from app.models.certificate import CertificateStatus
from app.services.pki_service import pki_service
from app.core.vault import vault_client
from app.core.config import settings

logger = structlog.get_logger(__name__)


class CAService:
    """Service layer for Certificate Authority operations."""

    def __init__(self):
        self.pki = pki_service
        self.vault = vault_client

    # ------------------------------------------------------------------
    # Retrieval helpers
    # ------------------------------------------------------------------
    def get_root_ca(self, db: Session) -> Optional[CertificateAuthority]:
        """Return the root Certificate Authority, if it exists."""
        return (
            db.query(CertificateAuthority)
            .filter(CertificateAuthority.is_root.is_(True))
            .order_by(CertificateAuthority.created_at.asc())
            .first()
        )

    def get_ca_by_id(self, db: Session, ca_id: int) -> Optional[CertificateAuthority]:
        """Fetch CA by primary key."""
        return db.query(CertificateAuthority).filter(CertificateAuthority.id == ca_id).first()

    def get_active_issuing_ca(self, db: Session) -> Optional[CertificateAuthority]:
        """Return the currently active issuing (non-root) CA."""
        issuing = (
            db.query(CertificateAuthority)
            .filter(
                CertificateAuthority.status == CAStatus.ACTIVE,
                CertificateAuthority.is_root.is_(False),
                CertificateAuthority.is_offline.is_(False),
            )
            .order_by(CertificateAuthority.created_at.desc())
            .first()
        )

        if issuing:
            return issuing

        # Fallback to any active CA (e.g., standalone root deployments)
        fallback = (
            db.query(CertificateAuthority)
            .filter(CertificateAuthority.status == CAStatus.ACTIVE)
            .order_by(CertificateAuthority.created_at.desc())
            .first()
        )

        return self._ensure_root_online_when_needed(db, fallback)

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _get_subject_attr(cert: x509.Certificate, oid: NameOID) -> Optional[str]:
        values = cert.subject.get_attributes_for_oid(oid)
        return values[0].value if values else None

    def list_authorities(self, db: Session) -> Sequence[CertificateAuthority]:
        """Return all known CAs ordered by creation time."""
        return (
            db.query(CertificateAuthority)
            .order_by(CertificateAuthority.created_at.asc())
            .all()
        )

    def _ensure_root_online_when_needed(
        self, db: Session, candidate: Optional[CertificateAuthority]
    ) -> Optional[CertificateAuthority]:
        """Bring the root online automatically when it becomes the issuer."""

        if candidate and candidate.is_root and candidate.is_offline:
            candidate.is_offline = False
            db.commit()
            db.refresh(candidate)
            logger.info(
                "Root Certificate Authority automatically marked online for issuance",
                ca_id=candidate.id,
            )

        return candidate

    def _ensure_unique_common_name(self, db: Session, common_name: str) -> None:
        existing = (
            db.query(CertificateAuthority)
            .filter(CertificateAuthority.common_name == common_name)
            .first()
        )
        if existing:
            raise ValueError(
                f"A Certificate Authority named '{common_name}' already exists (id={existing.id}). "
                "Choose a different common name or disable automatic intermediate creation."
            )

    # ------------------------------------------------------------------
    # Initialization and creation
    # ------------------------------------------------------------------
    def initialize_hierarchy(
        self,
        db: Session,
        *,
        common_name: str,
        organization: str,
        organizational_unit: Optional[str] = None,
        country: str = "US",
        state: Optional[str] = None,
        locality: Optional[str] = None,
        email: Optional[str] = None,
        validity_days: Optional[int] = None,
        key_size: Optional[int] = None,
        create_intermediate: bool = True,
        intermediate_common_name: Optional[str] = None,
        parent_ca_id: Optional[int] = None,
        offline_root: bool = True,
        path_length: Optional[int] = 0,
    ) -> List[CertificateAuthority]:
        """
        Initialize the CA hierarchy by creating a root CA (if needed) and an optional intermediate.

        Returns:
            List of newly created CertificateAuthority records.
        """
        created: List[CertificateAuthority] = []
        validity = validity_days or settings.CA_VALIDITY_DAYS
        key_bits = key_size or settings.CERT_DEFAULT_KEY_SIZE

        root_ca = self.get_root_ca(db)
        if not root_ca:
            self._ensure_unique_common_name(db, common_name)
            logger.info("Creating new root Certificate Authority", common_name=common_name)
            root_ca = self._create_root_ca(
                db,
                common_name=common_name,
                organization=organization,
                organizational_unit=organizational_unit,
                country=country,
                state=state,
                locality=locality,
                email=email,
                validity_days=validity,
                key_size=key_bits,
                offline_root=offline_root,
            )
            created.append(root_ca)
        elif offline_root and not root_ca.is_offline:
            # Update metadata if the operator wants to mark the existing root as offline
            root_ca.is_offline = True
            db.commit()
            db.refresh(root_ca)

        if create_intermediate:
            parent_ca = self.get_ca_by_id(db, parent_ca_id) if parent_ca_id else root_ca
            if not parent_ca:
                raise ValueError("Parent CA not found for intermediate creation")

            requested_common_name = intermediate_common_name or f"{common_name} Intermediate CA"
            self._ensure_unique_common_name(db, requested_common_name)

            logger.info(
                "Creating intermediate Certificate Authority",
                parent_ca_id=parent_ca.id,
                requested_common_name=requested_common_name,
            )
            intermediate_ca = self._create_intermediate_ca(
                db,
                parent_ca=parent_ca,
                common_name=requested_common_name,
                organization=organization,
                organizational_unit=organizational_unit,
                country=country,
                state=state,
                locality=locality,
                email=email,
                validity_days=validity,
                key_size=key_bits,
                path_length=path_length,
            )
            created.append(intermediate_ca)

        return created

    def _create_root_ca(
        self,
        db: Session,
        *,
        common_name: str,
        organization: str,
        organizational_unit: Optional[str],
        country: str,
        state: Optional[str],
        locality: Optional[str],
        email: Optional[str],
        validity_days: int,
        key_size: int,
        offline_root: bool,
    ) -> CertificateAuthority:
        """Create a new self-signed root CA."""
        certificate, private_key = self.pki.create_ca_certificate(
            common_name=common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            country=country,
            state=state,
            locality=locality,
            email=email,
            validity_days=validity_days,
            key_size=key_size,
        )

        key_path = f"cas/{certificate.serial_number}"
        if not self.vault.store_private_key(key_path, private_key):
            raise ValueError("Failed to store root CA private key in Vault")

        ca_record = CertificateAuthority(
            common_name=common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            country=country,
            state=state,
            locality=locality,
            email=email,
            key_size=key_size,
            signature_algorithm=settings.CERT_SIGNATURE_ALGORITHM,
            serial_number=str(certificate.serial_number),
            status=CAStatus.ACTIVE,
            is_root=True,
            is_offline=offline_root,
            parent_ca_id=None,
            pem_certificate=self.pki.certificate_to_pem(certificate),
            private_key_vault_path=key_path,
            issued_at=datetime.now(timezone.utc),
            not_valid_before=certificate.not_valid_before,
            not_valid_after=certificate.not_valid_after,
        )

        db.add(ca_record)
        db.commit()
        db.refresh(ca_record)
        logger.info("Root Certificate Authority created", ca_id=ca_record.id)
        return ca_record

    def _create_intermediate_ca(
        self,
        db: Session,
        *,
        parent_ca: CertificateAuthority,
        common_name: str,
        organization: str,
        organizational_unit: Optional[str],
        country: str,
        state: Optional[str],
        locality: Optional[str],
        email: Optional[str],
        validity_days: int,
        key_size: int,
        path_length: Optional[int],
    ) -> CertificateAuthority:
        """Create an intermediate CA signed by the provided parent."""
        parent_cert = x509.load_pem_x509_certificate(parent_ca.pem_certificate.encode("utf-8"))
        parent_private_key = self.vault.retrieve_private_key(parent_ca.private_key_vault_path)
        if not parent_private_key:
            raise ValueError("Failed to retrieve parent private key from Vault")

        certificate, private_key = self.pki.create_intermediate_certificate(
            parent_cert=parent_cert,
            parent_private_key=parent_private_key,
            common_name=common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            country=country,
            state=state,
            locality=locality,
            email=email,
            validity_days=validity_days,
            key_size=key_size,
            path_length=path_length,
        )

        key_path = f"cas/{certificate.serial_number}"
        if not self.vault.store_private_key(key_path, private_key):
            raise ValueError("Failed to store intermediate CA private key in Vault")

        intermediate_record = CertificateAuthority(
            common_name=common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            country=country,
            state=state,
            locality=locality,
            email=email,
            key_size=key_size,
            signature_algorithm=settings.CERT_SIGNATURE_ALGORITHM,
            serial_number=str(certificate.serial_number),
            status=CAStatus.ACTIVE,
            is_root=False,
            is_offline=False,
            parent_ca_id=parent_ca.id,
            pem_certificate=self.pki.certificate_to_pem(certificate),
            private_key_vault_path=key_path,
            issued_at=datetime.now(timezone.utc),
            not_valid_before=certificate.not_valid_before,
            not_valid_after=certificate.not_valid_after,
        )

        db.add(intermediate_record)
        db.commit()
        db.refresh(intermediate_record)
        logger.info(
            "Intermediate Certificate Authority created",
            ca_id=intermediate_record.id,
            parent_ca_id=parent_ca.id,
        )
        return intermediate_record

    def import_external_root_ca(
        self,
        db: Session,
        *,
        pem_certificate: str,
        offline_root: bool = True,
        pem_private_key: Optional[str] = None,
        private_key_password: Optional[str] = None,
    ) -> CertificateAuthority:
        """Import an externally managed root CA into the system."""

        certificate = x509.load_pem_x509_certificate(pem_certificate.encode("utf-8"))

        existing = (
            db.query(CertificateAuthority)
            .filter(CertificateAuthority.serial_number == str(certificate.serial_number))
            .first()
        )
        if existing:
            return existing

        key_path: Optional[str] = None
        if pem_private_key:
            private_key = serialization.load_pem_private_key(
                pem_private_key.encode("utf-8"),
                password=private_key_password.encode("utf-8") if private_key_password else None,
            )
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("Only RSA private keys are supported for imported roots")
            key_path = f"cas/{certificate.serial_number}"
            if not self.vault.store_private_key(key_path, private_key):
                raise ValueError("Failed to store imported root private key in Vault")

        subject = certificate.subject
        signature_name = (
            certificate.signature_hash_algorithm.name.upper()
            if certificate.signature_hash_algorithm
            else certificate.signature_algorithm_oid._name.upper()
        )
        root_record = CertificateAuthority(
            common_name=self._get_subject_attr(certificate, NameOID.COMMON_NAME) or subject.rfc4514_string(),
            organization=self._get_subject_attr(certificate, NameOID.ORGANIZATION_NAME) or "Unknown",
            organizational_unit=self._get_subject_attr(certificate, NameOID.ORGANIZATIONAL_UNIT_NAME),
            country=self._get_subject_attr(certificate, NameOID.COUNTRY_NAME) or "US",
            state=self._get_subject_attr(certificate, NameOID.STATE_OR_PROVINCE_NAME),
            locality=self._get_subject_attr(certificate, NameOID.LOCALITY_NAME),
            email=self._get_subject_attr(certificate, NameOID.EMAIL_ADDRESS),
            key_size=certificate.public_key().key_size,
            signature_algorithm=signature_name,
            serial_number=str(certificate.serial_number),
            status=CAStatus.ACTIVE,
            is_root=True,
            is_offline=offline_root,
            parent_ca_id=None,
            pem_certificate=pem_certificate.strip() + "\n",
            private_key_vault_path=key_path,
            issued_at=datetime.now(timezone.utc),
            not_valid_before=certificate.not_valid_before,
            not_valid_after=certificate.not_valid_after,
        )

        db.add(root_record)
        db.commit()
        db.refresh(root_record)
        logger.info("External root CA imported", ca_id=root_record.id)
        return root_record

    def import_intermediate_ca(
        self,
        db: Session,
        *,
        pem_certificate: str,
        pem_private_key: str,
        private_key_password: Optional[str] = None,
        parent_ca_id: Optional[int] = None,
        root_certificate_pem: Optional[str] = None,
        is_offline: bool = False,
    ) -> CertificateAuthority:
        """Import an intermediate CA certificate/private key pair."""

        certificate = x509.load_pem_x509_certificate(pem_certificate.encode("utf-8"))
        parent_ca: Optional[CertificateAuthority] = None

        if parent_ca_id:
            parent_ca = self.get_ca_by_id(db, parent_ca_id)
            if not parent_ca:
                raise ValueError("Parent Certificate Authority not found")
        elif root_certificate_pem:
            parent_ca = self.import_external_root_ca(
                db,
                pem_certificate=root_certificate_pem,
                offline_root=True,
            )
        else:
            parent_ca = self.get_root_ca(db)

        if not parent_ca:
            raise ValueError("A parent/root CA is required to import an intermediate")

        private_key = serialization.load_pem_private_key(
            pem_private_key.encode("utf-8"),
            password=private_key_password.encode("utf-8") if private_key_password else None,
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Only RSA private keys are supported for imported intermediates")

        key_path = f"cas/{certificate.serial_number}"
        if not self.vault.store_private_key(key_path, private_key):
            raise ValueError("Failed to store imported intermediate private key in Vault")

        existing = (
            db.query(CertificateAuthority)
            .filter(CertificateAuthority.serial_number == str(certificate.serial_number))
            .first()
        )
        if existing:
            return existing

        subject = certificate.subject
        signature_name = (
            certificate.signature_hash_algorithm.name.upper()
            if certificate.signature_hash_algorithm
            else certificate.signature_algorithm_oid._name.upper()
        )
        intermediate_record = CertificateAuthority(
            common_name=self._get_subject_attr(certificate, NameOID.COMMON_NAME) or subject.rfc4514_string(),
            organization=self._get_subject_attr(certificate, NameOID.ORGANIZATION_NAME) or parent_ca.organization,
            organizational_unit=self._get_subject_attr(certificate, NameOID.ORGANIZATIONAL_UNIT_NAME),
            country=self._get_subject_attr(certificate, NameOID.COUNTRY_NAME) or parent_ca.country,
            state=self._get_subject_attr(certificate, NameOID.STATE_OR_PROVINCE_NAME) or parent_ca.state,
            locality=self._get_subject_attr(certificate, NameOID.LOCALITY_NAME) or parent_ca.locality,
            email=self._get_subject_attr(certificate, NameOID.EMAIL_ADDRESS) or parent_ca.email,
            key_size=certificate.public_key().key_size,
            signature_algorithm=signature_name,
            serial_number=str(certificate.serial_number),
            status=CAStatus.ACTIVE,
            is_root=False,
            is_offline=is_offline,
            parent_ca_id=parent_ca.id,
            pem_certificate=pem_certificate.strip() + "\n",
            private_key_vault_path=key_path,
            issued_at=datetime.now(timezone.utc),
            not_valid_before=certificate.not_valid_before,
            not_valid_after=certificate.not_valid_after,
        )

        db.add(intermediate_record)
        db.commit()
        db.refresh(intermediate_record)
        logger.info(
            "External intermediate CA imported",
            ca_id=intermediate_record.id,
            parent_ca_id=parent_ca.id,
        )
        return intermediate_record

    # ------------------------------------------------------------------
    # Revocation and hierarchy helpers
    # ------------------------------------------------------------------
    def revoke_ca(self, db: Session, ca: CertificateAuthority, reason: str = "unspecified") -> None:
        """Revoke a CA and cascade the revocation down the hierarchy."""
        queue = [ca]
        now = datetime.now(timezone.utc)

        while queue:
            current = queue.pop(0)
            if current.status == CAStatus.REVOKED:
                continue

            current.status = CAStatus.REVOKED
            current.revocation_reason = reason
            current.revoked_at = now

            for cert in current.issued_certificates:
                if cert.status != CertificateStatus.REVOKED:
                    cert.status = CertificateStatus.REVOKED
                    cert.revoked_at = now
                    cert.revocation_reason = f"CA revoked: {reason}"

            queue.extend(current.child_cas)

        db.commit()
        logger.warning("Certificate Authority revoked", ca_id=ca.id, reason=reason)

    def build_certificate_chain(self, ca: CertificateAuthority) -> str:
        """Return PEM chain for the provided CA (leaf first)."""
        pem_parts = [ca.pem_certificate.strip()]
        parent = ca.parent_ca
        while parent:
            pem_parts.append(parent.pem_certificate.strip())
            parent = parent.parent_ca
        return "\n".join(pem_parts) + "\n"

    def set_active_issuing_ca(self, db: Session, ca_id: int) -> CertificateAuthority:
        """Designate the CA that should issue new certificates."""

        ca = self.get_ca_by_id(db, ca_id)
        if not ca:
            raise ValueError("Certificate Authority not found")
        if ca.status == CAStatus.REVOKED:
            raise ValueError("Cannot activate a revoked CA")
        if not ca.private_key_vault_path:
            raise ValueError("Selected CA has no private key in Vault")

        others = (
            db.query(CertificateAuthority)
            .filter(
                CertificateAuthority.id != ca.id,
                CertificateAuthority.is_root.is_(False),
                CertificateAuthority.status == CAStatus.ACTIVE,
            )
            .all()
        )
        for other in others:
            other.status = CAStatus.SUSPENDED

        ca.status = CAStatus.ACTIVE
        ca.is_offline = False
        db.commit()
        db.refresh(ca)
        logger.info("Issuing CA updated", ca_id=ca.id)
        return ca

    def delete_ca(self, db: Session, ca: CertificateAuthority) -> None:
        """Permanently delete a CA that has no dependants or issued certs."""

        if ca.is_root:
            raise ValueError("Root Certificate Authorities cannot be deleted")

        if ca.child_cas:
            raise ValueError("Certificate Authority has child intermediates; delete them first")

        if ca.issued_certificates:
            raise ValueError("Certificate Authority has issued certificates and cannot be removed")

        key_path = ca.private_key_vault_path
        db.delete(ca)
        db.commit()

        if key_path:
            try:
                self.vault.delete_key(key_path)
            except Exception as exc:  # pragma: no cover - best-effort cleanup
                logger.warning(
                    "Failed to delete CA private key from Vault during CA deletion",
                    ca_id=ca.id,
                    error=str(exc),
                )

        logger.info("Certificate Authority deleted", ca_id=ca.id)

    def serialize_ca(self, ca: CertificateAuthority) -> Dict[str, Any]:
        """Convert a CA SQLAlchemy object into a dictionary for responses."""
        return {
            "id": ca.id,
            "common_name": ca.common_name,
            "organization": ca.organization,
            "organizational_unit": ca.organizational_unit,
            "country": ca.country,
            "state": ca.state,
            "locality": ca.locality,
            "email": ca.email,
            "status": ca.status.value,
            "serial_number": ca.serial_number,
            "not_valid_before": ca.not_valid_before,
            "not_valid_after": ca.not_valid_after,
            "issued_certificates_count": ca.certificate_count,
            "is_root": ca.is_root,
            "is_offline": ca.is_offline,
            "parent_ca_id": ca.parent_ca_id,
            "child_count": len(ca.child_cas),
            "days_until_expiry": ca.days_until_expiry,
        }

    def get_hierarchy_summary(self, db: Session) -> Dict[str, Any]:
        """Return serialized hierarchy information for API responses."""
        root = self.get_root_ca(db)
        active = self.get_active_issuing_ca(db)
        all_authorities = self.list_authorities(db)

        return {
            "root_ca": self.serialize_ca(root) if root else None,
            "active_ca": self.serialize_ca(active) if active else None,
            "hierarchy": [self.serialize_ca(ca) for ca in all_authorities],
        }

# Global CA service instance
ca_service = CAService()
