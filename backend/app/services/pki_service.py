"""
PKI core operations for certificate generation, signing, and management.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
import ipaddress
import structlog

from app.core.config import settings
from app.core.vault import vault_client

logger = structlog.get_logger(__name__)


class PKIService:
    """Service for PKI operations including certificate generation and signing."""
    
    def __init__(self):
        """Initialize PKI service."""
        self.vault = vault_client
    
    def generate_private_key(self, key_size: int = 4096) -> rsa.RSAPrivateKey:
        """
        Generate an RSA private key.
        
        Args:
            key_size: RSA key size in bits (2048 or 4096)
            
        Returns:
            RSAPrivateKey: Generated private key
        """
        if key_size not in settings.CERT_ALLOWED_KEY_SIZES:
            raise ValueError(f"Key size {key_size} not allowed. Allowed sizes: {settings.CERT_ALLOWED_KEY_SIZES}")
        
        logger.info("Generating RSA private key", key_size=key_size)
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        return private_key
    
    def create_ca_certificate(
        self,
        common_name: str,
        organization: str,
        organizational_unit: str = None,
        country: str = "US",
        state: str = None,
        locality: str = None,
        email: str = None,
        validity_days: int = None,
        key_size: int = 4096
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Create a self-signed CA certificate.
        
        Args:
            common_name: Certificate common name
            organization: Organization name
            organizational_unit: Organizational unit
            country: Country code (ISO 3166-1 alpha-2)
            state: State or province
            locality: City or locality
            email: Email address
            validity_days: Certificate validity in days
            key_size: RSA key size in bits
            
        Returns:
            Tuple of (Certificate, PrivateKey)
        """
        if validity_days is None:
            validity_days = settings.CA_VALIDITY_DAYS
        
        logger.info("Creating CA certificate", common_name=common_name, validity_days=validity_days)
        
        # Generate private key
        private_key = self.generate_private_key(key_size)
        
        # Build subject
        subject_components = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ]
        
        if organizational_unit:
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
        if state:
            subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if email:
            subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        
        subject = x509.Name(subject_components)
        
        # Create certificate
        now = datetime.now(timezone.utc)
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(subject)  # Self-signed
        cert_builder = cert_builder.public_key(private_key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(now + timedelta(days=validity_days))
        
        # Add CA extensions
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=True,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        
        # Sign the certificate
        hash_algorithm = self._get_hash_algorithm(settings.CERT_SIGNATURE_ALGORITHM)
        certificate = cert_builder.sign(private_key, hash_algorithm)
        
        logger.info("CA certificate created successfully", serial_number=certificate.serial_number)
        
        return certificate, private_key

    def create_intermediate_certificate(
        self,
        parent_cert: x509.Certificate,
        parent_private_key: rsa.RSAPrivateKey,
        common_name: str,
        organization: str,
        organizational_unit: str = None,
        country: str = "US",
        state: str = None,
        locality: str = None,
        email: str = None,
        validity_days: int = None,
        key_size: int = 4096,
        path_length: int = 0,
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Create an intermediate CA certificate signed by an existing parent CA.
        """
        if validity_days is None:
            validity_days = settings.CA_VALIDITY_DAYS

        logger.info(
            "Creating intermediate CA certificate",
            common_name=common_name,
            parent_serial=parent_cert.serial_number,
            path_length=path_length,
        )

        private_key = self.generate_private_key(key_size)

        subject_components = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ]

        if organizational_unit:
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
        if state:
            subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if email:
            subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        subject = x509.Name(subject_components)
        now = datetime.now(timezone.utc)

        # Calculate validity
        not_valid_after = now + timedelta(days=validity_days)
        
        # Cap validity at parent CA expiry
        if parent_cert.not_valid_after < not_valid_after:
            logger.warning(
                "Intermediate CA validity capped by parent CA expiry",
                requested_expiry=not_valid_after,
                capped_expiry=parent_cert.not_valid_after,
                parent_serial=parent_cert.serial_number
            )
            not_valid_after = parent_cert.not_valid_after

        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(parent_cert.subject)
        cert_builder = cert_builder.public_key(private_key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(not_valid_after)

        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )

        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=True,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )

        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_cert.public_key()),
            critical=False,
        )

        hash_algorithm = self._get_hash_algorithm(settings.CERT_SIGNATURE_ALGORITHM)
        certificate = cert_builder.sign(parent_private_key, hash_algorithm)

        logger.info(
            "Intermediate CA certificate created successfully",
            serial_number=certificate.serial_number,
            issuer_serial=parent_cert.serial_number,
        )

        return certificate, private_key
    
    def create_server_certificate(
        self,
        common_name: str,
        subject_alt_names: List[str] = None,
        ca_cert: x509.Certificate = None,
        ca_private_key: rsa.RSAPrivateKey = None,
        validity_days: int = None,
        key_size: int = 4096,
        certificate_type: str = "server"
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Create a server certificate signed by the CA.
        
        Args:
            common_name: Certificate common name
            subject_alt_names: List of subject alternative names
            ca_cert: CA certificate for signing
            ca_private_key: CA private key for signing
            validity_days: Certificate validity in days
            key_size: RSA key size in bits
            certificate_type: Certificate type (server, wildcard, ip)
            
        Returns:
            Tuple of (Certificate, PrivateKey)
        """
        if validity_days is None:
            validity_days = settings.CERT_DEFAULT_VALIDITY_DAYS
        
        if subject_alt_names is None:
            subject_alt_names = []
        
        logger.info("Creating server certificate", common_name=common_name, validity_days=validity_days)
        
        # Generate private key
        private_key = self.generate_private_key(key_size)
        
        # Build subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.CA_ORGANIZATION),
            x509.NameAttribute(NameOID.COUNTRY_NAME, settings.CA_COUNTRY),
        ])
        
        # Create certificate
        now = datetime.now(timezone.utc)
        
        # Calculate validity
        not_valid_after = now + timedelta(days=validity_days)
        
        # Cap validity at CA expiry
        if ca_cert.not_valid_after < not_valid_after:
            logger.warning(
                "Certificate validity capped by CA expiry",
                requested_expiry=not_valid_after,
                capped_expiry=ca_cert.not_valid_after,
                ca_serial=ca_cert.serial_number
            )
            not_valid_after = ca_cert.not_valid_after

        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(ca_cert.subject)
        cert_builder = cert_builder.public_key(private_key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(not_valid_after)
        
        # Add server certificate extensions
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        
        # Add Subject Alternative Names
        san_list = []
        
        # Add common name to SAN if not already present
        if common_name not in subject_alt_names:
            subject_alt_names.insert(0, common_name)
        
        for san in subject_alt_names:
            san = san.strip()
            if not san:
                continue
                
            # Check if it's an IP address
            try:
                ip = ipaddress.ip_address(san)
                san_list.append(x509.IPAddress(ip))
            except ValueError:
                # It's a DNS name
                san_list.append(x509.DNSName(san))
        
        if san_list:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
        
        # Sign the certificate
        hash_algorithm = self._get_hash_algorithm(settings.CERT_SIGNATURE_ALGORITHM)
        certificate = cert_builder.sign(ca_private_key, hash_algorithm)
        
        logger.info("Server certificate created successfully", 
                   serial_number=certificate.serial_number,
                   common_name=common_name)
        
        return certificate, private_key
    
    def create_crl(
        self,
        ca_cert: x509.Certificate,
        ca_private_key: rsa.RSAPrivateKey,
        revoked_certificates: List[Tuple[int, datetime, x509.ReasonFlags]] = None
    ) -> x509.CertificateRevocationList:
        """
        Create a Certificate Revocation List (CRL).
        
        Args:
            ca_cert: CA certificate
            ca_private_key: CA private key
            revoked_certificates: List of (serial_number, revocation_date, reason) tuples
            
        Returns:
            CertificateRevocationList: Generated CRL
        """
        logger.info("Creating Certificate Revocation List")
        
        if revoked_certificates is None:
            revoked_certificates = []
        
        now = datetime.now(timezone.utc)
        next_update = now + timedelta(days=7)  # CRL valid for 7 days
        
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(next_update)
        
        # Add revoked certificates
        for serial_number, revocation_date, reason in revoked_certificates:
            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                serial_number
            ).revocation_date(revocation_date)
            
            if reason:
                revoked_cert = revoked_cert.add_extension(
                    x509.CRLReason(reason), critical=False
                )
            
            builder = builder.add_revoked_certificate(revoked_cert.build())
        
        # Sign the CRL
        hash_algorithm = self._get_hash_algorithm(settings.CERT_SIGNATURE_ALGORITHM)
        crl = builder.sign(ca_private_key, hash_algorithm)
        
        logger.info("CRL created successfully", revoked_count=len(revoked_certificates))
        
        return crl
    
    def validate_certificate(self, cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
        """
        Validate a certificate against the CA certificate.
        
        Args:
            cert: Certificate to validate
            ca_cert: CA certificate
            
        Returns:
            bool: True if certificate is valid
        """
        try:
            # Check if certificate is signed by the CA
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_oid._name
            )
            
            # Check validity period
            now = datetime.now(timezone.utc)
            if now < cert.not_valid_before or now > cert.not_valid_after:
                logger.warning("Certificate is outside validity period", 
                             serial_number=cert.serial_number)
                return False
            
            logger.info("Certificate validation successful", serial_number=cert.serial_number)
            return True
            
        except Exception as e:
            logger.error("Certificate validation failed", 
                        serial_number=cert.serial_number, 
                        error=str(e))
            return False
    
    def certificate_to_pem(self, cert: x509.Certificate) -> str:
        """
        Convert certificate to PEM format.
        
        Args:
            cert: Certificate to convert
            
        Returns:
            str: PEM encoded certificate
        """
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    def private_key_to_pem(self, private_key: rsa.RSAPrivateKey) -> str:
        """
        Convert private key to PEM format.
        
        Args:
            private_key: Private key to convert
            
        Returns:
            str: PEM encoded private key
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    def crl_to_pem(self, crl: x509.CertificateRevocationList) -> str:
        """
        Convert CRL to PEM format.
        
        Args:
            crl: CRL to convert
            
        Returns:
            str: PEM encoded CRL
        """
        return crl.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    def _get_hash_algorithm(self, algorithm_name: str):
        """
        Get hash algorithm instance from name.
        
        Args:
            algorithm_name: Algorithm name (SHA256, SHA384, SHA512)
            
        Returns:
            Hash algorithm instance
        """
        algorithms = {
            "SHA256": hashes.SHA256(),
            "SHA384": hashes.SHA384(),
            "SHA512": hashes.SHA512(),
        }
        
        return algorithms.get(algorithm_name, hashes.SHA256())


# Global PKI service instance
pki_service = PKIService()