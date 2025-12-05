"""
HashiCorp Vault client for secure key storage and PKI operations.
"""

import hvac
import structlog
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from app.core.config import settings

logger = structlog.get_logger(__name__)


class VaultClient:
    """
    HashiCorp Vault client for PKI operations and secure storage.
    """
    
    def __init__(self):
        self.client = None
        self.authenticated = False
        self._dev_store: Dict[str, Dict[str, Any]] = {}
        self._dev_ca: Optional[Dict[str, Any]] = None
        self._dev_store_dir: Optional[Path] = None
        self._dev_keys_dir: Optional[Path] = None
        self._dev_ca_path: Optional[Path] = None
        self.connect()
    
    def connect(self):
        """Initialize Vault client connection."""
        try:
            if settings.VAULT_DEV_MODE:
                logger.warning("Vault dev mode enabled - using in-memory key store")
                self.authenticated = True
                self._dev_store = {}
                self._dev_ca = None
                self._init_dev_storage()
                return
            
            self.client = hvac.Client(url=settings.VAULT_ADDR)
            
            # Determine authentication method
            token = settings.VAULT_TOKEN
            
            # If no token in env, check database
            if not token and not (settings.VAULT_ROLE_ID and settings.VAULT_SECRET_ID):
                try:
                    from app.core.database import SessionLocal
                    from app.models.system import SystemConfig
                    from app.core.security import decrypt_value
                    
                    # Create a new session just for this check
                    # We use a try/except block because this might run before tables are created
                    db = SessionLocal()
                    try:
                        config = db.query(SystemConfig).filter(SystemConfig.key == "vault_token").first()
                        if config and config.value:
                            token = decrypt_value(config.value)
                            logger.info("Retrieved Vault token from database")
                    finally:
                        db.close()
                except Exception as e:
                    # This is expected during first run or if tables don't exist yet
                    logger.debug("Could not retrieve Vault token from DB", error=str(e))

            # Authenticate using token or AppRole
            if token:
                self.client.token = token
            elif settings.VAULT_ROLE_ID and settings.VAULT_SECRET_ID:
                self.client.auth.approle.login(
                    role_id=settings.VAULT_ROLE_ID,
                    secret_id=settings.VAULT_SECRET_ID
                )
            
            # Verify authentication
            if self.client.is_authenticated():
                self.authenticated = True
                logger.info("Vault client authenticated successfully")
            else:
                # Don't log error if we just didn't have credentials yet
                if token or (settings.VAULT_ROLE_ID and settings.VAULT_SECRET_ID):
                    logger.error("Vault authentication failed")
                else:
                    logger.info("Vault client not authenticated (no credentials found)")
                self.authenticated = False
                
        except Exception as e:
            logger.error("Failed to connect to Vault", error=str(e))
            self.authenticated = False
    
    def is_authenticated(self) -> bool:
        """Check if Vault client is authenticated."""
        if settings.VAULT_DEV_MODE:
            return True
        try:
            return self.client and self.client.is_authenticated()
        except:
            return False
    
    def _init_dev_storage(self) -> None:
        self._dev_store_dir = Path("data/vault-dev")
        self._dev_store_dir.mkdir(parents=True, exist_ok=True)
        self._dev_keys_dir = self._dev_store_dir / "keys"
        self._dev_keys_dir.mkdir(parents=True, exist_ok=True)
        self._dev_ca_path = self._dev_store_dir / "ca_certificate.pem"

    def _normalize_key_id(self, key_id: str) -> str:
        return key_id if key_id.startswith("pki/keys/") else f"pki/keys/{key_id}"

    def _dev_key_filename(self, normalized_id: str) -> Optional[Path]:
        if not self._dev_keys_dir:
            return None
        safe_name = normalized_id.replace('/', '__')
        return self._dev_keys_dir / f"{safe_name}.pem"

    def _persist_dev_key(self, normalized_id: str, pem_data: str) -> None:
        path = self._dev_key_filename(normalized_id)
        if path:
            path.write_text(pem_data)

    def _load_dev_key(self, normalized_id: str) -> Optional[Dict[str, Any]]:
        if normalized_id in self._dev_store:
            return self._dev_store[normalized_id]
        path = self._dev_key_filename(normalized_id)
        if path and path.exists():
            pem_data = path.read_text()
            secret = {
                'private_key': pem_data,
                'key_type': 'RSA',
                'key_size': None,
            }
            self._dev_store[normalized_id] = secret
            return secret
        return None

    def store_private_key(self, key_id: str, private_key: rsa.RSAPrivateKey) -> bool:
        """
        Store a private key in Vault.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            if settings.VAULT_DEV_MODE:
                normalized_id = self._normalize_key_id(key_id)
                self._dev_store[normalized_id] = {
                    'private_key': pem_data,
                    'key_type': 'RSA',
                    'key_size': private_key.key_size,
                }
                self._persist_dev_key(normalized_id, pem_data)
            else:
                # Store in Vault KV store
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=f"pki/keys/{key_id}",
                    secret={
                        'private_key': pem_data,
                        'key_type': 'RSA',
                        'key_size': private_key.key_size
                    }
                )
            
            logger.info("Private key stored in Vault", key_id=key_id)
            return True
            
        except Exception as e:
            logger.error("Failed to store private key", key_id=key_id, error=str(e))
            return False
    
    def retrieve_private_key(self, key_id: str) -> Optional[rsa.RSAPrivateKey]:
        """
        Retrieve a private key from Vault.
        
        Args:
            key_id: Unique identifier for the key
            
        Returns:
            RSAPrivateKey: The private key, or None if not found
        """
        try:
            if settings.VAULT_DEV_MODE:
                lookup_id = self._normalize_key_id(key_id)
                secret = self._load_dev_key(lookup_id)
                if not secret:
                    raise KeyError("Key not found in dev store")
                pem_data = secret['private_key']
            else:
                # Retrieve from Vault KV store
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=f"pki/keys/{key_id}"
                )
                pem_data = response['data']['data']['private_key']
            
            # Deserialize private key from PEM format
            private_key = serialization.load_pem_private_key(
                pem_data.encode('utf-8'),
                password=None
            )
            
            logger.info("Private key retrieved from Vault", key_id=key_id)
            return private_key
            
        except Exception as e:
            logger.error("Failed to retrieve private key", key_id=key_id, error=str(e))
            return None
    
    def store_ca_certificate(self, ca_cert: x509.Certificate) -> bool:
        """
        Store CA certificate in Vault.
        
        Args:
            ca_cert: CA certificate to store
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Serialize certificate to PEM format
            pem_data = ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            payload = {
                'certificate': pem_data,
                'subject': str(ca_cert.subject),
                'issuer': str(ca_cert.issuer),
                'serial_number': str(ca_cert.serial_number),
                'not_valid_before': ca_cert.not_valid_before.isoformat(),
                'not_valid_after': ca_cert.not_valid_after.isoformat()
            }

            if settings.VAULT_DEV_MODE:
                self._dev_ca = payload
                if self._dev_ca_path:
                    self._dev_ca_path.write_text(pem_data)
            else:
                # Store in Vault
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=f"pki/ca/certificate",
                    secret=payload
                )
            
            logger.info("CA certificate stored in Vault")
            return True
            
        except Exception as e:
            logger.error("Failed to store CA certificate", error=str(e))
            return False
    
    def retrieve_ca_certificate(self) -> Optional[x509.Certificate]:
        """
        Retrieve CA certificate from Vault.
        
        Returns:
            Certificate: The CA certificate, or None if not found
        """
        try:
            if settings.VAULT_DEV_MODE:
                if not self._dev_ca:
                    if self._dev_ca_path and self._dev_ca_path.exists():
                        self._dev_ca = {'certificate': self._dev_ca_path.read_text()}
                    else:
                        raise KeyError("CA certificate not stored in dev mode")
                pem_data = self._dev_ca['certificate']
            else:
                # Retrieve from Vault
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=f"pki/ca/certificate"
                )
                pem_data = response['data']['data']['certificate']
            
            # Deserialize certificate from PEM format
            ca_cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'))
            
            logger.info("CA certificate retrieved from Vault")
            return ca_cert
            
        except Exception as e:
            logger.error("Failed to retrieve CA certificate", error=str(e))
            return None
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from Vault.
        
        Args:
            key_id: Unique identifier for the key
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if settings.VAULT_DEV_MODE:
                normalized_id = self._normalize_key_id(key_id)
                self._dev_store.pop(normalized_id, None)
                path = self._dev_key_filename(normalized_id)
                if path and path.exists():
                    path.unlink()
            else:
                self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=f"pki/keys/{key_id}"
                )
            
            logger.info("Key deleted from Vault", key_id=key_id)
            return True
            
        except Exception as e:
            logger.error("Failed to delete key", key_id=key_id, error=str(e))
            return False
    
    def list_stored_keys(self, subpath: str = "") -> list:
        """
        List stored keys in Vault.
        
        Args:
            subpath: Optional subpath under pki/keys (e.g. "certificates")
            
        Returns:
            list: List of key identifiers (relative to the path)
        """
        try:
            path = "pki/keys"
            if subpath:
                path = f"{path}/{subpath}"
                
            if settings.VAULT_DEV_MODE:
                # Filter dev store keys that start with the path
                # Note: _dev_store keys are full paths like "pki/keys/certificates/123"
                prefix = f"{path}/"
                keys = []
                for k in self._dev_store.keys():
                    if k.startswith(prefix):
                        # Return just the filename part
                        keys.append(k[len(prefix):])
                    elif not subpath and k.startswith("pki/keys/") and "/" not in k[9:]:
                         # Root level keys
                         keys.append(k[9:])
                return keys

            response = self.client.secrets.kv.v2.list_secrets(path=path)
            return response['data']['keys']
            
        except Exception as e:
            # It's common to get 404 if the path doesn't exist (e.g. no keys yet)
            return []
    
    def get_vault_status(self) -> Dict[str, Any]:
        """
        Get Vault status and health information.
        
        Returns:
            dict: Vault status information
        """
        try:
            if settings.VAULT_DEV_MODE:
                return {
                    'authenticated': True,
                    'initialized': True,
                    'sealed': False,
                    'standby': False,
                    'server_time_utc': None,
                    'version': 'dev',
                    'cluster_name': 'dev'
                }
            
            # Check initialization status first (doesn't require auth)
            try:
                initialized = self.client.sys.is_initialized()
                logger.info(f"Vault initialization check: {initialized}")
            except Exception as e:
                logger.error(f"Vault initialization check failed: {e}")
                initialized = False

            health = {}
            try:
                health = self.client.sys.read_health_status(method='GET')
                if hasattr(health, 'json'):
                    health = health.json()
            except Exception:
                # If uninitialized, health check might fail or return different structure
                pass
                
            return {
                'authenticated': self.is_authenticated(),
                'initialized': initialized,
                'sealed': health.get('sealed', True) if initialized else True,
                'standby': health.get('standby', False),
                'server_time_utc': health.get('server_time_utc'),
                'version': health.get('version'),
                'cluster_name': health.get('cluster_name')
            }
            
        except Exception as e:
            logger.error("Failed to get Vault status", error=str(e))
            return {
                'authenticated': False,
                'initialized': False,
                'error': str(e)
            }

    def initialize_vault(self, shares: int = 5, threshold: int = 3) -> Dict[str, Any]:
        """
        Initialize a fresh Vault instance.
        
        Returns:
            dict: { 'root_token': str, 'keys': list[str] }
        """
        if settings.VAULT_DEV_MODE:
            raise Exception("Cannot initialize Vault in dev mode")
            
        if self.client.sys.is_initialized():
            raise Exception("Vault is already initialized")
            
        result = self.client.sys.initialize(shares, threshold)
        return result

    def seal_vault(self) -> Dict[str, Any]:
        """
        Seal Vault. Requires root token or operator permissions.
        
        Returns:
            dict: Seal status with 'sealed' key
        """
        if settings.VAULT_DEV_MODE:
            logger.warning("Cannot seal Vault in dev mode")
            return {'sealed': False, 'message': 'Cannot seal Vault in dev mode'}
            
        try:
            self.client.sys.seal()
            logger.info("Vault sealed successfully")
            return {'sealed': True, 'message': 'Vault sealed successfully'}
        except Exception as e:
            logger.error(f"Failed to seal Vault: {e}")
            raise

    def unseal_vault(self, keys: list[str]) -> Dict[str, Any]:
        """
        Unseal Vault using provided keys.
        
        Returns:
            dict: Unseal status
        """
        if settings.VAULT_DEV_MODE:
            return {'sealed': False}
            
        if not keys:
            raise Exception("No unseal keys provided")
            
        response = None
        for key in keys:
            response = self.client.sys.submit_unseal_key(key)
            if not response['sealed']:
                break
                
        return response

    def enable_kv_engine(self, path: str = "secret"):
        """Enable KV v2 secrets engine at the specified path."""
        if settings.VAULT_DEV_MODE:
            return
            
        try:
            # Check if already enabled
            mounts = self.client.sys.list_mounted_secrets_engines()
            if f"{path}/" in mounts:
                logger.info(f"KV engine already enabled at {path}/")
                return

            self.client.sys.enable_secrets_engine(
                backend_type='kv',
                path=path,
                options={'version': '2'}
            )
            logger.info(f"Enabled KV v2 engine at {path}/")
        except Exception as e:
            logger.error(f"Failed to enable KV engine at {path}/", error=str(e))
            raise


# Global Vault client instance
vault_client = VaultClient()