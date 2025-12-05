"""
Auto-Unseal Key Management

This module implements secure storage and retrieval of Vault unseal keys using
envelope encryption with cloud KMS providers.

Architecture:
1. Unseal keys are encrypted with a Data Encryption Key (DEK)
2. The DEK is wrapped (encrypted) by cloud KMS providers
3. Multiple KMS providers can hold wrapped copies of the DEK for redundancy
4. On unseal, the DEK is unwrapped by KMS, then used to decrypt the unseal keys

Security:
- Unseal keys never leave the system unencrypted
- KMS providers only see the wrapped DEK, not the actual secrets
- Multiple KMS providers provide redundancy and failover
"""

import os
import json
import base64
import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class AutoUnsealKeyManager:
    """Manages encrypted storage and retrieval of Vault unseal keys."""
    
    # Database keys for storing encrypted data
    DB_KEY_ENCRYPTED_UNSEAL_KEYS = "auto_unseal_encrypted_keys"
    DB_KEY_WRAPPED_DEK_PREFIX = "auto_unseal_wrapped_dek_"
    DB_KEY_LOCAL_DEK = "auto_unseal_local_dek"  # For unencrypted local storage
    
    def __init__(self, db_session=None):
        self.db = db_session
    
    def generate_dek(self) -> bytes:
        """Generate a new 256-bit Data Encryption Key."""
        return os.urandom(32)  # 256 bits
    
    def encrypt_unseal_keys(self, unseal_keys: List[str], dek: bytes) -> str:
        """
        Encrypt unseal keys with the DEK using AES-256-GCM.
        
        Args:
            unseal_keys: List of Vault unseal keys
            dek: 256-bit Data Encryption Key
            
        Returns:
            Base64-encoded encrypted blob (nonce + ciphertext + tag)
        """
        # Serialize keys to JSON
        plaintext = json.dumps({"keys": unseal_keys}).encode('utf-8')
        
        # Generate random nonce (96 bits for GCM)
        nonce = os.urandom(12)
        
        # Encrypt with AES-256-GCM
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Combine nonce + ciphertext (tag is appended by AESGCM)
        encrypted_blob = nonce + ciphertext
        
        return base64.b64encode(encrypted_blob).decode('utf-8')
    
    def decrypt_unseal_keys(self, encrypted_blob: str, dek: bytes) -> List[str]:
        """
        Decrypt unseal keys using the DEK.
        
        Args:
            encrypted_blob: Base64-encoded encrypted data
            dek: 256-bit Data Encryption Key
            
        Returns:
            List of Vault unseal keys
        """
        # Decode from base64
        data = base64.b64decode(encrypted_blob)
        
        # Extract nonce (first 12 bytes) and ciphertext+tag (rest)
        nonce = data[:12]
        ciphertext = data[12:]
        
        # Decrypt with AES-256-GCM
        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Parse JSON
        keys_data = json.loads(plaintext.decode('utf-8'))
        return keys_data.get('keys', [])
    
    def wrap_dek_with_oci_kms(self, dek: bytes, kms_config: dict) -> Dict[str, Any]:
        """
        Wrap (encrypt) the DEK using OCI KMS.
        
        Args:
            dek: The Data Encryption Key to wrap
            kms_config: OCI KMS configuration
            
        Returns:
            Dict with wrapped_dek and metadata (including full config for later unwrapping)
        """
        try:
            import oci
            from app.core.security import decrypt_value, encrypt_value
            
            key_id = kms_config.get('key_id') or kms_config.get('key_ocid')
            crypto_endpoint = kms_config.get('crypto_endpoint')
            use_instance_principal = kms_config.get('auth_type_use_instance_principal') or kms_config.get('use_instance_principal', False)
            
            if not key_id or not crypto_endpoint:
                return {"success": False, "error": "Missing key_id or crypto_endpoint"}
            
            # Encode DEK as base64 (OCI requires this)
            dek_b64 = base64.b64encode(dek).decode('utf-8')
            
            if use_instance_principal:
                signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
                oci_config = {}
                crypto_client = oci.key_management.KmsCryptoClient(
                    {}, signer=signer, service_endpoint=crypto_endpoint
                )
            else:
                # API Key authentication
                user_ocid = kms_config.get('auth_type_api_key_user_ocid') or kms_config.get('user_ocid')
                fingerprint = kms_config.get('auth_type_api_key_fingerprint') or kms_config.get('fingerprint')
                tenancy_ocid = kms_config.get('auth_type_api_key_tenancy_ocid') or kms_config.get('tenancy_ocid')
                region = kms_config.get('auth_type_api_key_region') or kms_config.get('region')
                private_key = kms_config.get('auth_type_api_key_private_key') or kms_config.get('private_key')
                
                # Decrypt private key if encrypted
                if private_key:
                    try:
                        private_key = decrypt_value(private_key)
                    except:
                        pass
                
                oci_config = {
                    "user": user_ocid,
                    "key_content": private_key,
                    "fingerprint": fingerprint,
                    "tenancy": tenancy_ocid,
                    "region": region
                }
                
                crypto_client = oci.key_management.KmsCryptoClient(
                    oci_config, service_endpoint=crypto_endpoint
                )
            
            # Encrypt (wrap) the DEK
            encrypt_response = crypto_client.encrypt(
                encrypt_data_details=oci.key_management.models.EncryptDataDetails(
                    key_id=key_id,
                    plaintext=dek_b64
                )
            )
            
            # Build result with full config needed for unwrapping
            result = {
                "success": True,
                "wrapped_dek": encrypt_response.data.ciphertext,
                "key_id": key_id,
                "crypto_endpoint": crypto_endpoint,
                "provider": "ocikms",
                "wrapped_at": datetime.now(timezone.utc).isoformat(),
                "use_instance_principal": use_instance_principal
            }
            
            # Store encrypted auth config for later unwrapping (if not using instance principal)
            if not use_instance_principal:
                auth_config = {
                    "user_ocid": user_ocid,
                    "fingerprint": fingerprint,
                    "tenancy_ocid": tenancy_ocid,
                    "region": region,
                    "private_key": private_key  # Already decrypted
                }
                # Encrypt the auth config before storing
                result["auth_config_encrypted"] = encrypt_value(json.dumps(auth_config))
            
            return result
            
        except Exception as e:
            logger.error(f"OCI KMS wrap failed: {e}")
            return {"success": False, "error": str(e)}
    
    def unwrap_dek_with_oci_kms(self, wrapped_dek: str, kms_config: dict) -> Optional[bytes]:
        """
        Unwrap (decrypt) the DEK using OCI KMS.
        
        Args:
            wrapped_dek: The wrapped DEK ciphertext
            kms_config: OCI KMS configuration (can include auth_config_encrypted from wrap result)
            
        Returns:
            The unwrapped DEK bytes, or None on failure
        """
        try:
            import oci
            from app.core.security import decrypt_value
            
            key_id = kms_config.get('key_id') or kms_config.get('key_ocid')
            crypto_endpoint = kms_config.get('crypto_endpoint')
            use_instance_principal = kms_config.get('auth_type_use_instance_principal') or kms_config.get('use_instance_principal', False)
            
            if not key_id or not crypto_endpoint:
                logger.error("Missing key_id or crypto_endpoint for OCI unwrap")
                return None
            
            if use_instance_principal:
                signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
                crypto_client = oci.key_management.KmsCryptoClient(
                    {}, signer=signer, service_endpoint=crypto_endpoint
                )
            else:
                # Try to get auth config from the wrapped DEK record first
                auth_config_encrypted = kms_config.get('auth_config_encrypted')
                if auth_config_encrypted:
                    try:
                        auth_config_json = decrypt_value(auth_config_encrypted)
                        auth_config = json.loads(auth_config_json)
                        user_ocid = auth_config.get('user_ocid')
                        fingerprint = auth_config.get('fingerprint')
                        tenancy_ocid = auth_config.get('tenancy_ocid')
                        region = auth_config.get('region')
                        private_key = auth_config.get('private_key')
                    except Exception as e:
                        logger.warning(f"Failed to decrypt stored auth config: {e}, falling back to kms_config")
                        auth_config_encrypted = None
                
                if not auth_config_encrypted:
                    # Fall back to reading from kms_config directly
                    user_ocid = kms_config.get('auth_type_api_key_user_ocid') or kms_config.get('user_ocid')
                    fingerprint = kms_config.get('auth_type_api_key_fingerprint') or kms_config.get('fingerprint')
                    tenancy_ocid = kms_config.get('auth_type_api_key_tenancy_ocid') or kms_config.get('tenancy_ocid')
                    region = kms_config.get('auth_type_api_key_region') or kms_config.get('region')
                    private_key = kms_config.get('auth_type_api_key_private_key') or kms_config.get('private_key')
                    
                    if private_key:
                        try:
                            private_key = decrypt_value(private_key)
                        except:
                            pass
                
                # Validate we have all required fields
                missing = []
                if not user_ocid: missing.append("user")
                if not tenancy_ocid: missing.append("tenancy")
                if not region: missing.append("region")
                if not fingerprint: missing.append("fingerprint")
                if not private_key: missing.append("key_file")
                
                if missing:
                    missing_str = ', '.join([f'"{m}": "missing"' for m in missing])
                    logger.error(f"OCI KMS unwrap failed: {{{missing_str}}}")
                    return None
                
                oci_config = {
                    "user": user_ocid,
                    "key_content": private_key,
                    "fingerprint": fingerprint,
                    "tenancy": tenancy_ocid,
                    "region": region
                }
                
                crypto_client = oci.key_management.KmsCryptoClient(
                    oci_config, service_endpoint=crypto_endpoint
                )
            
            # Decrypt (unwrap) the DEK
            decrypt_response = crypto_client.decrypt(
                decrypt_data_details=oci.key_management.models.DecryptDataDetails(
                    key_id=key_id,
                    ciphertext=wrapped_dek
                )
            )
            
            # Decode from base64
            return base64.b64decode(decrypt_response.data.plaintext)
            
        except Exception as e:
            logger.error(f"OCI KMS unwrap failed: {e}")
            return None
    
    def wrap_dek_with_gcp_kms(self, dek: bytes, kms_config: dict) -> Dict[str, Any]:
        """
        Wrap (encrypt) the DEK using GCP Cloud KMS.
        
        Args:
            dek: The Data Encryption Key to wrap
            kms_config: GCP KMS configuration
            
        Returns:
            Dict with wrapped_dek and metadata (including encrypted credentials for later unwrapping)
        """
        try:
            from google.cloud import kms
            from google.oauth2 import service_account
            from app.core.security import decrypt_value, encrypt_value
            
            project = kms_config.get('project')
            location = kms_config.get('location') or kms_config.get('region')
            key_ring = kms_config.get('key_ring')
            crypto_key = kms_config.get('crypto_key')
            credentials_json = kms_config.get('credentials') or kms_config.get('credentials_json')
            
            if not all([project, location, key_ring, crypto_key]):
                return {"success": False, "error": "Missing GCP KMS configuration"}
            
            # Decrypt credentials if encrypted
            decrypted_credentials = None
            if credentials_json:
                try:
                    decrypted_credentials = decrypt_value(credentials_json)
                except:
                    decrypted_credentials = credentials_json
                creds_dict = json.loads(decrypted_credentials)
                credentials = service_account.Credentials.from_service_account_info(creds_dict)
                client = kms.KeyManagementServiceClient(credentials=credentials)
            else:
                client = kms.KeyManagementServiceClient()
            
            # Build key name
            key_name = client.crypto_key_path(project, location, key_ring, crypto_key)
            
            # Encrypt (wrap) the DEK
            encrypt_response = client.encrypt(
                request={"name": key_name, "plaintext": dek}
            )
            
            # Build result with full config needed for unwrapping
            result = {
                "success": True,
                "wrapped_dek": base64.b64encode(encrypt_response.ciphertext).decode('utf-8'),
                "key_name": key_name,
                "project": project,
                "location": location,
                "key_ring": key_ring,
                "crypto_key": crypto_key,
                "provider": "gcpckms",
                "wrapped_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Store encrypted credentials for later unwrapping
            if decrypted_credentials:
                result["credentials_encrypted"] = encrypt_value(decrypted_credentials)
            
            return result
            
        except Exception as e:
            logger.error(f"GCP KMS wrap failed: {e}")
            return {"success": False, "error": str(e)}
    
    def unwrap_dek_with_gcp_kms(self, wrapped_dek: str, kms_config: dict) -> Optional[bytes]:
        """
        Unwrap (decrypt) the DEK using GCP Cloud KMS.
        
        Args:
            wrapped_dek: The wrapped DEK ciphertext
            kms_config: GCP KMS configuration (can include credentials_encrypted from wrap result)
            
        Returns:
            The unwrapped DEK bytes, or None on failure
        """
        try:
            from google.cloud import kms
            from google.oauth2 import service_account
            from app.core.security import decrypt_value
            
            project = kms_config.get('project')
            location = kms_config.get('location') or kms_config.get('region')
            key_ring = kms_config.get('key_ring')
            crypto_key = kms_config.get('crypto_key')
            
            if not all([project, location, key_ring, crypto_key]):
                logger.error(f"Missing GCP KMS configuration for unwrap: project={project}, location={location}, key_ring={key_ring}, crypto_key={crypto_key}")
                return None
            
            # Try to get credentials from encrypted storage first (from wrap result)
            credentials_json = None
            credentials_encrypted = kms_config.get('credentials_encrypted')
            if credentials_encrypted:
                try:
                    credentials_json = decrypt_value(credentials_encrypted)
                except Exception as e:
                    logger.warning(f"Failed to decrypt stored credentials: {e}, trying direct credentials")
            
            # Fall back to direct credentials if not found in encrypted storage
            if not credentials_json:
                credentials_json = kms_config.get('credentials') or kms_config.get('credentials_json')
                if credentials_json:
                    try:
                        credentials_json = decrypt_value(credentials_json)
                    except:
                        pass
            
            if credentials_json:
                creds_dict = json.loads(credentials_json)
                credentials = service_account.Credentials.from_service_account_info(creds_dict)
                client = kms.KeyManagementServiceClient(credentials=credentials)
            else:
                # Use default credentials (e.g., from environment)
                client = kms.KeyManagementServiceClient()
            
            key_name = client.crypto_key_path(project, location, key_ring, crypto_key)
            
            # Decrypt (unwrap) the DEK
            ciphertext = base64.b64decode(wrapped_dek)
            decrypt_response = client.decrypt(
                request={"name": key_name, "ciphertext": ciphertext}
            )
            
            return decrypt_response.plaintext
            
        except Exception as e:
            logger.error(f"GCP KMS unwrap failed: {e}")
            return None
    
    def wrap_dek_with_aws_kms(self, dek: bytes, kms_config: dict) -> Dict[str, Any]:
        """
        Wrap (encrypt) the DEK using AWS KMS.
        """
        try:
            import boto3
            from app.core.security import decrypt_value
            
            region = kms_config.get('region', 'us-east-1')
            kms_key_id = kms_config.get('kms_key_id')
            access_key = kms_config.get('access_key')
            secret_key = kms_config.get('secret_key')
            
            if not kms_key_id:
                return {"success": False, "error": "Missing KMS key ID"}
            
            # Decrypt credentials if needed
            if access_key:
                try:
                    access_key = decrypt_value(access_key)
                except:
                    pass
            if secret_key:
                try:
                    secret_key = decrypt_value(secret_key)
                except:
                    pass
            
            # Create client
            if access_key and secret_key:
                client = boto3.client(
                    'kms',
                    region_name=region,
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key
                )
            else:
                client = boto3.client('kms', region_name=region)
            
            # Encrypt (wrap) the DEK
            response = client.encrypt(
                KeyId=kms_key_id,
                Plaintext=dek
            )
            
            return {
                "success": True,
                "wrapped_dek": base64.b64encode(response['CiphertextBlob']).decode('utf-8'),
                "key_id": kms_key_id,
                "provider": "awskms",
                "wrapped_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"AWS KMS wrap failed: {e}")
            return {"success": False, "error": str(e)}
    
    def unwrap_dek_with_aws_kms(self, wrapped_dek: str, kms_config: dict) -> Optional[bytes]:
        """
        Unwrap (decrypt) the DEK using AWS KMS.
        """
        try:
            import boto3
            from app.core.security import decrypt_value
            
            region = kms_config.get('region', 'us-east-1')
            access_key = kms_config.get('access_key')
            secret_key = kms_config.get('secret_key')
            
            if access_key:
                try:
                    access_key = decrypt_value(access_key)
                except:
                    pass
            if secret_key:
                try:
                    secret_key = decrypt_value(secret_key)
                except:
                    pass
            
            if access_key and secret_key:
                client = boto3.client(
                    'kms',
                    region_name=region,
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key
                )
            else:
                client = boto3.client('kms', region_name=region)
            
            ciphertext = base64.b64decode(wrapped_dek)
            response = client.decrypt(CiphertextBlob=ciphertext)
            
            return response['Plaintext']
            
        except Exception as e:
            logger.error(f"AWS KMS unwrap failed: {e}")
            return None
    
    def wrap_dek_with_azure_keyvault(self, dek: bytes, kms_config: dict) -> Dict[str, Any]:
        """
        Wrap (encrypt) the DEK using Azure Key Vault.
        """
        try:
            from azure.identity import ClientSecretCredential
            from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
            from azure.keyvault.keys import KeyClient
            from app.core.security import decrypt_value
            
            vault_name = kms_config.get('vault_name')
            tenant_id = kms_config.get('tenant_id')
            client_id = kms_config.get('client_id')
            client_secret = kms_config.get('client_secret')
            key_name = kms_config.get('key_name')
            
            if not all([vault_name, tenant_id, client_id, client_secret, key_name]):
                return {"success": False, "error": "Missing Azure Key Vault configuration"}
            
            if client_secret:
                try:
                    client_secret = decrypt_value(client_secret)
                except:
                    pass
            
            vault_url = f"https://{vault_name}.vault.azure.net"
            
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Get the key
            key_client = KeyClient(vault_url=vault_url, credential=credential)
            key = key_client.get_key(key_name)
            
            # Create crypto client for the key
            crypto_client = CryptographyClient(key, credential=credential)
            
            # Encrypt (wrap) the DEK
            result = crypto_client.encrypt(EncryptionAlgorithm.rsa_oaep_256, dek)
            
            return {
                "success": True,
                "wrapped_dek": base64.b64encode(result.ciphertext).decode('utf-8'),
                "key_name": key_name,
                "vault_name": vault_name,
                "provider": "azurekeyvault",
                "wrapped_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Azure Key Vault wrap failed: {e}")
            return {"success": False, "error": str(e)}
    
    def unwrap_dek_with_azure_keyvault(self, wrapped_dek: str, kms_config: dict) -> Optional[bytes]:
        """
        Unwrap (decrypt) the DEK using Azure Key Vault.
        """
        try:
            from azure.identity import ClientSecretCredential
            from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
            from azure.keyvault.keys import KeyClient
            from app.core.security import decrypt_value
            
            vault_name = kms_config.get('vault_name')
            tenant_id = kms_config.get('tenant_id')
            client_id = kms_config.get('client_id')
            client_secret = kms_config.get('client_secret')
            key_name = kms_config.get('key_name')
            
            if not all([vault_name, tenant_id, client_id, client_secret, key_name]):
                logger.error("Missing Azure Key Vault configuration for unwrap")
                return None
            
            if client_secret:
                try:
                    client_secret = decrypt_value(client_secret)
                except:
                    pass
            
            vault_url = f"https://{vault_name}.vault.azure.net"
            
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            key_client = KeyClient(vault_url=vault_url, credential=credential)
            key = key_client.get_key(key_name)
            
            crypto_client = CryptographyClient(key, credential=credential)
            
            ciphertext = base64.b64decode(wrapped_dek)
            result = crypto_client.decrypt(EncryptionAlgorithm.rsa_oaep_256, ciphertext)
            
            return result.plaintext
            
        except Exception as e:
            logger.error(f"Azure Key Vault unwrap failed: {e}")
            return None
    
    def wrap_dek_with_transit(self, dek: bytes, kms_config: dict) -> Dict[str, Any]:
        """
        Wrap (encrypt) the DEK using HashiCorp Vault Transit.
        """
        try:
            import hvac
            from app.core.security import decrypt_value
            
            vault_addr = kms_config.get('address')
            vault_token = kms_config.get('token')
            key_name = kms_config.get('key_name')
            mount_path = kms_config.get('mount_path', 'transit')
            
            if not all([vault_addr, vault_token, key_name]):
                return {"success": False, "error": "Missing Transit configuration"}
            
            if vault_token:
                try:
                    vault_token = decrypt_value(vault_token)
                except:
                    pass
            
            client = hvac.Client(url=vault_addr, token=vault_token)
            
            # Encrypt the DEK
            plaintext_b64 = base64.b64encode(dek).decode('utf-8')
            response = client.secrets.transit.encrypt_data(
                name=key_name,
                plaintext=plaintext_b64,
                mount_point=mount_path
            )
            
            return {
                "success": True,
                "wrapped_dek": response['data']['ciphertext'],
                "key_name": key_name,
                "provider": "transit",
                "wrapped_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Transit wrap failed: {e}")
            return {"success": False, "error": str(e)}
    
    def unwrap_dek_with_transit(self, wrapped_dek: str, kms_config: dict) -> Optional[bytes]:
        """
        Unwrap (decrypt) the DEK using HashiCorp Vault Transit.
        """
        try:
            import hvac
            from app.core.security import decrypt_value
            
            vault_addr = kms_config.get('address')
            vault_token = kms_config.get('token')
            key_name = kms_config.get('key_name')
            mount_path = kms_config.get('mount_path', 'transit')
            
            if not all([vault_addr, vault_token, key_name]):
                logger.error("Missing Transit configuration for unwrap")
                return None
            
            if vault_token:
                try:
                    vault_token = decrypt_value(vault_token)
                except:
                    pass
            
            client = hvac.Client(url=vault_addr, token=vault_token)
            
            response = client.secrets.transit.decrypt_data(
                name=key_name,
                ciphertext=wrapped_dek,
                mount_point=mount_path
            )
            
            return base64.b64decode(response['data']['plaintext'])
            
        except Exception as e:
            logger.error(f"Transit unwrap failed: {e}")
            return None
    
    def wrap_dek(self, dek: bytes, provider: str, kms_config: dict) -> Dict[str, Any]:
        """
        Wrap DEK with the specified provider.
        """
        if provider == "ocikms":
            return self.wrap_dek_with_oci_kms(dek, kms_config)
        elif provider == "gcpckms":
            return self.wrap_dek_with_gcp_kms(dek, kms_config)
        elif provider == "awskms":
            return self.wrap_dek_with_aws_kms(dek, kms_config)
        elif provider == "azurekeyvault":
            return self.wrap_dek_with_azure_keyvault(dek, kms_config)
        elif provider == "transit":
            return self.wrap_dek_with_transit(dek, kms_config)
        else:
            return {"success": False, "error": f"Unknown provider: {provider}"}
    
    def unwrap_dek(self, wrapped_dek: str, provider: str, kms_config: dict) -> Optional[bytes]:
        """
        Unwrap DEK with the specified provider.
        """
        if provider == "ocikms":
            return self.unwrap_dek_with_oci_kms(wrapped_dek, kms_config)
        elif provider == "gcpckms":
            return self.unwrap_dek_with_gcp_kms(wrapped_dek, kms_config)
        elif provider == "awskms":
            return self.unwrap_dek_with_aws_kms(wrapped_dek, kms_config)
        elif provider == "azurekeyvault":
            return self.unwrap_dek_with_azure_keyvault(wrapped_dek, kms_config)
        elif provider == "transit":
            return self.unwrap_dek_with_transit(wrapped_dek, kms_config)
        else:
            logger.error(f"Unknown provider for unwrap: {provider}")
            return None
    
    def store_encrypted_keys(
        self,
        db,
        unseal_keys: List[str],
        dek: bytes,
        wrap_results: Dict[str, Dict[str, Any]]
    ) -> bool:
        """
        Store encrypted unseal keys and wrapped DEKs in the database.
        
        Args:
            db: Database session
            unseal_keys: The Vault unseal keys
            dek: The Data Encryption Key
            wrap_results: Dict of provider -> wrap result
            
        Returns:
            True if successful
        """
        from app.models.system import SystemConfig
        
        try:
            # Encrypt unseal keys with DEK
            encrypted_keys = self.encrypt_unseal_keys(unseal_keys, dek)
            
            # Store encrypted keys
            config = db.query(SystemConfig).filter(
                SystemConfig.key == self.DB_KEY_ENCRYPTED_UNSEAL_KEYS
            ).first()
            
            encrypted_data = {
                "encrypted_keys": encrypted_keys,
                "key_count": len(unseal_keys),
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            if config:
                config.value = json.dumps(encrypted_data)
            else:
                config = SystemConfig(
                    key=self.DB_KEY_ENCRYPTED_UNSEAL_KEYS,
                    value=json.dumps(encrypted_data)
                )
                db.add(config)
            
            # Store wrapped DEKs for each provider
            for provider, result in wrap_results.items():
                if result.get("success"):
                    dek_key = f"{self.DB_KEY_WRAPPED_DEK_PREFIX}{provider}"
                    dek_config = db.query(SystemConfig).filter(
                        SystemConfig.key == dek_key
                    ).first()
                    
                    if dek_config:
                        dek_config.value = json.dumps(result)
                    else:
                        dek_config = SystemConfig(
                            key=dek_key,
                            value=json.dumps(result)
                        )
                        db.add(dek_config)
            
            db.commit()
            logger.info(f"Stored encrypted unseal keys with {len(wrap_results)} KMS providers")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store encrypted keys: {e}")
            db.rollback()
            return False
    
    def store_local_dek(self, db, dek: bytes) -> bool:
        """
        Store the DEK unencrypted in the database (for local/dev mode).
        
        WARNING: This is less secure - use only when no KMS is available.
        """
        from app.models.system import SystemConfig
        from app.core.security import encrypt_value
        
        try:
            # Encrypt with local Fernet key (better than plaintext)
            dek_b64 = base64.b64encode(dek).decode('utf-8')
            encrypted_dek = encrypt_value(dek_b64)
            
            config = db.query(SystemConfig).filter(
                SystemConfig.key == self.DB_KEY_LOCAL_DEK
            ).first()
            
            local_data = {
                "dek": encrypted_dek,
                "provider": "local",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            if config:
                config.value = json.dumps(local_data)
            else:
                config = SystemConfig(
                    key=self.DB_KEY_LOCAL_DEK,
                    value=json.dumps(local_data)
                )
                db.add(config)
            
            db.commit()
            logger.info("Stored DEK with local encryption")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store local DEK: {e}")
            db.rollback()
            return False
    
    def get_encrypted_keys(self, db) -> Optional[str]:
        """
        Get the encrypted unseal keys blob from database.
        """
        from app.models.system import SystemConfig
        
        config = db.query(SystemConfig).filter(
            SystemConfig.key == self.DB_KEY_ENCRYPTED_UNSEAL_KEYS
        ).first()
        
        if config:
            try:
                data = json.loads(config.value)
                return data.get("encrypted_keys")
            except:
                pass
        return None
    
    def get_wrapped_dek(self, db, provider: str) -> Optional[str]:
        """
        Get the wrapped DEK for a specific provider.
        """
        from app.models.system import SystemConfig
        
        dek_key = f"{self.DB_KEY_WRAPPED_DEK_PREFIX}{provider}"
        config = db.query(SystemConfig).filter(
            SystemConfig.key == dek_key
        ).first()
        
        if config:
            try:
                data = json.loads(config.value)
                return data.get("wrapped_dek")
            except:
                pass
        return None
    
    def get_wrapped_dek_record(self, db, provider: str) -> Optional[Dict[str, Any]]:
        """
        Get the full wrapped DEK record for a specific provider.
        This includes the wrapped DEK and the config used to wrap it.
        """
        from app.models.system import SystemConfig
        
        dek_key = f"{self.DB_KEY_WRAPPED_DEK_PREFIX}{provider}"
        config = db.query(SystemConfig).filter(
            SystemConfig.key == dek_key
        ).first()
        
        if config:
            try:
                return json.loads(config.value)
            except:
                pass
        return None
    
    def get_local_dek(self, db) -> Optional[bytes]:
        """
        Get the locally stored DEK.
        """
        from app.models.system import SystemConfig
        from app.core.security import decrypt_value
        
        config = db.query(SystemConfig).filter(
            SystemConfig.key == self.DB_KEY_LOCAL_DEK
        ).first()
        
        if config:
            try:
                data = json.loads(config.value)
                encrypted_dek = data.get("dek")
                if encrypted_dek:
                    dek_b64 = decrypt_value(encrypted_dek)
                    return base64.b64decode(dek_b64)
            except Exception as e:
                logger.error(f"Failed to get local DEK: {e}")
        return None
    
    def get_available_providers(self, db) -> List[str]:
        """
        Get list of providers that have wrapped DEKs stored.
        """
        from app.models.system import SystemConfig
        
        providers = []
        provider_list = ["ocikms", "gcpckms", "awskms", "azurekeyvault", "transit", "local"]
        
        for provider in provider_list:
            if provider == "local":
                config = db.query(SystemConfig).filter(
                    SystemConfig.key == self.DB_KEY_LOCAL_DEK
                ).first()
            else:
                config = db.query(SystemConfig).filter(
                    SystemConfig.key == f"{self.DB_KEY_WRAPPED_DEK_PREFIX}{provider}"
                ).first()
            
            if config:
                providers.append(provider)
        
        return providers
    
    def remove_provider_from_auto_unseal(self, db, provider: str) -> Tuple[bool, str]:
        """
        Remove a provider from auto-unseal by deleting its wrapped DEK.
        This does NOT delete the provider's configuration - only removes it from auto-unseal.
        
        Args:
            db: Database session
            provider: The provider to remove (e.g., 'ocikms', 'gcpckms', 'local')
            
        Returns:
            Tuple of (success, message)
        """
        from app.models.system import SystemConfig
        
        try:
            if provider == "local":
                dek_key = self.DB_KEY_LOCAL_DEK
            else:
                dek_key = f"{self.DB_KEY_WRAPPED_DEK_PREFIX}{provider}"
            
            config = db.query(SystemConfig).filter(SystemConfig.key == dek_key).first()
            
            if not config:
                return False, f"Provider '{provider}' is not configured for auto-unseal"
            
            db.delete(config)
            db.commit()
            
            logger.info(f"Removed provider '{provider}' from auto-unseal")
            return True, f"Successfully removed '{provider}' from auto-unseal"
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to remove provider '{provider}' from auto-unseal: {e}")
            return False, f"Failed to remove provider: {str(e)}"

    def retrieve_unseal_keys(
        self,
        db,
        provider: str,
        kms_config: dict = None
    ) -> Tuple[Optional[List[str]], Optional[str]]:
        """
        Retrieve and decrypt unseal keys using the specified provider.
        
        Args:
            db: Database session
            provider: KMS provider to use
            kms_config: Provider configuration (optional, will use stored config if not provided)
            
        Returns:
            Tuple of (unseal_keys, error_message)
        """
        # Get encrypted keys
        encrypted_keys = self.get_encrypted_keys(db)
        if not encrypted_keys:
            return None, "No encrypted unseal keys found in database"
        
        # Get and unwrap DEK
        if provider == "local":
            dek = self.get_local_dek(db)
            if not dek:
                return None, "Local DEK not found"
        else:
            # Get the wrapped DEK record which includes config
            dek_record = self.get_wrapped_dek_record(db, provider)
            if not dek_record:
                return None, f"Wrapped DEK not found for provider {provider}"
            
            wrapped_dek = dek_record.get("wrapped_dek")
            if not wrapped_dek:
                return None, f"No wrapped DEK in record for {provider}"
            
            # Use stored config from the DEK record, or override with provided config
            unwrap_config = {
                "key_id": dek_record.get("key_id"),
                "crypto_endpoint": dek_record.get("crypto_endpoint"),
                "key_name": dek_record.get("key_name"),
                "keyring": dek_record.get("keyring"),
                "project": dek_record.get("project"),
                "location": dek_record.get("location"),
                "vault_url": dek_record.get("vault_url"),
                "vault_addr": dek_record.get("vault_addr"),
                "vault_token": dek_record.get("vault_token"),
                "transit_key": dek_record.get("transit_key"),
                # OCI-specific
                "auth_config_encrypted": dek_record.get("auth_config_encrypted"),
                "use_instance_principal": dek_record.get("use_instance_principal"),
                # GCP-specific  
                "credentials_encrypted": dek_record.get("credentials_encrypted"),
                "key_ring": dek_record.get("key_ring"),
                "crypto_key": dek_record.get("crypto_key"),
            }
            # Override with provided config if any
            if kms_config:
                unwrap_config.update(kms_config)
            
            dek = self.unwrap_dek(wrapped_dek, provider, unwrap_config)
            if not dek:
                return None, f"Failed to unwrap DEK with {provider}"
        
        # Decrypt unseal keys
        try:
            unseal_keys = self.decrypt_unseal_keys(encrypted_keys, dek)
            return unseal_keys, None
        except Exception as e:
            return None, f"Failed to decrypt unseal keys: {e}"
    
    def auto_unseal_vault(self, db) -> Dict[str, Any]:
        """
        Automatically unseal Vault using stored keys.
        Tries providers in priority order: cloud KMS providers first, then local.
        
        Args:
            db: Database session
            
        Returns:
            Dict with success status and details
        """
        import requests
        
        # Check if Vault is already unsealed
        vault_url = os.environ.get("VAULT_ADDR", "http://vault:8200")
        try:
            status_resp = requests.get(f"{vault_url}/v1/sys/seal-status", timeout=5)
            if status_resp.status_code == 200:
                status = status_resp.json()
                if not status.get("sealed", True):
                    return {
                        "success": True,
                        "message": "Vault is already unsealed",
                        "sealed": False
                    }
                threshold = status.get("t", 3)
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to check Vault status: {e}"
            }
        
        # Get available providers
        providers = self.get_available_providers(db)
        if not providers:
            return {
                "success": False,
                "error": "No KMS providers available for auto-unseal"
            }
        
        # Get priority order from database
        from app.models.system import SystemConfig
        priority_config = db.query(SystemConfig).filter(SystemConfig.key == "unseal_priority").first()
        if priority_config:
            try:
                db_priority = json.loads(priority_config.value)
                # Map UI names to provider names (local_file -> local for our purposes)
                priority_order = []
                for method in db_priority:
                    if method == "local_file":
                        priority_order.append("local")
                    elif method in ["ocikms", "gcpckms", "awskms", "azurekeyvault", "transit", "local"]:
                        priority_order.append(method)
                # Ensure all available providers are in the list
                for p in providers:
                    if p not in priority_order:
                        priority_order.append(p)
            except:
                priority_order = ["ocikms", "gcpckms", "awskms", "azurekeyvault", "transit", "local"]
        else:
            priority_order = ["ocikms", "gcpckms", "awskms", "azurekeyvault", "transit", "local"]
        
        # Sort available providers by priority
        sorted_providers = sorted(providers, key=lambda p: priority_order.index(p) if p in priority_order else 100)
        
        logger.info(f"Auto-unseal priority order: {priority_order}")
        logger.info(f"Available providers: {providers}")
        logger.info(f"Sorted providers to try: {sorted_providers}")
        
        # Try each provider
        last_error = None
        for provider in sorted_providers:
            logger.info(f"Attempting auto-unseal with provider: {provider}")
            
            keys, error = self.retrieve_unseal_keys(db, provider)
            if error:
                logger.warning(f"Failed to retrieve keys with {provider}: {error}")
                last_error = error
                continue
            
            if not keys:
                logger.warning(f"No keys retrieved from {provider}")
                last_error = "No keys retrieved"
                continue
            
            # Try to unseal with retrieved keys
            try:
                unseal_count = 0
                for key in keys[:threshold]:
                    unseal_resp = requests.put(
                        f"{vault_url}/v1/sys/unseal",
                        json={"key": key},
                        timeout=10
                    )
                    if unseal_resp.status_code == 200:
                        result = unseal_resp.json()
                        unseal_count += 1
                        if not result.get("sealed", True):
                            return {
                                "success": True,
                                "message": f"Vault unsealed successfully using {provider}",
                                "provider": provider,
                                "keys_used": unseal_count,
                                "sealed": False
                            }
                    else:
                        logger.error(f"Unseal request failed: {unseal_resp.status_code}")
                        break
                
                # Check final status
                status_resp = requests.get(f"{vault_url}/v1/sys/seal-status", timeout=5)
                if status_resp.status_code == 200:
                    status = status_resp.json()
                    if not status.get("sealed", True):
                        return {
                            "success": True,
                            "message": f"Vault unsealed successfully using {provider}",
                            "provider": provider,
                            "keys_used": unseal_count,
                            "sealed": False
                        }
                    else:
                        last_error = f"Vault still sealed after {unseal_count} keys"
                        
            except Exception as e:
                logger.error(f"Error during unseal with {provider}: {e}")
                last_error = str(e)
                continue
        
        return {
            "success": False,
            "error": f"All providers failed. Last error: {last_error}",
            "providers_tried": sorted_providers
        }


# Singleton instance
auto_unseal_manager = AutoUnsealKeyManager()
