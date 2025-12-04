from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, BackgroundTasks, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import text
from enum import Enum
import httpx
import structlog
import os
import time
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.auth import require_admin
from app.core.rate_limit import limiter, RATE_LIMITS
from app.services.certificate_service import CertificateService
from app.services.ca_service import ca_service
from app.models.certificate import CertificateType
from app.core.vault import vault_client
from app.models.system import SystemConfig
from app.core.security import encrypt_value
from app.core.config import settings
from app.services.backup_service import BackupService

from app.models.certificate import Certificate, CertificateStatus
from app.models.ca import CertificateAuthority
from app.models.monitoring import MonitoringService
from app.models.user import User
# from app.models.alert import Alert
from cryptography.hazmat.primitives import serialization
from packaging import version

logger = structlog.get_logger(__name__)

router = APIRouter()

class SystemCertRequest(BaseModel):
    common_name: str
    subject_alt_names: Optional[str] = None
    auto_restart: bool = False

@router.get("/certificate", response_model=SystemCertRequest)
def get_system_certificate(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Get the current system certificate details (Common Name and SANs).
    Returns the details of the most recently issued system certificate.
    """
    # Find the latest certificate with the specific note
    cert = db.query(Certificate).filter(
        Certificate.notes == "System Certificate for PKI Management Interface",
        Certificate.status == CertificateStatus.ACTIVE
    ).order_by(Certificate.created_at.desc()).first()
    
    if not cert:
        # Return empty defaults - frontend will handle defaults
        return SystemCertRequest(
            common_name="",
            subject_alt_names="",
            auto_restart=False
        )
        
    # Format SANs
    sans = ""
    san_list = cert.get_subject_alt_names_list()
    if san_list:
        sans = ", ".join(san_list)
        
    return SystemCertRequest(
        common_name=cert.common_name,
        subject_alt_names=sans,
        auto_restart=False
    )


def is_docker_available() -> bool:
    """Check if Docker socket is available for container management."""
    try:
        import docker
        try:
            client = docker.from_env()
            client.ping()
            return True
        except:
            client = docker.DockerClient(base_url='unix://var/run/docker.sock')
            client.ping()
            return True
    except:
        return False


def get_docker_client():
    """Get a Docker client, trying multiple methods."""
    import docker
    try:
        client = docker.from_env()
        client.ping()
        return client
    except Exception as e:
        logger.warning(f"docker.from_env() failed: {e}. Trying explicit socket.")
        client = docker.DockerClient(base_url='unix://var/run/docker.sock')
        return client


def restart_container(container_name: str, wait_before: int = 2):
    """
    Restart a container by name.
    
    Args:
        container_name: Name of the container to restart
        wait_before: Seconds to wait before restarting (to allow API response)
    """
    try:
        if wait_before > 0:
            time.sleep(wait_before)
        
        client = get_docker_client()
        container = client.containers.get(container_name)
        container.restart()
        logger.info(f"Container {container_name} restarted successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to restart container {container_name}", error=str(e))
        return False


def restart_nginx_container():
    """
    Restart the Nginx container in the background.
    Waits a few seconds to allow the API response to be sent.
    """
    try:
        # Wait for response to flush
        time.sleep(2)
        
        import docker
        # Connect to Docker socket
        try:
            client = docker.from_env()
            client.ping()
        except Exception as e:
            logger.warning(f"docker.from_env() failed: {e}. Trying explicit socket.")
            client = docker.DockerClient(base_url='unix://var/run/docker.sock')
        
        # Find and restart Nginx container
        container = client.containers.get('pki_nginx')
        container.restart()
        logger.info("Nginx container restarted successfully")
    except Exception as e:
        logger.error("Failed to restart Nginx container", error=str(e))

@router.post("/certificate", status_code=status.HTTP_200_OK)
def update_system_certificate(
    cert_data: SystemCertRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Issue a new certificate for the PKI system itself (Nginx).
    This will overwrite the existing /etc/nginx/ssl/server.crt and server.key.
    Requires Admin privileges.
    """
    logger.info("Updating system certificate", **cert_data.dict())
    
    cert_service = CertificateService()
    
    # Get active CA to determine max validity
    active_ca = ca_service.get_active_issuing_ca(db)
    if not active_ca:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active Certificate Authority found to issue system certificate"
        )
        
    # Calculate max validity days
    # Ensure we don't exceed CA expiration
    now = datetime.now(timezone.utc)
    if active_ca.not_valid_after.tzinfo is None:
        # Handle naive datetime if necessary (though model should be aware)
        ca_expiry = active_ca.not_valid_after.replace(tzinfo=timezone.utc)
    else:
        ca_expiry = active_ca.not_valid_after
        
    days_until_expiry = (ca_expiry - now).days
    
    # Use max available days, minus 1 for safety buffer
    validity_days = max(1, days_until_expiry - 1)
    
    # Prepare SANs
    san_list = []
    if cert_data.subject_alt_names:
        # Split by comma and strip whitespace
        san_list = [s.strip() for s in cert_data.subject_alt_names.split(",") if s.strip()]
    
    # Find existing active certificates with the same Common Name to revoke them later
    existing_certs = cert_service.list_certificates(
        db=db,
        search=cert_data.common_name,
        status=CertificateStatus.ACTIVE,
        certificate_type=CertificateType.SERVER
    )
    # Filter strictly by exact Common Name match to avoid partial matches
    existing_certs = [c for c in existing_certs if c.common_name == cert_data.common_name]

    # Issue certificate
    try:
        cert = cert_service.issue_certificate(
            db=db,
            common_name=cert_data.common_name,
            subject_alt_names=san_list,
            certificate_type=CertificateType.SERVER,
            validity_days=validity_days,
            notes="System Certificate for PKI Management Interface",
            created_by_user_id=current_user.id
        )
        
        # Revoke previous certificates
        for old_cert in existing_certs:
            try:
                # Ensure we don't revoke the one we just created (though IDs should differ)
                if old_cert.id != cert.id:
                    cert_service.revoke_certificate(
                        db=db,
                        certificate_id=old_cert.id,
                        reason="Replaced by new System Certificate",
                        created_by_user_id=current_user.id
                    )
                    logger.info(f"Revoked previous system certificate: {old_cert.id}")
            except Exception as e:
                logger.warning(f"Failed to revoke old certificate {old_cert.id}: {e}")

        # Retrieve the private key from Vault
        # The Certificate model stores the path to the private key in Vault
        # We need to handle the case where the key might not be immediately available or path is slightly different
        # But issue_certificate should have stored it.
        
        # Debug log
        logger.info(f"Retrieving private key from path: {cert.pem_private_key_vault_path}")
        
        private_key_obj = vault_client.retrieve_private_key(cert.pem_private_key_vault_path)
        
        if not private_key_obj:
            # Fallback: Try to list keys in that directory to see if we have a mismatch
            try:
                keys = vault_client.list_stored_keys("certificates")
                logger.warning(f"Key not found. Available keys in certificates/: {keys}")
            except:
                pass
                
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve generated private key from {cert.pem_private_key_vault_path}"
            )
            
        # Serialize private key to PEM bytes
        private_key_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
            
        # Write to Nginx SSL directory
        # We assume the volume is mounted at /etc/nginx/ssl inside the container
        ssl_dir = "/etc/nginx/ssl"
        
        # Ensure directory exists (it should be mounted)
        if not os.path.exists(ssl_dir):
            os.makedirs(ssl_dir, exist_ok=True)
        
        # Write files
        crt_path = os.path.join(ssl_dir, "server.crt")
        key_path = os.path.join(ssl_dir, "server.key")
        
        # Build full chain (Leaf + Intermediate + Root)
        full_chain = cert.pem_certificate
        if cert.issuer_ca:
            chain_pem = ca_service.build_certificate_chain(cert.issuer_ca)
            if chain_pem:
                full_chain = f"{cert.pem_certificate.strip()}\n{chain_pem.strip()}\n"

        with open(crt_path, "w") as f:
            f.write(full_chain)
            
        with open(key_path, "wb") as f:
            f.write(private_key_pem)
            
        logger.info("System certificate updated successfully", crt_path=crt_path)
        
        message = "System certificate updated successfully."
        
        if cert_data.auto_restart:
            background_tasks.add_task(restart_nginx_container)
            message += " Nginx container will restart in a few seconds."
        else:
            message += " Please restart the application/Nginx to apply changes."

        return {
            "message": message,
            "certificate_id": cert.id,
            "common_name": cert.common_name
        }
        
    except Exception as e:
        logger.error("Failed to update system certificate", error=str(e), error_type=type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update system certificate. Check server logs for details."
        )

class SystemHealthResponse(BaseModel):
    database_connected: bool
    vault_connected: bool
    vault_initialized: bool
    vault_sealed: bool
    total_certificates: int
    total_cas: int
    missing_keys: List[str] = []
    orphaned_keys: List[str] = []

@router.get("/health", response_model=SystemHealthResponse)
@limiter.limit(RATE_LIMITS["health"])
def check_system_health(
    request: Request,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Perform a system health check, verifying Database and Vault connectivity,
    and checking for data integrity (missing keys and orphaned keys).
    Rate limited to prevent abuse.
    """
    health = SystemHealthResponse(
        database_connected=True,
        vault_connected=False,
        vault_initialized=False,
        vault_sealed=True,
        total_certificates=0,
        total_cas=0,
        missing_keys=[],
        orphaned_keys=[]
    )
    
    # Check Vault Status
    try:
        vault_status = vault_client.get_vault_status()
        health.vault_connected = vault_status.get('authenticated', False)
        health.vault_initialized = vault_status.get('initialized', False)
        health.vault_sealed = vault_status.get('sealed', True)
    except Exception as e:
        logger.error("Health check failed to contact Vault", error=str(e))
    
    if not health.vault_connected:
        return health

    # Check Integrity
    from app.models.certificate import Certificate
    from app.models.ca import CertificateAuthority
    
    expected_paths = set()

    # Check CAs
    cas = db.query(CertificateAuthority).all()
    health.total_cas = len(cas)
    for ca in cas:
        if ca.private_key_vault_path:
            expected_paths.add(ca.private_key_vault_path)
            # We use a lightweight check if possible, but retrieve_private_key is safe enough for now
            # Ideally we'd have a 'has_key' method to avoid transferring the key
            key = vault_client.retrieve_private_key(ca.private_key_vault_path)
            if not key:
                health.missing_keys.append(f"CA: {ca.common_name} (ID: {ca.id})")
    
    # Check Certificates
    certs = db.query(Certificate).all()
    health.total_certificates = len(certs)
    for cert in certs:
        if cert.pem_private_key_vault_path:
            expected_paths.add(cert.pem_private_key_vault_path)
            
            # Skip key check for revoked certificates as their keys might have been deleted (legacy behavior)
            # or we just don't care as much about health of revoked certs
            if cert.status == CertificateStatus.REVOKED:
                continue

            key = vault_client.retrieve_private_key(cert.pem_private_key_vault_path)
            if not key:
                health.missing_keys.append(f"Cert: {cert.common_name} (ID: {cert.id})")
    
    # Check for Orphaned Keys (Keys in Vault but not in DB)
    try:
        # Check 'certificates/' folder
        cert_keys = vault_client.list_stored_keys("certificates")
        for key in cert_keys:
            # Skip directory markers if any
            if key.endswith('/'): continue
            
            full_path = f"certificates/{key}"
            if full_path not in expected_paths:
                health.orphaned_keys.append(full_path)
                
        # Check 'cas/' folder
        ca_keys = vault_client.list_stored_keys("cas")
        for key in ca_keys:
            if key.endswith('/'): continue
            
            full_path = f"cas/{key}"
            if full_path not in expected_paths:
                health.orphaned_keys.append(full_path)
                
    except Exception as e:
        logger.error("Failed to scan for orphaned keys", error=str(e))
                
    return health


class VaultConfigRequest(BaseModel):
    vault_token: str

class SystemConfigResponse(BaseModel):
    vault_configured: bool
    vault_configured_via_env: bool
    docker_available: bool

@router.get("/config", response_model=SystemConfigResponse)
def get_system_config(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Get system configuration status.
    """
    env_token = settings.VAULT_TOKEN
    
    db_config = db.query(SystemConfig).filter(SystemConfig.key == "vault_token").first()
    db_configured = db_config is not None and db_config.value is not None
    
    # Check Docker availability
    docker_available = False
    try:
        import docker
        try:
            client = docker.from_env()
            client.ping()
            docker_available = True
        except:
            try:
                client = docker.DockerClient(base_url='unix://var/run/docker.sock')
                client.ping()
                docker_available = True
            except:
                pass
    except ImportError:
        pass

    return SystemConfigResponse(
        vault_configured=bool(env_token) or db_configured,
        vault_configured_via_env=bool(env_token),
        docker_available=docker_available
    )

@router.post("/config/vault", status_code=status.HTTP_200_OK)
def configure_vault(
    config: VaultConfigRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Configure Vault token in the database.
    """
    if settings.VAULT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vault is already configured via environment variables. Cannot override."
        )
        
    encrypted_token = encrypt_value(config.vault_token)
    
    db_config = db.query(SystemConfig).filter(SystemConfig.key == "vault_token").first()
    if not db_config:
        db_config = SystemConfig(key="vault_token", value=encrypted_token, description="Vault Access Token")
        db.add(db_config)
    else:
        db_config.value = encrypted_token
        
    db.commit()
    
    # Try to connect immediately
    vault_client.connect()
    
    if not vault_client.is_authenticated():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token saved, but failed to authenticate with Vault. Please check the token."
        )
        
    return {"message": "Vault configuration saved and connected successfully"}

class UnsealRequest(BaseModel):
    keys: List[str]

@router.post("/config/vault/unseal", status_code=status.HTTP_200_OK)
def unseal_vault(
    request: UnsealRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Unseal Vault using provided keys.
    """
    try:
        result = vault_client.unseal_vault(request.keys)
        if result.get('sealed') is True:
             raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Vault remained sealed. Please check your keys or provide more keys."
            )
        
        # Force client reconnect/auth check
        vault_client.connect()
        
        return {"message": "Vault unsealed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to unseal Vault", error=str(e), error_type=type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unseal Vault. Check server logs for details."
        )


class AutoUnsealStatusResponse(BaseModel):
    available: bool
    method: Optional[str] = None  # 'vault_keys_json' or 'kms' (future)
    message: str


@router.get("/config/vault/auto-unseal-status", response_model=AutoUnsealStatusResponse)
def get_auto_unseal_status(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Check if auto-unseal is available.
    Returns whether vault_keys.json exists or KMS is configured.
    Priority: vault_keys.json > KMS configuration
    """
    import json
    from pathlib import Path
    from app.core.security import decrypt_value
    
    # Check for vault_keys.json FIRST (local file takes priority when it exists)
    # Primary path is the mounted volume /app/vault_data/
    vault_keys_paths = [
        Path("/app/vault_data/vault_keys.json"),
        Path("/app/data/vault/vault_keys.json"),
        Path("/app/data/vault_keys.json"),
        Path("data/vault/vault_keys.json"),
        Path("data/vault_keys.json")
    ]
    
    for vault_keys_path in vault_keys_paths:
        if vault_keys_path.exists():
            try:
                with open(vault_keys_path, 'r') as f:
                    keys_data = json.load(f)
                keys = keys_data.get('keys', []) or keys_data.get('unseal_keys', [])
                if keys and len(keys) > 0:
                    return AutoUnsealStatusResponse(
                        available=True,
                        method="vault_keys_json",
                        message=f"Local auto-unseal ({len(keys)} keys in vault_keys.json)"
                    )
            except Exception as e:
                logger.warning("Failed to read vault_keys.json", error=str(e))
    
    # Check for KMS configuration in database (fallback)
    kms_config = db.query(SystemConfig).filter(SystemConfig.key == "vault_seal_config").first()
    if kms_config:
        try:
            decrypted = decrypt_value(kms_config.value)
            config = json.loads(decrypted)
            if config.get('enabled') and config.get('provider') != 'shamir':
                provider = config.get('provider', 'kms')
                provider_names = {
                    'transit': 'Self-Hosted Transit',
                    'awskms': 'AWS KMS',
                    'gcpckms': 'Google Cloud KMS',
                    'azurekeyvault': 'Azure Key Vault',
                    'ocikms': 'Oracle OCI KMS',
                    'alicloudkms': 'AliCloud KMS'
                }
                return AutoUnsealStatusResponse(
                    available=True,
                    method=provider,
                    message=f"{provider_names.get(provider, provider)} auto-unseal configured"
                )
        except Exception as e:
            logger.warning("Failed to read KMS config from DB", error=str(e))
    
    return AutoUnsealStatusResponse(
        available=False,
        method=None,
        message="No auto-unseal method available. Place vault_keys.json in the data directory or configure KMS."
    )


@router.post("/config/vault/auto-unseal", status_code=status.HTTP_200_OK)
def auto_unseal_vault(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Automatically unseal Vault using available methods.
    Tries vault_keys.json first, then KMS if configured.
    
    WARNING: This feature is for convenience in dev/test environments.
    For production, consider using proper KMS-based auto-unseal.
    """
    import json
    from pathlib import Path
    
    # Check for vault_keys.json in multiple paths
    vault_keys_paths = [
        Path("/app/vault_data/vault_keys.json"),
        Path("/app/data/vault/vault_keys.json"),
        Path("/app/data/vault_keys.json"),
        Path("data/vault/vault_keys.json"),
        Path("data/vault_keys.json")
    ]
    
    vault_keys_path = None
    for path in vault_keys_paths:
        if path.exists():
            vault_keys_path = path
            break
    
    if vault_keys_path:
        try:
            with open(vault_keys_path, 'r') as f:
                keys_data = json.load(f)
            
            keys = keys_data.get('keys', [])
            if not keys:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="vault_keys.json exists but contains no unseal keys"
                )
            
            # Attempt to unseal with the keys
            result = vault_client.unseal_vault(keys)
            
            if result.get('sealed') is True:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Vault remained sealed. The keys in vault_keys.json may be incorrect or insufficient."
                )
            
            # Force client reconnect/auth check
            vault_client.connect()
            
            logger.info("Vault auto-unsealed successfully using vault_keys.json")
            return {"message": "Vault unsealed successfully using vault_keys.json", "method": "vault_keys_json"}
            
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="vault_keys.json is not valid JSON"
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Auto-unseal failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Auto-unseal failed: {str(e)}"
            )
    
    # Future: Try KMS auto-unseal
    # kms_config = db.query(SystemConfig).filter(SystemConfig.key == "vault_kms_config").first()
    # if kms_config:
    #     ... implement KMS unseal ...
    
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="No auto-unseal method available. Place vault_keys.json in the data directory."
    )


class CreateVaultKeysFileRequest(BaseModel):
    """Request to create vault_keys.json for local auto-unseal"""
    keys: List[str]  # The unseal keys (base64 or hex encoded)


class VaultKeysFileStatusResponse(BaseModel):
    """Response for vault_keys.json status"""
    exists: bool
    key_count: int = 0
    message: str


@router.get("/config/vault/keys-file-status", response_model=VaultKeysFileStatusResponse)
def get_vault_keys_file_status(
    current_user = Depends(require_admin)
):
    """
    Check if vault_keys.json exists and is valid.
    """
    import json
    from pathlib import Path
    
    # Check multiple paths for vault_keys.json
    vault_keys_paths = [
        Path("/app/vault_data/vault_keys.json"),
        Path("/app/data/vault/vault_keys.json"),
        Path("/app/data/vault_keys.json"),
        Path("data/vault/vault_keys.json"),
        Path("data/vault_keys.json")
    ]
    
    vault_keys_path = None
    for path in vault_keys_paths:
        if path.exists():
            vault_keys_path = path
            break
    
    if not vault_keys_path:
        return VaultKeysFileStatusResponse(
            exists=False,
            key_count=0,
            message="vault_keys.json does not exist. Create it to enable local auto-unseal."
        )
    
    try:
        with open(vault_keys_path, 'r') as f:
            keys_data = json.load(f)
        
        keys = keys_data.get('keys', [])
        if not keys:
            return VaultKeysFileStatusResponse(
                exists=True,
                key_count=0,
                message="vault_keys.json exists but contains no keys."
            )
        
        return VaultKeysFileStatusResponse(
            exists=True,
            key_count=len(keys),
            message=f"vault_keys.json contains {len(keys)} unseal keys."
        )
    except json.JSONDecodeError:
        return VaultKeysFileStatusResponse(
            exists=True,
            key_count=0,
            message="vault_keys.json exists but is not valid JSON."
        )
    except Exception as e:
        return VaultKeysFileStatusResponse(
            exists=True,
            key_count=0,
            message=f"Error reading vault_keys.json: {str(e)}"
        )


@router.post("/config/vault/keys-file", status_code=status.HTTP_201_CREATED)
def create_vault_keys_file(
    request: CreateVaultKeysFileRequest,
    current_user = Depends(require_admin)
):
    """
    Create vault_keys.json for local auto-unseal.
    
    This stores the unseal keys in a JSON file for automatic unsealing.
    
    WARNING: This stores sensitive cryptographic keys on disk.
    Only use in dev/test environments or isolated home labs with physical security.
    For production, use KMS-based auto-unseal.
    """
    import json
    from pathlib import Path
    
    if not request.keys or len(request.keys) < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one unseal key is required"
        )
    
    # Validate keys look reasonable (base64 or hex)
    for i, key in enumerate(request.keys):
        if not key or len(key) < 20:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Key {i+1} appears to be invalid or too short"
            )
    
    # Use mounted volume path for persistence
    vault_keys_path = Path("/app/vault_data/vault_keys.json")
    
    # Ensure directory exists
    vault_keys_path.parent.mkdir(parents=True, exist_ok=True)
    
    keys_data = {
        "keys": request.keys,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": "scr-pki-web-ui"
    }
    
    try:
        with open(vault_keys_path, 'w') as f:
            json.dump(keys_data, f, indent=2)
        
        # Set restrictive permissions (600)
        os.chmod(vault_keys_path, 0o600)
        
        logger.info("Created vault_keys.json for local auto-unseal", key_count=len(request.keys))
        
        return {
            "message": f"vault_keys.json created with {len(request.keys)} keys",
            "key_count": len(request.keys),
            "warning": "This file contains sensitive cryptographic keys. Only use in dev/test environments."
        }
    except Exception as e:
        logger.error("Failed to create vault_keys.json", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create vault_keys.json: {str(e)}"
        )


@router.delete("/config/vault/keys-file", status_code=status.HTTP_200_OK)
def delete_vault_keys_file(
    current_user = Depends(require_admin)
):
    """
    Delete vault_keys.json to disable local auto-unseal.
    """
    from pathlib import Path
    
    # Check multiple paths
    vault_keys_paths = [
        Path("/app/vault_data/vault_keys.json"),
        Path("/app/data/vault/vault_keys.json"),
        Path("/app/data/vault_keys.json"),
        Path("data/vault/vault_keys.json"),
        Path("data/vault_keys.json")
    ]
    
    deleted = False
    for vault_keys_path in vault_keys_paths:
        if vault_keys_path.exists():
            try:
                vault_keys_path.unlink()
                logger.info("Deleted vault_keys.json", path=str(vault_keys_path))
                deleted = True
            except Exception as e:
                logger.error("Failed to delete vault_keys.json", path=str(vault_keys_path), error=str(e))
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="vault_keys.json does not exist"
        )
    
    return {"message": "vault_keys.json deleted. Local auto-unseal is now disabled."}


# =============================================================================
# Unseal Priority Configuration
# =============================================================================

class UnsealMethodStatus(BaseModel):
    """Status of a single unseal method"""
    method: str
    configured: bool
    enabled: bool
    priority: int
    last_used: Optional[str] = None
    last_status: Optional[str] = None  # "success", "failed", "unavailable"
    details: Optional[str] = None


class UnsealPriorityResponse(BaseModel):
    """Response with all configured unseal methods and their priority"""
    methods: List[UnsealMethodStatus]
    active_method: Optional[str] = None  # Currently used method


class UnsealPriorityRequest(BaseModel):
    """Request to update unseal priority order"""
    priority: List[str]  # Ordered list of method names


@router.get("/config/vault/unseal-priority", response_model=UnsealPriorityResponse)
def get_unseal_priority(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Get all configured unseal methods with their priority order.
    
    Methods are returned in priority order (first = highest priority).
    The system will try each method in order until one succeeds.
    """
    import json
    from pathlib import Path
    from app.core.security import decrypt_value
    
    methods = []
    
    # Check local keys file
    vault_keys_paths = [
        Path("/app/vault_data/vault_keys.json"),
        Path("/app/data/vault/vault_keys.json"),
        Path("/app/data/vault_keys.json"),
    ]
    
    local_file_configured = False
    local_file_key_count = 0
    for path in vault_keys_paths:
        if path.exists():
            try:
                with open(path, 'r') as f:
                    keys_data = json.load(f)
                keys = keys_data.get('keys', []) or keys_data.get('unseal_keys', [])
                if keys:
                    local_file_configured = True
                    local_file_key_count = len(keys)
                    break
            except:
                pass
    
    # Get priority order from database (or use default)
    priority_config = db.query(SystemConfig).filter(SystemConfig.key == "unseal_priority").first()
    if priority_config:
        try:
            priority_order = json.loads(priority_config.value)
        except:
            priority_order = ["local_file", "transit", "awskms", "gcpckms", "azurekeyvault", "ocikms", "alicloudkms"]
    else:
        priority_order = ["local_file", "transit", "awskms", "gcpckms", "azurekeyvault", "ocikms", "alicloudkms"]
    
    # Get all KMS configurations from database
    kms_configs = {}
    seal_config = db.query(SystemConfig).filter(SystemConfig.key == "vault_seal_config").first()
    if seal_config:
        try:
            decrypted = decrypt_value(seal_config.value)
            config = json.loads(decrypted)
            if config.get('provider') and config.get('provider') != 'shamir':
                kms_configs[config['provider']] = config
        except:
            pass
    
    # Also check for individual provider configs (for multiple KMS support)
    for provider in ["transit", "awskms", "gcpckms", "azurekeyvault", "ocikms", "alicloudkms"]:
        provider_config = db.query(SystemConfig).filter(
            SystemConfig.key == f"vault_seal_{provider}"
        ).first()
        if provider_config:
            try:
                decrypted = decrypt_value(provider_config.value)
                config = json.loads(decrypted)
                kms_configs[provider] = config
            except:
                pass
    
    # Build method list in priority order
    active_method = None
    
    # Add local file first if configured
    if "local_file" in priority_order:
        priority = priority_order.index("local_file")
    else:
        priority = 999
    
    methods.append(UnsealMethodStatus(
        method="local_file",
        configured=local_file_configured,
        enabled=local_file_configured,
        priority=priority,
        details=f"{local_file_key_count} keys stored" if local_file_configured else "Not configured"
    ))
    
    if local_file_configured and active_method is None:
        active_method = "local_file"
    
    # Add KMS providers
    provider_names = {
        'transit': 'Self-Hosted Transit',
        'awskms': 'AWS KMS',
        'gcpckms': 'Google Cloud KMS',
        'azurekeyvault': 'Azure Key Vault',
        'ocikms': 'Oracle OCI KMS',
        'alicloudkms': 'AliCloud KMS'
    }
    
    for provider, name in provider_names.items():
        if provider in priority_order:
            priority = priority_order.index(provider)
        else:
            priority = 999
        
        configured = provider in kms_configs
        enabled = configured and kms_configs.get(provider, {}).get('enabled', False)
        
        methods.append(UnsealMethodStatus(
            method=provider,
            configured=configured,
            enabled=enabled,
            priority=priority,
            details=name if configured else f"{name} - Not configured"
        ))
        
        if enabled and active_method is None:
            active_method = provider
    
    # Add Shamir (manual unseal) as always-available fallback
    methods.append(UnsealMethodStatus(
        method="shamir",
        configured=True,  # Always available
        enabled=True,     # Always enabled as fallback
        priority=998,     # Near the end
        details="Manual Unseal - Use 3 of 5 Shamir keys"
    ))
    
    # Sort by priority
    methods.sort(key=lambda m: m.priority)
    
    return UnsealPriorityResponse(
        methods=methods,
        active_method=active_method
    )


@router.post("/config/vault/unseal-priority", status_code=status.HTTP_200_OK)
def update_unseal_priority(
    request: UnsealPriorityRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Update the priority order for unseal methods.
    
    Methods will be tried in the order specified until one succeeds.
    """
    import json
    
    valid_methods = ["local_file", "transit", "awskms", "gcpckms", "azurekeyvault", "ocikms", "alicloudkms", "shamir"]
    
    # Validate all methods are valid
    for method in request.priority:
        if method not in valid_methods:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid method: {method}. Valid methods: {valid_methods}"
            )
    
    # Save to database
    config = db.query(SystemConfig).filter(SystemConfig.key == "unseal_priority").first()
    if config:
        config.value = json.dumps(request.priority)
    else:
        config = SystemConfig(key="unseal_priority", value=json.dumps(request.priority))
        db.add(config)
    
    db.commit()
    
    return {"message": "Unseal priority updated", "priority": request.priority}


# =============================================================================
# Key Replication (Copy Unseal Keys to KMS Provider for Redundancy)
# =============================================================================

class KeyReplicationSource(str, Enum):
    LOCAL_FILE = "local_file"  # vault_keys.json
    MANUAL = "manual"  # User provides keys directly
    SHAMIR = "shamir"  # Same as manual, user provides Shamir keys


class KeyReplicationRequest(BaseModel):
    """Request to replicate unseal keys to a KMS provider"""
    source: KeyReplicationSource
    source_keys: Optional[List[str]] = None  # Required if source is manual/shamir
    destination: str  # awskms, gcpckms, azurekeyvault, ocikms, alicloudkms, transit
    secret_name: Optional[str] = "vault-unseal-keys"  # Name/path for the stored secret


class KeyReplicationResponse(BaseModel):
    """Response from key replication"""
    success: bool
    message: str
    keys_replicated: int = 0
    destination: str
    secret_identifier: Optional[str] = None  # ARN, key path, etc.


@router.post("/config/vault/replicate-keys", response_model=KeyReplicationResponse)
def replicate_unseal_keys(
    request: KeyReplicationRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Replicate Vault unseal keys to a KMS provider for redundancy.
    
    This allows you to:
    1. Backup your Shamir keys to cloud KMS (encrypted at rest)
    2. Create redundancy across multiple KMS providers
    3. Enable disaster recovery scenarios
    
    The keys are stored encrypted using the destination provider's encryption.
    """
    import json
    from pathlib import Path
    from app.core.security import decrypt_value
    
    logger.info("Key replication requested", 
                source=request.source, 
                destination=request.destination)
    
    # Step 1: Get the source keys
    unseal_keys = []
    
    if request.source == KeyReplicationSource.LOCAL_FILE:
        # Read from vault_keys.json
        vault_keys_paths = [
            Path("/app/vault_data/vault_keys.json"),
            Path("/app/data/vault/vault_keys.json"),
            Path("/app/data/vault_keys.json"),
            Path("data/vault/vault_keys.json"),
        ]
        
        for path in vault_keys_paths:
            if path.exists():
                try:
                    with open(path, 'r') as f:
                        keys_data = json.load(f)
                    unseal_keys = keys_data.get('keys', []) or keys_data.get('unseal_keys', [])
                    if unseal_keys:
                        logger.info(f"Found {len(unseal_keys)} keys in {path}")
                        break
                except Exception as e:
                    logger.warning(f"Failed to read {path}: {e}")
        
        if not unseal_keys:
            return KeyReplicationResponse(
                success=False,
                message="No vault_keys.json found or it contains no keys",
                destination=request.destination
            )
    
    elif request.source in [KeyReplicationSource.MANUAL, KeyReplicationSource.SHAMIR]:
        if not request.source_keys or len(request.source_keys) == 0:
            return KeyReplicationResponse(
                success=False,
                message="No source keys provided. Please provide the Shamir unseal keys.",
                destination=request.destination
            )
        unseal_keys = request.source_keys
    
    else:
        return KeyReplicationResponse(
            success=False,
            message=f"Unknown source: {request.source}",
            destination=request.destination
        )
    
    # Step 2: Get the destination KMS configuration
    # Try both naming conventions: vault_seal_{provider} and seal_{provider}
    config_key = f"vault_seal_{request.destination}"
    config = db.query(SystemConfig).filter(SystemConfig.key == config_key).first()
    
    if not config:
        # Try alternate key format
        config_key = f"seal_{request.destination}"
        config = db.query(SystemConfig).filter(SystemConfig.key == config_key).first()
    
    if not config:
        return KeyReplicationResponse(
            success=False,
            message=f"Destination {request.destination} is not configured. Configure it first in System Settings.",
            destination=request.destination
        )
    
    try:
        from app.core.security import decrypt_value
        # Config is encrypted, need to decrypt first
        decrypted = decrypt_value(config.value)
        kms_config = json.loads(decrypted)
    except Exception as e:
        logger.error(f"Failed to decrypt/parse config for {request.destination}: {e}")
        return KeyReplicationResponse(
            success=False,
            message=f"Invalid configuration for {request.destination}",
            destination=request.destination
        )
    
    if not kms_config.get('enabled'):
        return KeyReplicationResponse(
            success=False,
            message=f"{request.destination} is configured but not enabled",
            destination=request.destination
        )
    
    # Step 3: Store the keys in the destination KMS
    secret_name = request.secret_name or "vault-unseal-keys"
    secret_data = json.dumps({
        "unseal_keys": unseal_keys,
        "replicated_at": datetime.now(timezone.utc).isoformat(),
        "source": request.source.value,
        "key_count": len(unseal_keys)
    })
    
    try:
        if request.destination == "awskms":
            result = _store_in_aws_secrets_manager(kms_config, secret_name, secret_data, db)
        elif request.destination == "gcpckms":
            result = _store_in_gcp_secret_manager(kms_config, secret_name, secret_data, db)
        elif request.destination == "azurekeyvault":
            result = _store_in_azure_keyvault(kms_config, secret_name, secret_data, db)
        elif request.destination == "ocikms":
            result = _store_in_oci_vault(kms_config, secret_name, secret_data, db)
        elif request.destination == "alicloudkms":
            result = _store_in_alicloud_kms(kms_config, secret_name, secret_data)
        elif request.destination == "transit":
            result = _store_in_vault_transit(kms_config, secret_name, secret_data, db)
        else:
            return KeyReplicationResponse(
                success=False,
                message=f"Unsupported destination: {request.destination}",
                destination=request.destination
            )
        
        if result.get("success"):
            logger.info(f"Successfully replicated {len(unseal_keys)} keys to {request.destination}")
            return KeyReplicationResponse(
                success=True,
                message=f"Successfully replicated {len(unseal_keys)} unseal keys to {request.destination}",
                keys_replicated=len(unseal_keys),
                destination=request.destination,
                secret_identifier=result.get("identifier")
            )
        else:
            return KeyReplicationResponse(
                success=False,
                message=result.get("error", "Unknown error during replication"),
                destination=request.destination
            )
    
    except Exception as e:
        logger.error(f"Key replication failed: {e}")
        return KeyReplicationResponse(
            success=False,
            message=f"Failed to replicate keys: {str(e)}",
            destination=request.destination
        )


def _store_in_aws_secrets_manager(kms_config: dict, secret_name: str, secret_data: str, db: Session) -> dict:
    """Store keys in AWS Secrets Manager (not KMS directly)"""
    try:
        import boto3
        from app.core.security import decrypt_value
        
        region = kms_config.get('region', 'us-east-1')
        access_key = kms_config.get('access_key')
        secret_key = kms_config.get('secret_key')
        
        # Try to decrypt credentials - if it fails, assume already plaintext
        if access_key:
            try:
                access_key = decrypt_value(access_key)
            except Exception:
                pass
        if secret_key:
            try:
                secret_key = decrypt_value(secret_key)
            except Exception:
                pass
        
        # Create Secrets Manager client
        if access_key and secret_key:
            client = boto3.client(
                'secretsmanager',
                region_name=region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
        else:
            # Use IAM role
            client = boto3.client('secretsmanager', region_name=region)
        
        # Try to update existing secret, or create new one
        try:
            response = client.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_data
            )
            return {"success": True, "identifier": response['ARN']}
        except client.exceptions.ResourceNotFoundException:
            # Secret doesn't exist, create it
            response = client.create_secret(
                Name=secret_name,
                SecretString=secret_data,
                Description="Vault unseal keys (replicated for redundancy)"
            )
            return {"success": True, "identifier": response['ARN']}
    
    except Exception as e:
        return {"success": False, "error": str(e)}


def _store_in_gcp_secret_manager(kms_config: dict, secret_name: str, secret_data: str, db: Session) -> dict:
    """Store keys in GCP Secret Manager"""
    try:
        from google.cloud import secretmanager
        from google.oauth2 import service_account
        from app.core.security import decrypt_value
        import json
        
        project = kms_config.get('project')
        # Support both 'credentials' and 'credentials_json' field names
        credentials_json = kms_config.get('credentials') or kms_config.get('credentials_json')
        
        if credentials_json:
            # Try to decrypt - if it fails, assume it's already plaintext
            try:
                credentials_json = decrypt_value(credentials_json)
            except Exception:
                pass  # Already decrypted or plaintext JSON
            
            creds_dict = json.loads(credentials_json)
            credentials = service_account.Credentials.from_service_account_info(creds_dict)
            client = secretmanager.SecretManagerServiceClient(credentials=credentials)
        else:
            client = secretmanager.SecretManagerServiceClient()
        
        parent = f"projects/{project}"
        secret_path = f"{parent}/secrets/{secret_name}"
        
        # Try to access existing secret
        try:
            client.access_secret_version(request={"name": f"{secret_path}/versions/latest"})
            # Secret exists, add new version
            response = client.add_secret_version(
                request={
                    "parent": secret_path,
                    "payload": {"data": secret_data.encode("UTF-8")}
                }
            )
            return {"success": True, "identifier": response.name}
        except Exception:
            # Secret doesn't exist, create it
            secret = client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_name,
                    "secret": {"replication": {"automatic": {}}}
                }
            )
            response = client.add_secret_version(
                request={
                    "parent": secret.name,
                    "payload": {"data": secret_data.encode("UTF-8")}
                }
            )
            return {"success": True, "identifier": response.name}
    
    except Exception as e:
        return {"success": False, "error": str(e)}


def _store_in_azure_keyvault(kms_config: dict, secret_name: str, secret_data: str, db: Session) -> dict:
    """Store keys in Azure Key Vault"""
    try:
        from azure.identity import ClientSecretCredential
        from azure.keyvault.secrets import SecretClient
        from app.core.security import decrypt_value
        
        vault_name = kms_config.get('vault_name')
        tenant_id = kms_config.get('tenant_id')
        client_id = kms_config.get('client_id')
        client_secret = kms_config.get('client_secret')
        
        # Try to decrypt credentials - if it fails, assume already plaintext
        if client_secret:
            try:
                client_secret = decrypt_value(client_secret)
            except Exception:
                pass  # Already decrypted or plaintext
        
        vault_url = f"https://{vault_name}.vault.azure.net"
        
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        client = SecretClient(vault_url=vault_url, credential=credential)
        
        # Azure Key Vault secret names can only contain alphanumeric and hyphens
        safe_name = secret_name.replace("_", "-")
        
        secret = client.set_secret(safe_name, secret_data)
        return {"success": True, "identifier": secret.id}
    
    except Exception as e:
        return {"success": False, "error": str(e)}


def _store_in_oci_vault(kms_config: dict, secret_name: str, secret_data: str, db: Session) -> dict:
    """Store keys in OCI Vault (Secrets service)"""
    try:
        import oci
        import base64
        from app.core.security import decrypt_value
        
        # Handle both old field names and new auth_type_ prefixed field names
        key_id = kms_config.get('key_id') or kms_config.get('key_ocid')
        use_instance_principal = kms_config.get('auth_type_use_instance_principal') or kms_config.get('use_instance_principal', False)
        crypto_endpoint = kms_config.get('crypto_endpoint')
        
        if not key_id:
            return {"success": False, "error": "Key ID (key_id or key_ocid) not configured"}
        
        if not crypto_endpoint:
            return {"success": False, "error": "Crypto endpoint not configured"}
        
        # Encode the secret data as base64 (OCI requires this)
        encoded_data = base64.b64encode(secret_data.encode()).decode()
        
        if use_instance_principal:
            # Instance Principal auth - use empty config with signer
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            crypto_client = oci.key_management.KmsCryptoClient(
                config={}, 
                signer=signer,
                service_endpoint=crypto_endpoint
            )
        else:
            # API Key authentication - use key_content in config (same pattern as seal test)
            tenancy = kms_config.get('auth_type_api_key_tenancy_ocid') or kms_config.get('tenancy_ocid')
            user = kms_config.get('auth_type_api_key_user_ocid') or kms_config.get('user_ocid')
            fingerprint = kms_config.get('auth_type_api_key_fingerprint') or kms_config.get('fingerprint')
            region = kms_config.get('region')
            
            if not all([tenancy, user, fingerprint, region]):
                missing = []
                if not tenancy: missing.append("tenancy_ocid")
                if not user: missing.append("user_ocid")
                if not fingerprint: missing.append("fingerprint")
                if not region: missing.append("region")
                return {"success": False, "error": f"Missing OCI config fields: {', '.join(missing)}"}
            
            private_key = kms_config.get('auth_type_api_key_private_key') or kms_config.get('private_key')
            if private_key:
                # Try to decrypt - if it fails, assume it's already plaintext
                try:
                    private_key = decrypt_value(private_key)
                except Exception:
                    pass  # Already decrypted or plaintext
            
            if not private_key:
                return {"success": False, "error": "Private key is required for API key authentication"}
            
            # Build OCI config with key_content (same pattern as the working seal test)
            oci_config = {
                "user": user,
                "fingerprint": fingerprint,
                "tenancy": tenancy,
                "region": region,
                "key_content": private_key
            }
            
            crypto_client = oci.key_management.KmsCryptoClient(
                oci_config, 
                service_endpoint=crypto_endpoint
            )
        
        # Encrypt the data with the key
        encrypt_response = crypto_client.encrypt(
            encrypt_data_details=oci.key_management.models.EncryptDataDetails(
                key_id=key_id,
                plaintext=encoded_data
            )
        )
        
        # Store the encrypted data reference in our database
        encrypted_keys_config = db.query(SystemConfig).filter(
            SystemConfig.key == "replicated_keys_ocikms"
        ).first()
        
        import json
        replicated_data = {
            "encrypted_data": encrypt_response.data.ciphertext,
            "key_id": key_id,
            "replicated_at": datetime.now(timezone.utc).isoformat(),
            "crypto_endpoint": crypto_endpoint
        }
        
        if encrypted_keys_config:
            encrypted_keys_config.value = json.dumps(replicated_data)
        else:
            encrypted_keys_config = SystemConfig(
                key="replicated_keys_ocikms",
                value=json.dumps(replicated_data)
            )
            db.add(encrypted_keys_config)
        
        db.commit()
        
        return {"success": True, "identifier": f"oci:kms:{crypto_endpoint}:key:{key_id}"}
    
    except Exception as e:
        import traceback
        logger.error(f"OCI replication error: {traceback.format_exc()}")
        return {"success": False, "error": str(e)}


def _store_in_alicloud_kms(kms_config: dict, secret_name: str, secret_data: str) -> dict:
    """Store keys in AliCloud KMS Secrets Manager"""
    try:
        from alibabacloud_kms20160120.client import Client as KmsClient
        from alibabacloud_tea_openapi import models as open_api_models
        from alibabacloud_kms20160120 import models as kms_models
        
        config = open_api_models.Config(
            access_key_id=kms_config.get('access_key_id'),
            access_key_secret=kms_config.get('access_key_secret'),
            region_id=kms_config.get('region')
        )
        
        client = KmsClient(config)
        
        # Try to create or update secret
        try:
            # Try to put secret value (update existing)
            request = kms_models.PutSecretValueRequest(
                secret_name=secret_name,
                secret_data=secret_data,
                version_id=datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            )
            response = client.put_secret_value(request)
            return {"success": True, "identifier": f"alicloud:secret:{secret_name}"}
        except Exception:
            # Create new secret
            request = kms_models.CreateSecretRequest(
                secret_name=secret_name,
                secret_data=secret_data,
                description="Vault unseal keys (replicated for redundancy)"
            )
            response = client.create_secret(request)
            return {"success": True, "identifier": f"alicloud:secret:{secret_name}"}
    
    except Exception as e:
        return {"success": False, "error": str(e)}


def _store_in_vault_transit(kms_config: dict, secret_name: str, secret_data: str, db: Session) -> dict:
    """Store keys in another Vault instance using Transit"""
    try:
        import hvac
        from app.core.security import decrypt_value
        
        address = kms_config.get('address')
        token = kms_config.get('token')
        key_name = kms_config.get('key_name', 'autounseal')
        mount_path = kms_config.get('mount_path', 'transit')
        tls_skip_verify = kms_config.get('tls_skip_verify', False)
        
        # Try to decrypt token - if it fails, assume already plaintext
        if token:
            try:
                token = decrypt_value(token)
            except Exception:
                pass
        
        client = hvac.Client(url=address, token=token, verify=not tls_skip_verify)
        
        # Use the KV engine to store the keys (encrypted by Transit)
        # First encrypt with Transit
        import base64
        plaintext = base64.b64encode(secret_data.encode()).decode()
        
        encrypt_response = client.secrets.transit.encrypt_data(
            name=key_name,
            plaintext=plaintext,
            mount_point=mount_path
        )
        
        ciphertext = encrypt_response['data']['ciphertext']
        
        # Store in KV
        kv_path = f"replicated-keys/{secret_name}"
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=kv_path,
                secret={
                    "ciphertext": ciphertext,
                    "key_name": key_name,
                    "replicated_at": datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception:
            # Try KV v1
            client.secrets.kv.v1.create_or_update_secret(
                path=kv_path,
                secret={
                    "ciphertext": ciphertext,
                    "key_name": key_name,
                    "replicated_at": datetime.now(timezone.utc).isoformat()
                }
            )
        
        return {"success": True, "identifier": f"vault:{address}/secret/{kv_path}"}
    
    except Exception as e:
        return {"success": False, "error": str(e)}


class ReplicatedKeyInfo(BaseModel):
    """Information about a replicated key backup"""
    destination: str
    replicated_at: Optional[str] = None
    identifier: Optional[str] = None
    status: str = "unknown"


class KeyReplicationStatusResponse(BaseModel):
    """Response with status of all key replications"""
    has_local_keys: bool
    local_key_count: int = 0
    replications: List[ReplicatedKeyInfo]


@router.get("/config/vault/replication-status", response_model=KeyReplicationStatusResponse)
def get_key_replication_status(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Get the status of key replications to various KMS providers.
    """
    import json
    from pathlib import Path
    
    replications = []
    
    # Check local keys
    has_local_keys = False
    local_key_count = 0
    vault_keys_paths = [
        Path("/app/vault_data/vault_keys.json"),
        Path("/app/data/vault/vault_keys.json"),
        Path("/app/data/vault_keys.json"),
        Path("data/vault/vault_keys.json"),
    ]
    
    for path in vault_keys_paths:
        if path.exists():
            try:
                with open(path, 'r') as f:
                    keys_data = json.load(f)
                keys = keys_data.get('keys', []) or keys_data.get('unseal_keys', [])
                if keys:
                    has_local_keys = True
                    local_key_count = len(keys)
                    break
            except:
                pass
    
    # Check for replicated keys in database
    providers = ["awskms", "gcpckms", "azurekeyvault", "ocikms", "alicloudkms", "transit"]
    
    for provider in providers:
        # Check if provider is configured and enabled (try both key formats)
        config = db.query(SystemConfig).filter(SystemConfig.key == f"vault_seal_{provider}").first()
        if not config:
            config = db.query(SystemConfig).filter(SystemConfig.key == f"seal_{provider}").first()
        
        if config:
            try:
                provider_config = json.loads(config.value)
                if provider_config.get('enabled'):
                    # Check for replication record
                    replication_record = db.query(SystemConfig).filter(
                        SystemConfig.key == f"replicated_keys_{provider}"
                    ).first()
                    
                    if replication_record:
                        try:
                            repl_data = json.loads(replication_record.value)
                            replications.append(ReplicatedKeyInfo(
                                destination=provider,
                                replicated_at=repl_data.get('replicated_at'),
                                identifier=repl_data.get('identifier', repl_data.get('key_id')),
                                status="replicated"
                            ))
                        except:
                            replications.append(ReplicatedKeyInfo(
                                destination=provider,
                                status="configured"
                            ))
                    else:
                        replications.append(ReplicatedKeyInfo(
                            destination=provider,
                            status="configured"
                        ))
            except:
                pass
    
    return KeyReplicationStatusResponse(
        has_local_keys=has_local_keys,
        local_key_count=local_key_count,
        replications=replications
    )


# =============================================================================
# Vault Seal Configuration (KMS / Transit Auto-Unseal)
# =============================================================================

class SealProvider(str, Enum):
    SHAMIR = "shamir"  # Default - manual unseal with keys
    TRANSIT = "transit"  # Self-hosted Transit (another Vault)
    AWSKMS = "awskms"
    GCPCKMS = "gcpckms"
    AZUREKEYVAULT = "azurekeyvault"
    OCIKMS = "ocikms"
    ALICLOUDKMS = "alicloudkms"


class SealConfigBase(BaseModel):
    """Base configuration for all seal types"""
    provider: str
    enabled: bool = False

class TransitSealConfig(SealConfigBase):
    """Configuration for Transit auto-unseal (self-hosted KMS)"""
    provider: str = "transit"
    address: str  # e.g., http://kms-vault:8200
    token: str  # Transit token with encrypt/decrypt permissions
    key_name: str = "autounseal"
    mount_path: str = "transit"
    tls_skip_verify: bool = False
    tls_ca_cert: Optional[str] = None

class AWSKMSSealConfig(SealConfigBase):
    """Configuration for AWS KMS auto-unseal"""
    provider: str = "awskms"
    region: str
    access_key: Optional[str] = None  # Optional if using IAM role
    secret_key: Optional[str] = None
    kms_key_id: str  # ARN or key ID
    endpoint: Optional[str] = None  # Custom endpoint (for testing)

class GCPKMSSealConfig(SealConfigBase):
    """Configuration for Google Cloud KMS auto-unseal"""
    provider: str = "gcpckms"
    project: str
    region: str
    key_ring: str
    crypto_key: str
    credentials_json: Optional[str] = None  # Service account JSON

class AzureKeyVaultSealConfig(SealConfigBase):
    """Configuration for Azure Key Vault auto-unseal"""
    provider: str = "azurekeyvault"
    vault_name: str
    key_name: str
    tenant_id: str
    client_id: str
    client_secret: str

class OCIKMSSealConfig(SealConfigBase):
    """Configuration for Oracle Cloud KMS auto-unseal"""
    provider: str = "ocikms"
    key_id: str  # OCID of the key
    crypto_endpoint: str
    management_endpoint: str
    auth_type_api_key: bool = False
    # For API key auth:
    tenancy_ocid: Optional[str] = None
    user_ocid: Optional[str] = None
    fingerprint: Optional[str] = None
    private_key: Optional[str] = None
    region: Optional[str] = None

class AliCloudKMSSealConfig(SealConfigBase):
    """Configuration for AliCloud KMS auto-unseal"""
    provider: str = "alicloudkms"
    region: str
    access_key: str
    secret_key: str
    kms_key_id: str

class SealConfigResponse(BaseModel):
    """Response containing current seal configuration"""
    configured: bool
    provider: str
    enabled: bool
    # Only include non-sensitive fields
    details: dict = {}
    requires_migration: bool = False
    migration_instructions: Optional[str] = None

class SealConfigRequest(BaseModel):
    """Request to save seal configuration"""
    provider: str
    enabled: bool = True
    config: dict  # Provider-specific configuration

def _get_seal_config_from_db(db: Session) -> Optional[dict]:
    """Retrieve seal configuration from database"""
    import json
    from app.core.security import decrypt_value
    
    config = db.query(SystemConfig).filter(SystemConfig.key == "vault_seal_config").first()
    if not config:
        return None
    
    try:
        decrypted = decrypt_value(config.value)
        return json.loads(decrypted)
    except Exception as e:
        logger.error("Failed to decrypt seal config", error=str(e))
        return None

def _save_seal_config_to_db(db: Session, config: dict):
    """Save seal configuration to database (encrypted)"""
    import json
    from app.core.security import encrypt_value
    
    encrypted = encrypt_value(json.dumps(config))
    
    existing = db.query(SystemConfig).filter(SystemConfig.key == "vault_seal_config").first()
    if existing:
        existing.value = encrypted
        existing.description = f"Vault seal configuration ({config.get('provider', 'unknown')})"
    else:
        new_config = SystemConfig(
            key="vault_seal_config",
            value=encrypted,
            description=f"Vault seal configuration ({config.get('provider', 'unknown')})"
        )
        db.add(new_config)
    
    db.commit()

def _generate_vault_seal_stanza(config: dict) -> str:
    """Generate Vault HCL seal configuration stanza"""
    provider = config.get("provider")
    
    if provider == "shamir" or not config.get("enabled"):
        return ""  # No seal stanza needed for Shamir
    
    if provider == "transit":
        return f'''
seal "transit" {{
  address         = "{config.get('address')}"
  token           = "{config.get('token')}"
  key_name        = "{config.get('key_name', 'autounseal')}"
  mount_path      = "{config.get('mount_path', 'transit')}"
  tls_skip_verify = {str(config.get('tls_skip_verify', False)).lower()}
}}
'''
    
    if provider == "awskms":
        stanza = f'''
seal "awskms" {{
  region     = "{config.get('region')}"
  kms_key_id = "{config.get('kms_key_id')}"
'''
        if config.get('access_key'):
            stanza += f'  access_key = "{config.get("access_key")}"\n'
        if config.get('secret_key'):
            stanza += f'  secret_key = "{config.get("secret_key")}"\n'
        if config.get('endpoint'):
            stanza += f'  endpoint   = "{config.get("endpoint")}"\n'
        stanza += "}\n"
        return stanza
    
    if provider == "gcpckms":
        return f'''
seal "gcpckms" {{
  project     = "{config.get('project')}"
  region      = "{config.get('region')}"
  key_ring    = "{config.get('key_ring')}"
  crypto_key  = "{config.get('crypto_key')}"
}}
'''
    
    if provider == "azurekeyvault":
        return f'''
seal "azurekeyvault" {{
  vault_name  = "{config.get('vault_name')}"
  key_name    = "{config.get('key_name')}"
  tenant_id   = "{config.get('tenant_id')}"
  client_id   = "{config.get('client_id')}"
  client_secret = "{config.get('client_secret')}"
}}
'''
    
    if provider == "ocikms":
        stanza = f'''
seal "ocikms" {{
  key_id              = "{config.get('key_id')}"
  crypto_endpoint     = "{config.get('crypto_endpoint')}"
  management_endpoint = "{config.get('management_endpoint')}"
'''
        if config.get('auth_type_api_key'):
            stanza += '  auth_type_api_key = true\n'
        stanza += "}\n"
        return stanza
    
    if provider == "alicloudkms":
        return f'''
seal "alicloudkms" {{
  region     = "{config.get('region')}"
  access_key = "{config.get('access_key')}"
  secret_key = "{config.get('secret_key')}"
  kms_key_id = "{config.get('kms_key_id')}"
}}
'''
    
    return ""

def _write_vault_seal_config(config: dict) -> bool:
    """Write Vault seal configuration to the config file"""
    from pathlib import Path
    
    seal_stanza = _generate_vault_seal_stanza(config)
    
    # Write to a dedicated seal config file that Vault can include
    config_path = Path("/app/data/vault/config/seal.hcl")
    if not config_path.parent.exists():
        config_path = Path("data/vault/config/seal.hcl")
    
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        config_path.write_text(seal_stanza)
        logger.info("Vault seal configuration written", path=str(config_path))
        return True
    except Exception as e:
        logger.error("Failed to write seal config", error=str(e))
        return False


@router.get("/config/vault/seal", response_model=SealConfigResponse)
def get_seal_config(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Get current Vault seal configuration.
    Sensitive fields (tokens, keys) are masked in the response.
    """
    config = _get_seal_config_from_db(db)
    
    if not config:
        return SealConfigResponse(
            configured=False,
            provider="shamir",
            enabled=False,
            details={},
            requires_migration=False
        )
    
    # Mask sensitive fields
    masked_details = {}
    sensitive_fields = ['token', 'secret_key', 'client_secret', 'private_key', 'credentials_json', 'access_key']
    
    for key, value in config.items():
        if key in ['provider', 'enabled']:
            continue
        if key in sensitive_fields and value:
            masked_details[key] = "********"
        else:
            masked_details[key] = value
    
    # Check if migration is needed (current seal type vs configured)
    # This would require checking Vault's actual seal status
    requires_migration = False
    migration_instructions = None
    
    try:
        vault_status = vault_client.get_status()
        # If Vault reports a different seal type, migration is needed
        # Note: This is a simplified check
        if config.get('enabled') and not vault_status.get('sealed'):
            # Vault is running with some seal type
            # In a real scenario, we'd compare seal types
            pass
    except:
        pass
    
    return SealConfigResponse(
        configured=True,
        provider=config.get('provider', 'shamir'),
        enabled=config.get('enabled', False),
        details=masked_details,
        requires_migration=requires_migration,
        migration_instructions=migration_instructions
    )


@router.post("/config/vault/seal", status_code=status.HTTP_200_OK)
def save_seal_config(
    request: SealConfigRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Save Vault seal configuration.
    
    This saves the configuration to the database and writes the Vault HCL config file.
    The configuration will take effect after Vault is restarted and seal migration is performed.
    
    IMPORTANT: Changing seal type requires seal migration with current unseal keys.
    """
    provider = request.provider.lower()
    
    # Validate provider
    valid_providers = ['shamir', 'transit', 'awskms', 'gcpckms', 'azurekeyvault', 'ocikms', 'alicloudkms']
    if provider not in valid_providers:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider. Must be one of: {', '.join(valid_providers)}"
        )
    
    # Build full config
    full_config = {
        'provider': provider,
        'enabled': request.enabled,
        **request.config
    }
    
    # Validate required fields based on provider
    required_fields = {
        'transit': ['address', 'token'],
        'awskms': ['region', 'kms_key_id'],
        'gcpckms': ['project', 'region', 'key_ring', 'crypto_key'],
        'azurekeyvault': ['vault_name', 'key_name', 'tenant_id', 'client_id', 'client_secret'],
        'ocikms': ['key_id', 'crypto_endpoint', 'management_endpoint'],
        'alicloudkms': ['region', 'access_key', 'secret_key', 'kms_key_id']
    }
    
    if provider in required_fields:
        missing = [f for f in required_fields[provider] if not request.config.get(f)]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing required fields for {provider}: {', '.join(missing)}"
            )
    
    # Save to database
    _save_seal_config_to_db(db, full_config)
    
    # Write Vault config file
    if request.enabled:
        if not _write_vault_seal_config(full_config):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to write Vault seal configuration file"
            )
    
    logger.info("Vault seal configuration saved", provider=provider, enabled=request.enabled)
    
    # Check if Docker socket is available for automatic restart
    docker_available = is_docker_available()
    
    # Build detailed next steps
    if request.enabled and provider != 'shamir':
        if docker_available:
            next_steps = [
                "Configuration saved! Docker socket detected.",
                "",
                "You can perform seal migration automatically or manually:",
                "",
                "AUTOMATIC (Recommended):",
                "  Enter your unseal keys above and click 'Start Automated Migration'.",
                "  SCR-PKI will restart Vault and perform the migration for you.",
                "",
                "MANUAL:",
                "  1. Stop SCR-PKI: docker compose down",
                "  2. Start Vault only: docker compose up -d pki_vault",
                "  3. Unseal with migration:",
                "     docker exec pki_vault vault operator unseal -migrate <KEY>",
                "     (repeat with 3 keys)",
                "  4. Restart all: docker compose up -d",
            ]
        else:
            next_steps = [
                "Configuration saved! To complete seal migration:",
                "",
                "Step 1: Stop the SCR-PKI stack",
                "  docker compose down",
                "",
                "Step 2: Start ONLY the Vault container in migration mode",
                "  docker compose up -d pki_vault",
                "",
                "Step 3: Wait for Vault to start, then unseal with migration flag",
                "  docker exec pki_vault vault operator unseal -migrate <KEY_1>",
                "  docker exec pki_vault vault operator unseal -migrate <KEY_2>",
                "  docker exec pki_vault vault operator unseal -migrate <KEY_3>",
                "  (Use 3 of your 5 original Shamir unseal keys)",
                "",
                "Step 4: Verify migration succeeded",
                "  docker exec pki_vault vault status",
                "  (Seal Type should now show: " + provider + ")",
                "",
                "Step 5: Restart the full stack",
                "  docker compose down && docker compose up -d",
                "",
                "Note: After successful migration, Vault will auto-unseal using " + provider + "."
            ]
    else:
        next_steps = []
    
    return {
        "message": f"Seal configuration saved for {provider}",
        "provider": provider,
        "enabled": request.enabled,
        "docker_available": docker_available,
        "next_steps": next_steps
    }


@router.delete("/config/vault/seal", status_code=status.HTTP_200_OK)
def delete_seal_config(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Delete Vault seal configuration, reverting to Shamir (manual unseal).
    
    WARNING: This requires seal migration back to Shamir keys.
    """
    from pathlib import Path
    
    # Delete from database
    config = db.query(SystemConfig).filter(SystemConfig.key == "vault_seal_config").first()
    if config:
        db.delete(config)
        db.commit()
    
    # Remove seal config file
    config_paths = [
        Path("/app/data/vault/config/seal.hcl"),
        Path("data/vault/config/seal.hcl")
    ]
    
    for path in config_paths:
        if path.exists():
            path.unlink()
            logger.info("Removed seal config file", path=str(path))
    
    return {
        "message": "Seal configuration removed. Vault will use Shamir (manual unseal) after restart.",
        "next_steps": [
            "1. Restart the Vault container",
            "2. Unseal with your Shamir unseal keys"
        ]
    }


@router.post("/config/vault/seal/{provider}", status_code=status.HTTP_200_OK)
def save_provider_seal_config(
    provider: str,
    request: SealConfigRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Save seal configuration for a specific provider.
    
    This allows configuring multiple KMS providers independently.
    Use the unseal-priority endpoint to set which provider is used.
    """
    import json
    from app.core.security import encrypt_value, decrypt_value
    
    provider = provider.lower()
    valid_providers = ['transit', 'awskms', 'gcpckms', 'azurekeyvault', 'ocikms', 'alicloudkms']
    
    if provider not in valid_providers:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider. Must be one of: {', '.join(valid_providers)}"
        )
    
    config_key = f"vault_seal_{provider}"
    existing = db.query(SystemConfig).filter(SystemConfig.key == config_key).first()
    
    # If there's existing config, merge with new values (preserving secrets not sent)
    existing_config = {}
    if existing:
        try:
            decrypted = decrypt_value(existing.value)
            existing_config = json.loads(decrypted)
        except:
            pass
    
    # Merge: new values overwrite, but keep existing values for fields not sent
    full_config = {
        **existing_config,  # Start with existing config
        'provider': provider,
        'enabled': request.enabled,
        **request.config  # Overwrite with new values
    }
    
    # Encrypt and store
    encrypted = encrypt_value(json.dumps(full_config))
    
    if existing:
        existing.value = encrypted
    else:
        new_config = SystemConfig(key=config_key, value=encrypted)
        db.add(new_config)
    
    db.commit()
    
    logger.info(f"Saved seal configuration for provider", provider=provider, enabled=request.enabled)
    
    return {
        "message": f"{provider} configuration saved",
        "provider": provider,
        "enabled": request.enabled
    }


@router.get("/config/vault/seal/{provider}")
def get_provider_seal_config(
    provider: str,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Get seal configuration for a specific provider.
    Sensitive fields are masked.
    """
    import json
    from app.core.security import decrypt_value
    
    provider = provider.lower()
    config_key = f"vault_seal_{provider}"
    
    config_row = db.query(SystemConfig).filter(SystemConfig.key == config_key).first()
    if not config_row:
        return {"configured": False, "provider": provider}
    
    try:
        decrypted = decrypt_value(config_row.value)
        config = json.loads(decrypted)
    except:
        return {"configured": False, "provider": provider, "error": "Failed to decrypt config"}
    
    # Mask sensitive fields
    sensitive_fields = ['token', 'secret_key', 'client_secret', 'private_key', 'credentials_json', 'access_key']
    masked_config = {}
    for key, value in config.items():
        if key in sensitive_fields and value:
            masked_config[key] = "••••••••" + str(value)[-4:] if len(str(value)) > 4 else "••••••••"
        else:
            masked_config[key] = value
    
    return {
        "configured": True,
        "provider": provider,
        "enabled": config.get('enabled', False),
        "config": masked_config
    }


@router.delete("/config/vault/seal/{provider}", status_code=status.HTTP_200_OK)
def delete_provider_seal_config(
    provider: str,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Delete seal configuration for a specific provider.
    """
    provider = provider.lower()
    config_key = f"vault_seal_{provider}"
    
    config_row = db.query(SystemConfig).filter(SystemConfig.key == config_key).first()
    if config_row:
        db.delete(config_row)
        db.commit()
        return {"message": f"{provider} configuration deleted"}
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No configuration found for {provider}"
    )


@router.post("/config/vault/seal-test", status_code=status.HTTP_200_OK)
def test_seal_config(
    request: SealConfigRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Test seal configuration connectivity without saving it.
    Attempts to connect to the KMS/Transit endpoint to verify credentials.
    """
    import httpx
    
    provider = request.provider.lower()
    config = request.config
    
    if provider == "transit":
        # Test Transit connectivity
        try:
            address = config.get('address', '').rstrip('/')
            token = config.get('token', '')
            
            response = httpx.get(
                f"{address}/v1/sys/health",
                headers={"X-Vault-Token": token},
                timeout=10,
                verify=not config.get('tls_skip_verify', False)
            )
            
            if response.status_code == 200:
                # Also verify the transit key exists
                key_name = config.get('key_name', 'autounseal')
                mount_path = config.get('mount_path', 'transit')
                
                key_response = httpx.get(
                    f"{address}/v1/{mount_path}/keys/{key_name}",
                    headers={"X-Vault-Token": token},
                    timeout=10,
                    verify=not config.get('tls_skip_verify', False)
                )
                
                if key_response.status_code == 200:
                    return {"success": True, "message": "Transit connection successful. Key found."}
                elif key_response.status_code == 404:
                    return {"success": False, "message": f"Transit key '{key_name}' not found at mount '{mount_path}'"}
                else:
                    return {"success": False, "message": f"Failed to access transit key: {key_response.status_code}"}
            else:
                return {"success": False, "message": f"Transit Vault health check failed: {response.status_code}"}
                
        except httpx.ConnectError:
            return {"success": False, "message": f"Cannot connect to Transit Vault at {address}"}
        except Exception as e:
            return {"success": False, "message": f"Transit test failed: {str(e)}"}
    
    elif provider == "awskms":
        # Test AWS KMS connectivity
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            kwargs = {
                'region_name': config.get('region')
            }
            if config.get('access_key') and config.get('secret_key'):
                kwargs['aws_access_key_id'] = config.get('access_key')
                kwargs['aws_secret_access_key'] = config.get('secret_key')
            if config.get('endpoint'):
                kwargs['endpoint_url'] = config.get('endpoint')
            
            kms = boto3.client('kms', **kwargs)
            
            # Try to describe the key
            kms.describe_key(KeyId=config.get('kms_key_id'))
            
            return {"success": True, "message": "AWS KMS connection successful. Key accessible."}
            
        except NoCredentialsError:
            return {"success": False, "message": "AWS credentials not found or invalid"}
        except ClientError as e:
            return {"success": False, "message": f"AWS KMS error: {e.response['Error']['Message']}"}
        except ImportError:
            return {"success": False, "message": "boto3 not installed. Cannot test AWS KMS."}
        except Exception as e:
            return {"success": False, "message": f"AWS KMS test failed: {str(e)}"}
    
    elif provider == "gcpckms":
        # Test GCP Cloud KMS connectivity
        try:
            from google.cloud import kms
            from google.oauth2 import service_account
            
            project = config.get('project')
            location = config.get('region')
            key_ring = config.get('key_ring')
            crypto_key = config.get('crypto_key')
            # Support both 'credentials' and 'credentials_json' field names
            credentials_json = config.get('credentials') or config.get('credentials_json')
            
            if not project or not location or not key_ring or not crypto_key:
                return {"success": False, "message": "Missing required fields: project, region, key_ring, crypto_key"}
            
            if credentials_json:
                import json
                try:
                    creds_dict = json.loads(credentials_json)
                except json.JSONDecodeError as e:
                    return {"success": False, "message": f"Invalid JSON in service account credentials: {str(e)}"}
                credentials = service_account.Credentials.from_service_account_info(creds_dict)
                client = kms.KeyManagementServiceClient(credentials=credentials)
            else:
                # No credentials provided - will fail with ADC error
                return {"success": False, "message": "Service Account JSON is required. Upload or paste your GCP service account key."}
            
            # Build the key name
            key_name = client.crypto_key_path(project, location, key_ring, crypto_key)
            
            logger.info(f"GCP KMS test - checking key: {key_name}")
            logger.info(f"GCP KMS test - service account: {creds_dict.get('client_email', 'unknown')}")
            
            # Try to get the key
            key = client.get_crypto_key(request={"name": key_name})
            
            return {"success": True, "message": f"GCP KMS connection successful. Key '{crypto_key}' accessible."}
            
        except ImportError:
            return {"success": False, "message": "google-cloud-kms not installed. Cannot test GCP KMS."}
        except Exception as e:
            error_msg = str(e)
            # Provide more helpful error messages
            if "403" in error_msg and "denied" in error_msg.lower():
                return {
                    "success": False, 
                    "message": f"GCP KMS permission denied. The service account needs 'Cloud KMS Viewer' or 'Cloud KMS CryptoKey Encrypter/Decrypter' role on the key/keyring/project. Key path: projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{crypto_key}. Error: {error_msg}"
                }
            elif "404" in error_msg or "not exist" in error_msg.lower():
                return {
                    "success": False,
                    "message": f"GCP KMS key not found. Check project ({project}), location ({location}), keyring ({key_ring}), and key ({crypto_key}) are correct."
                }
            return {"success": False, "message": f"GCP KMS test failed: {error_msg}"}
    
    elif provider == "ocikms":
        # Test OCI KMS connectivity
        try:
            import oci
            import logging
            logger = logging.getLogger(__name__)
            
            # Debug: log received config keys
            logger.info(f"OCI KMS test - received config keys: {list(config.keys())}")
            
            # Get crypto endpoint (required for KMS operations)
            crypto_endpoint = config.get('crypto_endpoint', '').strip()
            if not crypto_endpoint:
                return {"success": False, "message": "Crypto Endpoint is required for OCI KMS"}
            
            # Get key ID and validate format
            key_id = config.get('key_id', '').strip()
            logger.info(f"OCI KMS test - key_id value: '{key_id}'")
            
            if not key_id:
                return {"success": False, "message": f"Key ID (OCID) is required. Received config keys: {list(config.keys())}"}
            
            # Validate key OCID format
            if not key_id.startswith('ocid1.key.'):
                return {"success": False, "message": f"Invalid Key OCID format. Expected 'ocid1.key.oc1...' but got: '{key_id[:50] if len(key_id) > 50 else key_id}'"}
            
            # Check if using instance principal
            if config.get('auth_type_use_instance_principal'):
                try:
                    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
                    kms_crypto_client = oci.key_management.KmsCryptoClient({}, signer=signer, service_endpoint=crypto_endpoint)
                except Exception as e:
                    return {"success": False, "message": f"Instance Principal authentication failed (only works on OCI compute instances): {str(e)}"}
            else:
                # API Key authentication
                oci_config = {
                    "user": config.get('auth_type_api_key_user_ocid', ''),
                    "fingerprint": config.get('auth_type_api_key_fingerprint', ''),
                    "tenancy": config.get('auth_type_api_key_tenancy_ocid', ''),
                    "region": config.get('region', ''),
                    "key_content": config.get('auth_type_api_key_private_key', ''),
                }
                
                # Validate required fields
                required_fields = ['user', 'fingerprint', 'tenancy', 'region']
                missing_fields = [k for k in required_fields if not oci_config.get(k)]
                if missing_fields:
                    return {"success": False, "message": f"Missing required OCI configuration: {', '.join(missing_fields)}"}
                
                if not oci_config.get('key_content'):
                    return {"success": False, "message": "Private key is required for API key authentication"}
                
                kms_crypto_client = oci.key_management.KmsCryptoClient(oci_config, service_endpoint=crypto_endpoint)
            
            # Test by encrypting a small piece of data
            test_data = "vault-unseal-test"
            import base64
            plaintext_b64 = base64.b64encode(test_data.encode()).decode()
            
            encrypt_response = kms_crypto_client.encrypt(
                oci.key_management.models.EncryptDataDetails(
                    key_id=key_id,
                    plaintext=plaintext_b64
                )
            )
            
            return {"success": True, "message": f"OCI KMS connection successful. Key can encrypt data."}
            
        except ImportError:
            return {"success": False, "message": "oci SDK not installed. Cannot test OCI KMS."}
        except oci.exceptions.ServiceError as e:
            return {"success": False, "message": f"OCI KMS error: {e.message}"}
        except Exception as e:
            return {"success": False, "message": f"OCI KMS test failed: {str(e)}"}
    
    elif provider == "azurekeyvault":
        # Test Azure Key Vault connectivity
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            
            vault_name = config.get('vault_name', '')
            key_name = config.get('key_name', '')
            tenant_id = config.get('tenant_id', '')
            client_id = config.get('client_id', '')
            client_secret = config.get('client_secret', '')
            
            vault_url = f"https://{vault_name}.vault.azure.net"
            
            if client_id and client_secret and tenant_id:
                credential = ClientSecretCredential(tenant_id, client_id, client_secret)
            else:
                credential = DefaultAzureCredential()
            
            key_client = KeyClient(vault_url, credential)
            
            # Try to get the key
            key = key_client.get_key(key_name)
            
            return {"success": True, "message": f"Azure Key Vault connection successful. Key '{key_name}' accessible."}
            
        except ImportError:
            return {"success": False, "message": "azure-identity and azure-keyvault-keys not installed. Cannot test Azure Key Vault."}
        except Exception as e:
            return {"success": False, "message": f"Azure Key Vault test failed: {str(e)}"}
    
    # For other providers (alicloudkms), return a generic response
    return {
        "success": None,
        "message": f"Connectivity test not yet implemented for {provider}. Configuration saved but not validated."
    }


class SealMigrationRequest(BaseModel):
    unseal_keys: List[str] = []  # Required for migration from Shamir
    action: str = "start"  # "start", "status", "complete"


class SealMigrationResponse(BaseModel):
    success: bool
    message: str
    status: Optional[str] = None  # "not_started", "in_progress", "completed", "failed"
    docker_available: bool = False
    steps_completed: Optional[List[str]] = None
    next_step: Optional[str] = None


@router.post("/config/vault/seal/migrate", response_model=SealMigrationResponse)
def perform_seal_migration(
    request: SealMigrationRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Perform seal migration with optional Docker automation.
    
    If Docker socket is available:
    - Automatically restarts Vault container
    - Performs migration with provided unseal keys
    - Returns status of migration
    
    If Docker socket is NOT available:
    - Returns manual steps required
    """
    import subprocess
    import httpx
    from pathlib import Path
    
    docker_available = is_docker_available()
    action = request.action.lower()
    
    # Check if seal config exists
    config = db.query(SystemConfig).filter(SystemConfig.key == "vault_seal_config").first()
    if not config:
        return SealMigrationResponse(
            success=False,
            message="No seal configuration found. Save a seal config first.",
            status="not_started",
            docker_available=docker_available
        )
    
    # Get Vault status
    try:
        vault_client = get_vault_client()
        vault_status = vault_client.get_status()
    except Exception as e:
        return SealMigrationResponse(
            success=False,
            message=f"Cannot connect to Vault: {str(e)}",
            status="failed",
            docker_available=docker_available
        )
    
    if action == "status":
        # Just return current migration status
        return SealMigrationResponse(
            success=True,
            message="Status check complete",
            status="ready" if vault_status.get("initialized") else "not_initialized",
            docker_available=docker_available
        )
    
    if action == "start":
        if not docker_available:
            # Return manual migration steps
            return SealMigrationResponse(
                success=False,
                message="Docker socket not available. Manual migration required.",
                status="manual_required",
                docker_available=False,
                steps_completed=[],
                next_step="Run migration commands manually in the Vault container"
            )
        
        # Docker is available - perform automated migration
        steps_completed = []
        
        try:
            import docker
            client = docker.DockerClient(base_url='unix://var/run/docker.sock')
            
            # Step 1: Ensure seal.hcl config is in place
            seal_config_path = Path("/app/data/vault/config/seal.hcl")
            if not seal_config_path.exists():
                return SealMigrationResponse(
                    success=False,
                    message="Seal configuration file not found. Save seal config first.",
                    status="failed",
                    docker_available=True
                )
            steps_completed.append("Seal configuration file verified")
            
            # Step 2: Check if we have unseal keys (from request or vault_keys.json)
            unseal_keys = request.unseal_keys
            if not unseal_keys:
                # Try to load from vault_keys.json
                keys_paths = [
                    Path("/app/data/vault/vault_keys.json"),
                    Path("data/vault/vault_keys.json")
                ]
                for keys_path in keys_paths:
                    if keys_path.exists():
                        import json
                        with open(keys_path, 'r') as f:
                            keys_data = json.load(f)
                            unseal_keys = keys_data.get('unseal_keys', []) or keys_data.get('keys', [])
                            if unseal_keys:
                                steps_completed.append(f"Loaded unseal keys from {keys_path}")
                                break
            
            if not unseal_keys:
                return SealMigrationResponse(
                    success=False,
                    message="No unseal keys provided and vault_keys.json not found. Provide unseal keys to migrate.",
                    status="keys_required",
                    docker_available=True,
                    steps_completed=steps_completed,
                    next_step="Provide your Shamir unseal keys to perform migration"
                )
            
            steps_completed.append(f"Have {len(unseal_keys)} unseal keys ready")
            
            # Step 3: Restart Vault container (this loads the new seal config)
            try:
                vault_container = client.containers.get("pki_vault")
                vault_container.restart()
                steps_completed.append("Vault container restarted")
            except docker.errors.NotFound:
                # Try alternate name
                try:
                    vault_container = client.containers.get("pki-vault-1")
                    vault_container.restart()
                    steps_completed.append("Vault container restarted")
                except:
                    return SealMigrationResponse(
                        success=False,
                        message="Vault container not found. Check container name.",
                        status="failed",
                        docker_available=True,
                        steps_completed=steps_completed
                    )
            
            # Step 4: Wait for Vault to be ready (but sealed)
            import time
            time.sleep(5)  # Give Vault time to start
            
            # Step 5: Unseal with -migrate flag
            # We need to exec into the container to run vault operator unseal -migrate
            try:
                for i, key in enumerate(unseal_keys):
                    # Run unseal command with migrate flag
                    exec_result = vault_container.exec_run(
                        f"vault operator unseal -migrate {key}",
                        environment={"VAULT_ADDR": "http://127.0.0.1:8200"}
                    )
                    
                    output = exec_result.output.decode('utf-8', errors='ignore')
                    
                    if exec_result.exit_code != 0:
                        if "Unseal Key (will be hidden)" in output or "Error" in output:
                            return SealMigrationResponse(
                                success=False,
                                message=f"Unseal key {i+1} failed: {output}",
                                status="failed",
                                docker_available=True,
                                steps_completed=steps_completed
                            )
                    
                    # Check if unsealed
                    if "Sealed" in output and "false" in output.lower():
                        steps_completed.append(f"Migration complete with {i+1} keys")
                        break
                    else:
                        steps_completed.append(f"Applied unseal key {i+1}")
                
            except Exception as e:
                return SealMigrationResponse(
                    success=False,
                    message=f"Failed to run unseal command: {str(e)}",
                    status="failed",
                    docker_available=True,
                    steps_completed=steps_completed
                )
            
            # Step 6: Verify migration succeeded
            time.sleep(2)
            try:
                vault_client = get_vault_client()
                new_status = vault_client.get_status()
                
                if not new_status.get("sealed", True):
                    steps_completed.append("Vault is now unsealed with new seal configuration")
                    
                    return SealMigrationResponse(
                        success=True,
                        message="Seal migration completed successfully! Vault is now using auto-unseal.",
                        status="completed",
                        docker_available=True,
                        steps_completed=steps_completed
                    )
                else:
                    return SealMigrationResponse(
                        success=False,
                        message="Vault is still sealed after migration. May need more unseal keys.",
                        status="incomplete",
                        docker_available=True,
                        steps_completed=steps_completed,
                        next_step="Provide additional unseal keys if threshold not met"
                    )
                    
            except Exception as e:
                return SealMigrationResponse(
                    success=False,
                    message=f"Could not verify Vault status after migration: {str(e)}",
                    status="unknown",
                    docker_available=True,
                    steps_completed=steps_completed
                )
                
        except Exception as e:
            logger.error("Seal migration failed", error=str(e))
            return SealMigrationResponse(
                success=False,
                message=f"Migration failed: {str(e)}",
                status="failed",
                docker_available=True,
                steps_completed=steps_completed
            )
    
    return SealMigrationResponse(
        success=False,
        message=f"Unknown action: {action}",
        status="error",
        docker_available=docker_available
    )


class VaultInitResponse(BaseModel):
    root_token: str
    keys: List[str]
    message: str

@router.post("/config/vault/init", response_model=VaultInitResponse)
def initialize_vault(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Initialize a fresh Vault instance.
    Returns the root token and unseal keys.
    Automatically saves the root token as the system configuration.
    """
    try:
        # 1. Initialize Vault
        result = vault_client.initialize_vault(shares=5, threshold=3)
        root_token = result.get('root_token')
        keys = result.get('keys', [])
        
        if not root_token or not keys:
            raise Exception("Vault initialization returned incomplete data")
            
        # 2. Unseal Vault immediately so we can use it
        vault_client.unseal_vault(keys)
        
        # 3. Save Root Token to DB (if not using env vars)
        if not settings.VAULT_TOKEN:
            encrypted_token = encrypt_value(root_token)
            db_config = db.query(SystemConfig).filter(SystemConfig.key == "vault_token").first()
            if not db_config:
                db_config = SystemConfig(key="vault_token", value=encrypted_token, description="Vault Access Token (Root)")
                db.add(db_config)
            else:
                db_config.value = encrypted_token
            db.commit()
            
            # 4. Connect client
            vault_client.connect()
            
            # 5. Enable KV Engine
            # We need to ensure the KV v2 engine is enabled at 'secret/'
            # This requires the client to be authenticated (which it is now)
            vault_client.enable_kv_engine()
            
        return VaultInitResponse(
            root_token=root_token,
            keys=keys,
            message="Vault initialized successfully! SAVE THESE KEYS IMMEDIATELY. They will not be shown again."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to initialize Vault", error=str(e), error_type=type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initialize Vault. Check server logs for details."
        )

@router.post("/reset", status_code=status.HTTP_200_OK)
def reset_system(
    include_config: bool = False,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Reset the system by deleting all certificates, CAs, and monitoring data.
    Also deletes all users EXCEPT superusers.
    Optionally resets system configuration (Vault connection) and attempts to seal Vault.
    """
    logger.warning("System reset initiated by user", user=current_user.username, include_config=include_config)
    
    try:
        # 1. Delete Certificates and their keys from Vault
        certs = db.query(Certificate).all()
        for cert in certs:
            if cert.pem_private_key_vault_path:
                try:
                    vault_client.delete_key(cert.pem_private_key_vault_path)
                except Exception as e:
                    logger.error(f"Failed to delete key for cert {cert.id}", error=str(e))
            db.delete(cert)
            
        # 2. Delete CAs and their keys from Vault
        cas = db.query(CertificateAuthority).all()
        for ca in cas:
            if ca.private_key_vault_path:
                try:
                    vault_client.delete_key(ca.private_key_vault_path)
                except Exception as e:
                    logger.error(f"Failed to delete key for CA {ca.id}", error=str(e))
            db.delete(ca)
            
        # 3. Delete Monitoring Data
        # db.query(Alert).delete()
        db.query(MonitoringService).delete()
        
        # 4. Delete all users EXCEPT superusers
        # This ensures the admin/superuser remains, but other users are cleared
        db.query(User).filter(User.is_superuser == False).delete(synchronize_session=False)
        
        # 5. Delete System Config if requested
        if include_config:
            # Check Docker availability first if we need to restart Vault
            import docker
            docker_available = False
            try:
                try:
                    client = docker.from_env()
                    client.ping()
                    docker_available = True
                except:
                    client = docker.DockerClient(base_url='unix://var/run/docker.sock')
                    client.ping()
                    docker_available = True
            except:
                pass
            
            if not docker_available:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot reset Vault configuration: Docker socket is not available to restart the container."
                )

            # Try to seal Vault if possible
            try:
                if vault_client.client and vault_client.is_authenticated():
                    vault_client.client.sys.seal()
                    logger.info("Vault sealed successfully")
            except Exception as e:
                logger.warning("Failed to seal Vault during reset", error=str(e))

            # Delete all config except vault_token if we want to keep connection
            # But if include_config is True, we probably want to wipe everything
            num_deleted = db.query(SystemConfig).delete(synchronize_session=False)
            db.commit()
            logger.info(f"Deleted {num_deleted} system config entries")
            
            # Stop Vault Container FIRST to release DB locks
            container = None
            try:
                import docker
                import time
                
                # Initialize Docker client
                # SECURITY: This requires the container to have access to the Docker socket.
                # This is necessary to restart the Vault container to clear its memory state.
                try:
                    client = docker.from_env()
                    client.ping()
                    logger.info("Connected to Docker via environment")
                except Exception as e:
                    logger.warning(f"docker.from_env() failed: {e}. Trying explicit socket.")
                    # Fallback to explicit socket
                    # Note: docker-py usually expects unix://var/run/docker.sock
                    try:
                        client = docker.DockerClient(base_url='unix://var/run/docker.sock')
                        client.ping()
                        logger.info("Connected to Docker via unix socket")
                    except Exception as e2:
                        logger.error(f"Failed to connect to Docker via socket: {e2}")
                        raise e # Re-raise to trigger outer exception handler
                
                try:
                    container = client.containers.get('pki_vault')
                    container.stop(timeout=10) # Wait up to 10s for graceful stop
                    logger.info("Vault container stopped successfully")
                except docker.errors.NotFound:
                    logger.warning("Vault container not found, skipping stop")
                except Exception as e:
                    logger.error(f"Error stopping container: {e}")
                    # Try to kill if stop failed
                    try:
                        container.kill()
                        logger.info("Vault container killed")
                    except:
                        pass

            except Exception as e:
                logger.error("Failed to interact with Docker", error=str(e))
                # We proceed, but this is risky. If Vault is running, the DB wipe might be weird.

            # Recreate Vault Table (Postgres Backend)
            # ...existing code...
            try:
                # Terminate other connections to the database to allow the drop
                # This is crucial because Vault holds a persistent connection
                db.execute(text("""
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = current_database()
                    AND pid <> pg_backend_pid()
                    AND usename = 'pki_user'
                """))
                db.commit()
                
                logger.info("Dropping vault_kv_store table...")
                db.execute(text("DROP TABLE IF EXISTS vault_kv_store CASCADE"))
                
                # Standard Vault PostgreSQL backend schema
                create_table_sql = """
                CREATE TABLE vault_kv_store (
                  parent_path TEXT COLLATE "C" NOT NULL,
                  path        TEXT COLLATE "C",
                  key         TEXT COLLATE "C",
                  value       BYTEA,
                  CONSTRAINT pkey PRIMARY KEY (path, key)
                );
                CREATE INDEX IF NOT EXISTS parent_path_idx ON vault_kv_store (parent_path);
                """
                logger.info("Recreating vault_kv_store table...")
                db.execute(text(create_table_sql))
                
                # CRITICAL: Commit the transaction immediately so the DB change is visible 
                # to the Vault container when it restarts.
                db.commit()
                logger.info("Vault storage recreated and committed")
            except Exception as e:
                logger.error("Failed to recreate vault storage", error=str(e))
            
            # Start Vault Container
            try:
                if 'client' in locals() and client:
                    container = client.containers.get('pki_vault')
                    container.start()
                    logger.info("Vault container started successfully")
                    
                    # Wait a moment for Vault to come back up
                    time.sleep(5)
                    
                    # Force re-connect/reset of our client
                    # Clear any existing token in the client wrapper
                    vault_client.client.token = None
                    vault_client.authenticated = False
                    vault_client.connect()
            except Exception as e:
                logger.error("Failed to start Vault container", error=str(e))
                pass

        # Final commit for any other changes (though we committed the truncate already)
        # If include_config was false, we still need to commit the other deletions
        if not include_config:
            db.commit()
        
        msg = "System reset successfully. Users (except superusers) and data have been cleared."
        if include_config:
            msg += " Vault configuration reset and container restarted."
        
        return {"message": msg}
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error("System reset failed", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="System reset failed. Check server logs for details.")

class BackupResponse(BaseModel):
    filename: str
    size: int
    created_at: str

@router.get("/backups", response_model=List[BackupResponse])
def list_backups(current_user = Depends(require_admin)):
    """List available backups."""
    return BackupService.list_backups()

@router.post("/backups", status_code=status.HTTP_201_CREATED)
def create_backup(current_user = Depends(require_admin)):
    """Create a new system backup."""
    return BackupService.create_backup()

@router.post("/backups/upload")
async def upload_backup(
    file: UploadFile = File(...),
    current_user = Depends(require_admin)
):
    """Upload a backup file."""
    if not file.filename.endswith('.tar.gz'):
        raise HTTPException(status_code=400, detail="Invalid file type. Must be .tar.gz")
        
    file_path = os.path.join(BackupService.BACKUP_DIR, file.filename)
    os.makedirs(BackupService.BACKUP_DIR, exist_ok=True)
    
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)
        
    return {"message": "Backup uploaded successfully", "filename": file.filename}

@router.get("/backups/{filename}")
def download_backup(
    filename: str,
    current_user = Depends(require_admin)
):
    """Download a backup file."""
    path = BackupService.get_backup_path(filename)
    return FileResponse(path, filename=filename)

class RestoreRequest(BaseModel):
    unseal_keys: List[str]
    root_token: Optional[str] = None
    restore_app: bool = True
    restore_vault: bool = True

@router.post("/backups/{filename}/restore")
def restore_backup(
    filename: str,
    restore_data: RestoreRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Restore system from a backup.
    Requires unseal keys to unlock Vault after restoration.
    Allows granular restore of App Data and Vault Data.
    """
    # 1. Perform physical restore (DB and Files)
    BackupService.restore_backup(
        filename, 
        db, 
        restore_app=restore_data.restore_app, 
        restore_vault=restore_data.restore_vault
    )
    
    # 2. Restart Vault Container (Only if Vault data was restored)
    if restore_data.restore_vault:
        try:
            import docker
            import time
            
            # Initialize Docker client
            # SECURITY: This requires the container to have access to the Docker socket.
            try:
                client = docker.from_env()
                client.ping()
            except Exception as e:
                logger.warning(f"docker.from_env() failed: {e}. Trying explicit socket.")
                client = docker.DockerClient(base_url='unix://var/run/docker.sock')
            
            container = client.containers.get('pki_vault')
            
            # Stop container
            try:
                container.stop()
                logger.info("Vault container stopped for restore")
            except Exception as e:
                logger.warning(f"Failed to stop Vault container: {e}")
                
            # Start container
            container.start()
            logger.info("Vault container started after restore")
            
            # Wait for Vault to be ready
            time.sleep(5)
            
        except Exception as e:
            logger.error("Failed to restart Vault container during restore", error=str(e))
            return {
                "message": "Database restored, but failed to restart Vault. Please restart manually.",
                "details": str(e)
            }

        # 3. Unseal Vault
        try:
            # Force client reconnect
            vault_client.connect()
            
            if not vault_client.client.sys.is_sealed():
                logger.info("Vault is already unsealed")
            else:
                logger.info("Unsealing Vault with provided keys...")
                vault_client.unseal_vault(restore_data.unseal_keys)
                
                if vault_client.client.sys.is_sealed():
                    raise Exception("Vault remained sealed after providing keys")
                    
                logger.info("Vault unsealed successfully")
                
        except Exception as e:
            logger.error("Failed to unseal Vault after restore", error=str(e))
            return {
                "message": "Restore successful, but Vault unseal failed. Please unseal manually.",
                "details": str(e)
            }

        # 4. Update Root Token if provided
        if restore_data.root_token:
            try:
                encrypted_token = encrypt_value(restore_data.root_token)
                
                # Check if config exists (it should from the restore)
                db_config = db.query(SystemConfig).filter(SystemConfig.key == "vault_token").first()
                if not db_config:
                    db_config = SystemConfig(key="vault_token", value=encrypted_token, description="Vault Access Token")
                    db.add(db_config)
                else:
                    db_config.value = encrypted_token
                
                db.commit()
                logger.info("Updated Vault root token in system config")
                
                # Re-authenticate client with new token
                vault_client.connect()
                
            except Exception as e:
                logger.error("Failed to update root token", error=str(e))
                # Don't fail the whole request for this

    return {"message": "System restored successfully"}

@router.delete("/backups/{filename}")
def delete_backup(
    filename: str,
    current_user = Depends(require_admin)
):
    """Delete a backup file."""
    return BackupService.delete_backup(filename)

class AlertSettings(BaseModel):
    smtp_enabled: bool = False
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    alert_email_from: Optional[str] = None
    alert_email_to: Optional[str] = None
    
    webhook_slack_enabled: bool = False
    webhook_slack_url: Optional[str] = None
    
    webhook_discord_enabled: bool = False
    webhook_discord_url: Optional[str] = None
    
    alert_days_before_expiry: int = 30
    
    # Recipient Selection
    alert_recipient_owner: bool = True
    alert_recipient_admins: bool = False
    alert_recipient_global: bool = True

class TestEmailRequest(BaseModel):
    to_email: str
    smtp_settings: Optional[AlertSettings] = None

class TestWebhookRequest(BaseModel):
    webhook_url: str

@router.post("/settings/test-slack", status_code=status.HTTP_200_OK)
def send_test_slack(
    request: TestWebhookRequest,
    current_user = Depends(require_admin)
):
    """
    Send a test notification to Slack.
    """
    import requests
    
    if not request.webhook_url:
        raise HTTPException(status_code=400, detail="Webhook URL is required")

    try:
        payload = {
            "text": f"🔔 *Test Notification*\nThis is a test message from your PKI System.\nSent by: {current_user.username}"
        }
        response = requests.post(request.webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        
        return {"message": "Test Slack notification sent successfully"}
        
    except Exception as e:
        logger.error("Failed to send Slack test", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=400, detail="Failed to send Slack notification. Check webhook URL and server logs.")

@router.post("/settings/test-discord", status_code=status.HTTP_200_OK)
def send_test_discord(
    request: TestWebhookRequest,
    current_user = Depends(require_admin)
):
    """
    Send a test notification to Discord.
    """
    import requests
    
    if not request.webhook_url:
        raise HTTPException(status_code=400, detail="Webhook URL is required")

    try:
        payload = {
            "content": f"🔔 **Test Notification**\nThis is a test message from your PKI System.\nSent by: {current_user.username}"
        }
        response = requests.post(request.webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        
        return {"message": "Test Discord notification sent successfully"}
        
    except Exception as e:
        logger.error("Failed to send Discord test", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=400, detail="Failed to send Discord notification. Check webhook URL and server logs.")

@router.post("/settings/test-email", status_code=status.HTTP_200_OK)
def send_test_email(
    request: TestEmailRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Send a test email using provided or saved settings.
    """
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    # Determine settings to use
    if request.smtp_settings:
        settings = request.smtp_settings
    else:
        # Load from DB
        settings = get_alert_settings(db, current_user)

    if not settings.smtp_host:
        raise HTTPException(status_code=400, detail="SMTP Host is not configured")
    
    if not settings.alert_email_from:
        raise HTTPException(status_code=400, detail="From Address is not configured")

    try:
        msg = MIMEMultipart()
        msg['From'] = settings.alert_email_from
        msg['To'] = request.to_email
        msg['Subject'] = "PKI System - Test Email"
        
        body = f"""
        This is a test email from your PKI System.
        
        If you are reading this, your SMTP configuration is working correctly!
        
        Sent by user: {current_user.username}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port)
        if settings.smtp_use_tls:
            server.starttls()
        
        if settings.smtp_username and settings.smtp_password:
            server.login(settings.smtp_username, settings.smtp_password)
            
        server.send_message(msg)
        server.quit()
        
        return {"message": f"Test email sent successfully to {request.to_email}"}
        
    except Exception as e:
        logger.error("Failed to send test email", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="Failed to send email. Check SMTP settings and server logs.")

@router.get("/settings", response_model=AlertSettings)
def get_alert_settings(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Get system alert settings.
    """
    settings_dict = {}
    configs = db.query(SystemConfig).all()
    for config in configs:
        settings_dict[config.key] = config.value

    # Helper to safely get bool
    def get_bool(key, default=False):
        val = settings_dict.get(key)
        if val is None: return default
        return val.lower() == "true"

    # Helper to safely get int
    def get_int(key, default=0):
        val = settings_dict.get(key)
        if val is None: return default
        try:
            return int(val)
        except:
            return default

    return AlertSettings(
        smtp_enabled=get_bool("smtp_enabled"),
        smtp_host=settings_dict.get("smtp_host"),
        smtp_port=get_int("smtp_port", 587),
        smtp_username=settings_dict.get("smtp_username"),
        smtp_password="********" if settings_dict.get("smtp_password") else None,
        smtp_use_tls=get_bool("smtp_use_tls", True),
        alert_email_from=settings_dict.get("alert_email_from"),
        alert_email_to=settings_dict.get("alert_email_to"),
        
        webhook_slack_enabled=get_bool("webhook_slack_enabled"),
        webhook_slack_url=settings_dict.get("webhook_slack_url"),
        
        webhook_discord_enabled=get_bool("webhook_discord_enabled"),
        webhook_discord_url=settings_dict.get("webhook_discord_url"),
        
        alert_days_before_expiry=get_int("alert_days_before_expiry", 30),
        
        alert_recipient_owner=get_bool("alert_recipient_owner", True),
        alert_recipient_admins=get_bool("alert_recipient_admins", False),
        alert_recipient_global=get_bool("alert_recipient_global", True)
    )

@router.post("/settings", response_model=AlertSettings)
def update_alert_settings(
    settings: AlertSettings,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Update system alert settings.
    """
    def update_config(key: str, value: str):
        if value is None:
            # Optionally delete or set to empty
            # For now, let's set to empty string or delete?
            # Let's keep it simple and store as string, or skip if None
            return
            
        config = db.query(SystemConfig).filter(SystemConfig.key == key).first()
        if not config:
            config = SystemConfig(key=key, value=str(value))
            db.add(config)
        else:
            config.value = str(value)

    # SMTP
    update_config("smtp_enabled", str(settings.smtp_enabled).lower())
    if settings.smtp_host is not None: update_config("smtp_host", settings.smtp_host)
    update_config("smtp_port", str(settings.smtp_port))
    if settings.smtp_username is not None: update_config("smtp_username", settings.smtp_username)
    if settings.smtp_password is not None and settings.smtp_password != "********":
        update_config("smtp_password", settings.smtp_password)
    update_config("smtp_use_tls", str(settings.smtp_use_tls).lower())
    if settings.alert_email_from is not None: update_config("alert_email_from", settings.alert_email_from)
    if settings.alert_email_to is not None: update_config("alert_email_to", settings.alert_email_to)

    # Slack
    update_config("webhook_slack_enabled", str(settings.webhook_slack_enabled).lower())
    if settings.webhook_slack_url is not None: update_config("webhook_slack_url", settings.webhook_slack_url)

    # Discord
    update_config("webhook_discord_enabled", str(settings.webhook_discord_enabled).lower())
    if settings.webhook_discord_url is not None: update_config("webhook_discord_url", settings.webhook_discord_url)
    
    # General
    update_config("alert_days_before_expiry", str(settings.alert_days_before_expiry))
    
    # Recipients
    update_config("alert_recipient_owner", str(settings.alert_recipient_owner).lower())
    update_config("alert_recipient_admins", str(settings.alert_recipient_admins).lower())
    update_config("alert_recipient_global", str(settings.alert_recipient_global).lower())

    db.commit()
    
    return settings

class VersionCheckResponse(BaseModel):
    current_version: str
    latest_version: str
    update_available: bool
    release_url: Optional[str] = None
    docker_image_available: Optional[bool] = None

@router.get("/version-check", response_model=VersionCheckResponse)
async def check_version(current_user = Depends(require_admin)):
    """
    Check for updates against the GitHub repository and DockerHub.
    """
    current_version = "0.2.0"
    try:
        # Try to read version from file (mounted at /app/VERSION or in current dir)
        version_paths = ["VERSION", "/app/VERSION"]
        for p in version_paths:
            if os.path.exists(p):
                with open(p, "r") as f:
                    content = f.read().strip()
                    if content:
                        current_version = content
                        break
    except Exception as e:
        logger.warning(f"Failed to read local version file: {e}")

    latest_version = current_version
    release_url = "https://github.com/Simon-CR/scr-pki/releases"
    docker_available = False
    
    try:
        async with httpx.AsyncClient() as client:
            # Check GitHub
            try:
                response = await client.get(
                    "https://api.github.com/repos/Simon-CR/scr-pki/releases/latest",
                    timeout=5.0
                )
                if response.status_code == 200:
                    data = response.json()
                    tag_name = data.get("tag_name", "").lstrip("v")
                    release_url = data.get("html_url")
                    
                    # Robust version comparison
                    if version.parse(tag_name) > version.parse(current_version):
                        latest_version = tag_name
            except Exception as e:
                logger.warning("Failed to check GitHub updates", error=str(e))

            # Check DockerHub
            try:
                # Check if the latest version tag exists on DockerHub
                docker_tag = f"v{latest_version}" if not latest_version.startswith("v") else latest_version
                # Or just check 'latest' or the specific version
                # Let's check the specific version tag corresponding to the latest release
                
                # Note: DockerHub API might require auth for some endpoints, but tags list is usually public for public repos
                docker_response = await client.get(
                    f"https://hub.docker.com/v2/repositories/simonclr/scr-pki-backend/tags/{latest_version}",
                    timeout=5.0
                )
                if docker_response.status_code == 200:
                    docker_available = True
            except Exception as e:
                logger.warning("Failed to check DockerHub updates", error=str(e))

    except Exception as e:
        logger.warning("Failed to check for updates", error=str(e))
        
    return VersionCheckResponse(
        current_version=current_version,
        latest_version=latest_version,
        update_available=latest_version != current_version,
        release_url=release_url,
        docker_image_available=docker_available
    )