from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import text
import httpx
import structlog
import os
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.auth import require_admin
from app.services.certificate_service import CertificateService
from app.services.ca_service import ca_service
from app.models.certificate import CertificateType
from app.core.vault import vault_client
from app.models.system import SystemConfig
from app.core.security import encrypt_value
from app.core.config import settings
from app.services.backup_service import BackupService
from sqlalchemy import text

from app.models.certificate import Certificate
from app.models.ca import CertificateAuthority
from app.models.monitoring import MonitoringService
from app.models.user import User
# from app.models.alert import Alert

logger = structlog.get_logger(__name__)

router = APIRouter()

class SystemCertRequest(BaseModel):
    common_name: str
    subject_alt_names: Optional[str] = None

@router.post("/certificate", status_code=status.HTTP_200_OK)
def update_system_certificate(
    cert_data: SystemCertRequest,
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
        
        # Retrieve the private key from Vault
        # The Certificate model stores the path to the private key in Vault
        private_key_pem = vault_client.retrieve_private_key(cert.private_key_vault_path)
        
        if not private_key_pem:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve generated private key"
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
        
        with open(crt_path, "w") as f:
            f.write(cert.pem_certificate)
            
        with open(key_path, "wb") as f:
            f.write(private_key_pem)
            
        logger.info("System certificate updated successfully", crt_path=crt_path)
        
        return {
            "message": "System certificate updated successfully. Please restart the application/Nginx to apply changes.",
            "certificate_id": cert.id,
            "common_name": cert.common_name
        }
        
    except Exception as e:
        logger.error("Failed to update system certificate", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update system certificate: {str(e)}"
        )

class SystemHealthResponse(BaseModel):
    database_connected: bool
    vault_connected: bool
    vault_initialized: bool
    vault_sealed: bool
    total_certificates: int
    total_cas: int
    missing_keys: List[str] = []

@router.get("/health", response_model=SystemHealthResponse)
def check_system_health(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Perform a system health check, verifying Database and Vault connectivity,
    and checking for data integrity (missing keys).
    """
    health = SystemHealthResponse(
        database_connected=True,
        vault_connected=False,
        vault_initialized=False,
        vault_sealed=True,
        total_certificates=0,
        total_cas=0,
        missing_keys=[]
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
    
    # Check CAs
    cas = db.query(CertificateAuthority).all()
    health.total_cas = len(cas)
    for ca in cas:
        if ca.private_key_vault_path:
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
            key = vault_client.retrieve_private_key(cert.pem_private_key_vault_path)
            if not key:
                health.missing_keys.append(f"Cert: {cert.common_name} (ID: {cert.id})")
                
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
    except Exception as e:
        logger.error("Failed to unseal Vault", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to unseal Vault: {str(e)}"
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
        
    except Exception as e:
        logger.error("Failed to initialize Vault", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initialize Vault: {str(e)}"
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
        
    except Exception as e:
        db.rollback()
        logger.error("System reset failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

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
        logger.error("Failed to send Slack test", error=str(e))
        raise HTTPException(status_code=400, detail=f"Failed to send Slack notification: {str(e)}")

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
        logger.error("Failed to send Discord test", error=str(e))
        raise HTTPException(status_code=400, detail=f"Failed to send Discord notification: {str(e)}")

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
        logger.error("Failed to send test email", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

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
        smtp_password=settings_dict.get("smtp_password"), # TODO: Should we mask this?
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
    if settings.smtp_password is not None: update_config("smtp_password", settings.smtp_password)
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

@router.get("/version-check", response_model=VersionCheckResponse)
async def check_version(current_user = Depends(require_admin)):
    """
    Check for updates against the GitHub repository.
    """
    current_version = "1.0.0" 
    latest_version = current_version
    release_url = "https://github.com/Simon-CR/scr-pki/releases"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/repos/Simon-CR/scr-pki/releases/latest",
                timeout=5.0
            )
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("tag_name", "").lstrip("v")
                release_url = data.get("html_url")
    except Exception as e:
        logger.warning("Failed to check for updates", error=str(e))
        
    return VersionCheckResponse(
        current_version=current_version,
        latest_version=latest_version,
        update_available=latest_version != current_version,
        release_url=release_url
    )