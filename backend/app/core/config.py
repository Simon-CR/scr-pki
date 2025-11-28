"""
Configuration settings for the PKI Platform API.
Loads settings from environment variables with secure defaults.
"""

from typing import List, Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")
    
    # General Settings
    DEBUG: bool = False
    ENVIRONMENT: str = "production"
    SECRET_KEY: str
    LOG_LEVEL: str = "INFO"
    AUTH_DISABLED: bool = False
    
    # Web Interface Settings
    DOMAIN: str = "localhost"
    HTTP_PORT: int = 80
    HTTPS_PORT: int = 443
    
    # Database Settings
    DATABASE_URL: Optional[str] = None
    DB_HOST: str = "postgres"
    DB_PORT: int = 5432
    DB_NAME: str = "pki_platform"
    DB_USER: str
    DB_PASSWORD: str
    
    # Vault Settings
    VAULT_ADDR: str = "http://vault:8200"
    VAULT_TOKEN: Optional[str] = None
    VAULT_ROLE_ID: Optional[str] = None
    VAULT_SECRET_ID: Optional[str] = None
    VAULT_DEV_MODE: bool = False
    VAULT_CA_PATH: str = "pki/ca"
    VAULT_CERT_PATH: str = "pki/certs"
    
    # Certificate Authority Settings
    CA_COMMON_NAME: str = "Home Lab Root CA"
    CA_ORGANIZATION: str = "Home Lab"
    CA_ORGANIZATIONAL_UNIT: str = "Certificate Authority"
    CA_COUNTRY: str = "US"
    CA_STATE: str = "State"
    CA_LOCALITY: str = "City"
    CA_EMAIL: str = "admin@homelab.local"
    CA_VALIDITY_DAYS: int = 7300  # 20 years
    
    # Certificate Default Settings
    CERT_DEFAULT_VALIDITY_DAYS: int = 3650  # 10 years
    CERT_DEFAULT_KEY_SIZE: int = 4096
    CERT_SIGNATURE_ALGORITHM: str = "SHA256"
    CERT_ALLOWED_KEY_SIZES: List[int] = [2048, 4096]
    
    # Authentication Settings
    # ADMIN_USERNAME/PASSWORD/EMAIL removed - enrollment is done via UI on first start
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "RS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_TIMEOUT_MINUTES: int = 60
    
    # Rate Limiting
    RATE_LIMIT_PER_IP_HOUR: int = 100
    RATE_LIMIT_PER_USER_HOUR: int = 500
    RATE_LIMIT_CERT_ISSUE_HOUR: int = 10
    
    # CORS and Security
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "https://localhost", "https://127.0.0.1", "http://127.0.0.1:3000"]
    ALLOWED_HOSTS: List[str] = [
        "localhost",
        "localhost:3000",
        "localhost:8000",
        "127.0.0.1",
        "127.0.0.1:3000",
        "127.0.0.1:8000",
        "backend",
        "backend:8000",
        "pki_backend",
        "pki_backend:8000",
        "testserver"
    ]
    
    # Monitoring Settings
    MONITORING_CHECK_INTERVAL: int = 300  # 5 minutes
    MONITORING_TIMEOUT: int = 10
    MONITORING_RETRY_COUNT: int = 3
    MONITORING_ENABLED: bool = True
    
    # Alert Settings
    ALERT_EXPIRY_30_DAYS: bool = True
    ALERT_EXPIRY_14_DAYS: bool = True
    ALERT_EXPIRY_7_DAYS: bool = True
    ALERT_EXPIRY_1_DAY: bool = True
    ALERT_HEALTH_CHECK_FAILURE: bool = True
    ALERT_SERVICE_DOWN: bool = True
    
    # Email Settings
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USE_TLS: bool = True
    SMTP_FROM_EMAIL: str = "noreply@homelab.local"
    SMTP_FROM_NAME: str = "SCR-PKI"
    
    # Webhook Settings
    WEBHOOK_SLACK_URL: Optional[str] = None
    WEBHOOK_DISCORD_URL: Optional[str] = None
    WEBHOOK_CUSTOM_URL: Optional[str] = None
    
    # Pushover Settings
    PUSHOVER_TOKEN: Optional[str] = None
    PUSHOVER_USER_KEY: Optional[str] = None
    
    # Backup Settings
    BACKUP_ENABLED: bool = True
    BACKUP_SCHEDULE: str = "0 2 * * *"  # Daily at 2 AM
    BACKUP_RETENTION_DAYS: int = 30
    BACKUP_S3_ENABLED: bool = False
    BACKUP_S3_BUCKET: Optional[str] = None
    BACKUP_S3_ACCESS_KEY: Optional[str] = None
    BACKUP_S3_SECRET_KEY: Optional[str] = None
    
    # Advanced Settings
    WORKERS: int = 1
    MAX_CONNECTIONS: int = 100
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    CACHE_TTL: int = 300
    API_REQUEST_TIMEOUT: int = 30
    
    @field_validator("CORS_ORIGINS", mode="before")
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v
    
    @field_validator("ALLOWED_HOSTS", mode="before")
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v
    
    @field_validator("CERT_ALLOWED_KEY_SIZES", mode="before")
    def parse_key_sizes(cls, v):
        if isinstance(v, str):
            return [int(i.strip()) for i in v.split(",")]
        return v
    
    @property
    def database_url(self) -> str:
        """Construct database URL from components."""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    @property
    def async_database_url(self) -> str:
        """Construct async database URL for SQLAlchemy."""
        if self.DATABASE_URL:
            if self.DATABASE_URL.startswith("sqlite"):
                return self.DATABASE_URL.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
            if self.DATABASE_URL.startswith("postgresql+asyncpg"):
                return self.DATABASE_URL
            if self.DATABASE_URL.startswith("postgresql"):
                return self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
            return self.DATABASE_URL
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"


# Create global settings instance
settings = Settings()