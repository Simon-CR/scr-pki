"""
Configuration settings for the PKI Platform API.
Loads settings from environment variables with secure defaults.
"""

import json
from typing import List, Optional, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_list_field(v: Union[str, List[str], None], default: List[str] = None) -> List[str]:
    """Parse a list field from environment variable or value.
    
    Handles:
    - JSON arrays: '["a", "b", "c"]'
    - Comma-separated strings: 'a,b,c'
    - Empty strings: '' -> default or []
    - None: -> default or []
    - Already a list: returns as-is
    """
    if v is None or v == "":
        return default or []
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        v = v.strip()
        if not v:
            return default or []
        # Try JSON first
        if v.startswith("["):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                pass
        # Fall back to comma-separated
        return [item.strip() for item in v.split(",") if item.strip()]
    return default or []


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
        # Don't try to JSON parse env vars automatically
        env_parse_none_str="None",
    )
    
    # General Settings
    DEBUG: bool = False
    ENVIRONMENT: str = "production"
    SECRET_KEY: str
    LOG_LEVEL: str = "INFO"
    
    # ⚠️ SECURITY WARNING: AUTH_DISABLED
    # When set to True, ALL authentication is bypassed and every request
    # is treated as a fully privileged admin user. This is extremely dangerous
    # and should ONLY be used for local development or testing.
    # NEVER enable this in production environments!
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
    # Note: Apple/Safari requires TLS certs to be ≤398 days for full browser trust
    # Longer durations are allowed but may show warnings in browsers
    CERT_DEFAULT_VALIDITY_DAYS: int = 365  # 1 year (browser compliant default)
    CERT_DEFAULT_KEY_SIZE: int = 4096
    CERT_SIGNATURE_ALGORITHM: str = "SHA256"
    CERT_ALLOWED_KEY_SIZES: Union[str, List[int]] = [2048, 4096]
    
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
    
    # Password Policy (configurable for home lab flexibility)
    # Set these via environment variables to enforce stricter requirements
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = False
    PASSWORD_REQUIRE_LOWERCASE: bool = False
    PASSWORD_REQUIRE_DIGIT: bool = False
    PASSWORD_REQUIRE_SPECIAL: bool = False
    
    # CORS and Security
    # Accept both comma-separated strings and JSON arrays from environment variables
    CORS_ORIGINS: Union[str, List[str]] = ["http://localhost:3000", "https://localhost", "https://127.0.0.1", "http://127.0.0.1:3000"]
    ALLOWED_HOSTS: Union[str, List[str]] = [
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
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS_ORIGINS from comma-separated string or JSON array."""
        return parse_list_field(v, ["http://localhost:3000"])
    
    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v):
        """Parse ALLOWED_HOSTS from comma-separated string or JSON array."""
        return parse_list_field(v, ["localhost", "127.0.0.1", "backend", "pki_backend"])
    
    @field_validator("CERT_ALLOWED_KEY_SIZES", mode="before")
    @classmethod
    def parse_key_sizes(cls, v):
        """Parse CERT_ALLOWED_KEY_SIZES from comma-separated string or JSON array."""
        if v is None or v == "":
            return [2048, 4096]
        if isinstance(v, list):
            return [int(x) for x in v]
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return [2048, 4096]
            if v.startswith("["):
                try:
                    return [int(x) for x in json.loads(v)]
                except json.JSONDecodeError:
                    pass
            return [int(x.strip()) for x in v.split(",") if x.strip()]
        return [2048, 4096]
    
    @property
    def database_url(self) -> str:
        """Construct database URL from components."""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return f"postgresql+psycopg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
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