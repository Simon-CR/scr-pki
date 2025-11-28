"""
Token blacklist for tracking revoked JWT tokens.

Uses in-memory storage with automatic expiration cleanup.
For production cluster deployments, consider using Redis.
"""

from datetime import datetime, timezone, timedelta
from typing import Set, Dict
import threading
import structlog

logger = structlog.get_logger(__name__)


class TokenBlacklist:
    """
    Thread-safe in-memory token blacklist.
    
    Stores token JTI (JWT ID) claims with their expiration times.
    Automatically cleans up expired entries to prevent memory leaks.
    """
    
    def __init__(self):
        self._blacklist: Dict[str, datetime] = {}
        self._lock = threading.Lock()
        
    def add(self, jti: str, expires_at: datetime) -> None:
        """
        Add a token JTI to the blacklist.
        
        Args:
            jti: JWT ID (unique token identifier)
            expires_at: When the token expires (for cleanup)
        """
        with self._lock:
            self._blacklist[jti] = expires_at
            self._cleanup()
            logger.info("Token blacklisted", jti=jti)
    
    def is_blacklisted(self, jti: str) -> bool:
        """
        Check if a token JTI is blacklisted.
        
        Args:
            jti: JWT ID to check
            
        Returns:
            bool: True if token is blacklisted
        """
        with self._lock:
            return jti in self._blacklist
    
    def _cleanup(self) -> None:
        """Remove expired entries from blacklist."""
        now = datetime.now(timezone.utc)
        expired = [jti for jti, exp in self._blacklist.items() if exp < now]
        for jti in expired:
            del self._blacklist[jti]
        if expired:
            logger.debug("Cleaned up expired blacklist entries", count=len(expired))
    
    def size(self) -> int:
        """Get the current size of the blacklist."""
        with self._lock:
            return len(self._blacklist)


# Global blacklist instance
token_blacklist = TokenBlacklist()
