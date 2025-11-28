"""
Rate limiting configuration for the API.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
import structlog

logger = structlog.get_logger(__name__)


def get_real_client_ip(request: Request) -> str:
    """
    Get the real client IP, accounting for reverse proxies.
    Checks X-Real-IP and X-Forwarded-For headers.
    """
    # X-Real-IP is set by nginx
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # X-Forwarded-For may contain multiple IPs
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (original client)
        return forwarded_for.split(",")[0].strip()
    
    # Fall back to direct connection
    return get_remote_address(request)


# Create limiter instance
limiter = Limiter(
    key_func=get_real_client_ip,
    default_limits=["1000/hour"],  # Default rate limit
    storage_uri="memory://",  # Use in-memory storage (consider Redis for production cluster)
)


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Custom handler for rate limit exceeded errors."""
    logger.warning(
        "Rate limit exceeded",
        client_ip=get_real_client_ip(request),
        path=request.url.path,
        limit=str(exc.detail),
    )
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Rate limit exceeded. Please try again later.",
            "retry_after": exc.detail
        },
        headers={"Retry-After": str(exc.detail) if exc.detail else "60"}
    )


# Rate limit decorators for specific endpoints
# Usage: @limiter.limit("5/minute")

# Predefined rate limits for different endpoint types
RATE_LIMITS = {
    "auth_login": "5/minute",           # Login attempts
    "auth_register": "3/minute",        # Registration
    "setup": "3/minute",                # Initial setup
    "password_reset": "3/minute",       # Password reset requests
    "certificate_issue": "30/minute",   # Certificate operations
    "api_default": "100/minute",        # Default API rate
    "health": "60/minute",              # Health checks
}
