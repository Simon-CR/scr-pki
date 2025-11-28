"""
SCR-PKI Backend API
========================

A secure, web-based Certificate Authority platform for home lab environments.

Main Features:
- Certificate Authority management
- SSL/TLS certificate issuance and management
- Certificate monitoring and expiration alerts
- Service health monitoring
- HashiCorp Vault integration for secure key storage
- JWT-based authentication with RBAC
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
import structlog
import time
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import engine, init_db
from app.core.vault import vault_client
from app.core.rate_limit import limiter, rate_limit_exceeded_handler
from app.api.v1.api import api_router
from app.core.auth import get_current_user
from app.services.user_service import create_default_admin
from app.services.scheduler import scheduler_service

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle manager for FastAPI application.
    Handles startup and shutdown tasks.
    """
    # Startup
    logger.info("Starting SCR-PKI API")
    
    # Security warning for AUTH_DISABLED
    if settings.AUTH_DISABLED:
        logger.critical(
            "⚠️  SECURITY WARNING: AUTH_DISABLED=true - Authentication is completely bypassed! "
            "All requests will be treated as admin. DO NOT use in production!"
        )
        # Log to stderr as well for visibility
        import sys
        print("\n" + "="*80, file=sys.stderr)
        print("⚠️  CRITICAL SECURITY WARNING ⚠️", file=sys.stderr)
        print("AUTH_DISABLED=true is set - ALL AUTHENTICATION IS BYPASSED!", file=sys.stderr)
        print("Every request has full admin access. This is for development only.", file=sys.stderr)
        print("="*80 + "\n", file=sys.stderr)
    
    # Initialize database
    # Note: In production with multiple workers, this is handled by pre_start.py
    # to avoid race conditions. We keep it here for dev mode and safety.
    try:
        await init_db()
        logger.info("Database initialized")
    except Exception as e:
        # In production, this might fail if another worker is doing it, 
        # but pre_start.py should have handled it.
        logger.warning(f"Database initialization skipped or failed: {e}")
    
    # Create default admin user - DISABLED for fresh start experience
    # Enrollment is now handled via the /setup endpoint
    # await create_default_admin()
    
    # Initialize Vault connection
    # Try to connect again now that DB is initialized (in case token is stored there)
    if not vault_client.is_authenticated():
        vault_client.connect()

    if not vault_client.is_authenticated():
        if settings.VAULT_DEV_MODE:
            logger.warning("Vault dev mode enabled - continuing without Vault connection")
        else:
            # We don't raise an error here anymore, to allow the UI to configure the token
            logger.warning("Vault authentication failed - System requires configuration")
    else:
        logger.info("Vault connection established")
    
    # Start scheduler
    scheduler_service.start()
    logger.info("Scheduler started")

    logger.info("SCR-PKI API started successfully")
    
    yield
    
    # Shutdown
    scheduler_service.stop()
    logger.info("Shutting down SCR-PKI API")


# Create FastAPI application
app = FastAPI(
    title="SCR-PKI API",
    description=__doc__,
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if settings.ENVIRONMENT.lower() in {"production", "prod"}:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS
    )
else:
    logger.warning(
        "TrustedHostMiddleware disabled for %s environment",
        settings.ENVIRONMENT
    )


@app.middleware("http")
async def add_security_headers(request, call_next):
    """Add security headers to API responses (supplementary to nginx headers)."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    # Process time header
    response.headers["X-Process-Time"] = str(process_time)
    
    # Security headers (backup for direct API access, nginx handles these for proxied requests)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # X-XSS-Protection is deprecated and can cause issues; modern browsers use CSP instead
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    
    return response


@app.middleware("http")
async def log_requests(request, call_next):
    """Log all HTTP requests for audit purposes."""
    start_time = time.time()
    
    # Log request
    logger.info(
        "HTTP request started",
        method=request.method,
        url=str(request.url),
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    
    response = await call_next(request)
    
    # Log response
    duration = time.time() - start_time
    logger.info(
        "HTTP request completed",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        duration=f"{duration:.4f}s",
    )
    
    return response


# Health check endpoint
@app.get("/health")
@limiter.limit("60/minute")
async def health_check(request: Request):
    """
    Health check endpoint for load balancers and monitoring.
    Rate limited to prevent abuse.
    
    Returns:
        dict: Health status and system information
    """
    try:
        # Check database connection
        from app.core.database import SessionLocal
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        database_status = "healthy"
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        database_status = "unhealthy"
    
    # Check Vault connection
    try:
        vault_status = "healthy" if vault_client.is_authenticated() else "unhealthy"
    except Exception as e:
        logger.error("Vault health check failed", error=str(e))
        vault_status = "unhealthy"
    
    overall_status = "healthy" if all([
        database_status == "healthy",
        vault_status == "healthy"
    ]) else "unhealthy"
    
    return {
        "status": overall_status,
        "timestamp": time.time(),
        "version": "1.0.0",
        "components": {
            "database": database_status,
            "vault": vault_status
        }
    }


# Root endpoint
@app.get("/")
async def root():
    """
    Root endpoint with API information.
    """
    return {
        "message": "SCR-PKI API",
        "version": "1.0.0",
        "docs_url": "/docs" if settings.DEBUG else None,
        "health_url": "/health"
    }


# Include API router
app.include_router(api_router, prefix="/api/v1")


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    Global exception handler for unhandled errors.
    """
    logger.error(
        "Unhandled exception",
        error=str(exc),
        error_type=type(exc).__name__,
        url=str(request.url),
        method=request.method,
        exc_info=True
    )
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "timestamp": time.time()
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )