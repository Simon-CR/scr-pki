"""
Main API router for v1 endpoints.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, ca, certificates, monitoring, users, alerts, setup, system

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(setup.router, prefix="/setup", tags=["setup"])
api_router.include_router(system.router, prefix="/system", tags=["system"])
api_router.include_router(ca.router, prefix="/ca", tags=["certificate-authority"])
api_router.include_router(certificates.router, prefix="/certificates", tags=["certificates"])
api_router.include_router(monitoring.router, prefix="/monitoring", tags=["monitoring"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(users.router, prefix="/users", tags=["users"])