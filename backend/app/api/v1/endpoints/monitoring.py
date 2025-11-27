"""
Monitoring service endpoints.
"""

from datetime import datetime
from typing import Any, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import get_current_active_user, require_operator_or_admin
from app.core.database import get_db
from app.models.certificate import Certificate, CertificateStatus
from app.models.user import User
from app.services.monitoring_verifier import verify_remote_certificate

logger = structlog.get_logger(__name__)

router = APIRouter()


class MonitoringOverview(BaseModel):
    """Monitoring overview response."""
    total_services: int
    services_up: int
    services_down: int
    average_uptime: float


@router.get("/", response_model=MonitoringOverview)
async def get_monitoring_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """Get monitoring overview for dashboard."""
    logger.info("Getting monitoring overview", user_id=current_user.id)

    services = _query_monitored_certificates(db)
    total = len(services)
    services_up = len([cert for cert in services if cert.status == CertificateStatus.ACTIVE])
    services_down = total - services_up
    average_uptime = (services_up / total * 100.0) if total else 100.0

    overview = {
        "total_services": total,
        "services_up": services_up,
        "services_down": services_down,
        "average_uptime": round(average_uptime, 1),
    }

    logger.info("Retrieved monitoring overview", **overview)
    return overview


class ServiceResponse(BaseModel):
    """Monitoring service response model."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    certificate_id: int
    name: str
    url: str
    port: Optional[int] = None
    status: str
    last_check_result: Optional[str]
    uptime_percentage: float
    certificate_status: str
    expires_at: Optional[datetime]
    days_until_expiry: int
    serial_number: str
    certificate_match: Optional[bool] = None
    observed_serial_number: Optional[str] = None
    last_verified_at: Optional[datetime] = None
    verification_error: Optional[str] = None


import asyncio
from concurrent.futures import ThreadPoolExecutor

@router.get("/services", response_model=List[ServiceResponse])
async def list_services(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """List all monitored services."""
    logger.info("Listing monitored services", user_id=current_user.id)
    certificates = _query_monitored_certificates(db)
    
    # Run checks in parallel using a thread pool to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=10) as executor:
        tasks = [
            loop.run_in_executor(executor, _serialize_certificate_monitor, cert)
            for cert in certificates
        ]
        services = await asyncio.gather(*tasks)
        
    logger.info("Retrieved monitored services", count=len(services))
    return services


@router.post("/services/{service_id}/check")
async def trigger_manual_check(
    service_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_operator_or_admin)
) -> Any:
    """Trigger manual health check for a service."""
    # TODO: Implement manual check trigger once monitoring workers exist
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Manual check trigger not yet implemented"
    )


def _query_monitored_certificates(db: Session) -> List[Certificate]:
    return (
        db.query(Certificate)
        .filter(Certificate.monitoring_enabled.is_(True))
        .order_by(Certificate.common_name.asc())
        .all()
    )


def _serialize_certificate_monitor(cert: Certificate) -> dict:
    status = _status_from_certificate(cert)
    verification = verify_remote_certificate(cert)
    return {
        "id": cert.id,
        "certificate_id": cert.id,
        "name": cert.common_name,
        "url": cert.monitoring_target_url or cert.common_name,
        "port": cert.monitoring_target_port,
        "status": status,
        "last_check_result": _build_last_check_result(cert, verification),
        "uptime_percentage": 100.0 if cert.status == CertificateStatus.ACTIVE else 0.0,
        "certificate_status": cert.status.value,
        "expires_at": cert.not_valid_after,
        "days_until_expiry": cert.days_until_expiry,
        "serial_number": cert.serial_number,
        "certificate_match": verification["certificate_match"],
        "observed_serial_number": verification["observed_serial_number"],
        "last_verified_at": verification["last_verified_at"],
        "verification_error": verification["verification_error"],
    }


def _status_from_certificate(cert: Certificate) -> str:
    if cert.status == CertificateStatus.ACTIVE:
        return "up"
    if cert.status == CertificateStatus.REVOKED:
        return "down"
    return "pending"


def _build_last_check_result(cert: Certificate, verification: dict) -> str:
    if verification["verification_error"]:
        return f"Verification failed: {verification['verification_error']}"
    if verification["certificate_match"] is True:
        return "Remote endpoint presents the assigned certificate."
    if verification["certificate_match"] is False and verification["observed_serial_number"]:
        return f"Serial mismatch observed ({verification['observed_serial_number']})."
    if verification["certificate_match"] is False:
        return "Remote certificate could not be confirmed."
    if cert.status == CertificateStatus.ACTIVE:
        return "Certificate active"
    if cert.status == CertificateStatus.EXPIRED:
        return "Certificate expired"
    if cert.status == CertificateStatus.REVOKED:
        return "Certificate revoked"
    return "Pending activation"