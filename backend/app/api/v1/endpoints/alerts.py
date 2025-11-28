"""
Alert management endpoints.
"""

from datetime import datetime, timezone
from typing import Any, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import get_current_active_user, require_operator_or_admin
from app.core.config import settings
from app.core.database import get_db
from app.models.certificate import Certificate, CertificateStatus
from app.models.monitoring import CheckResult
from app.models.user import User
from app.models.alert import AlertAcknowledgment

logger = structlog.get_logger(__name__)

router = APIRouter()


class AlertResponse(BaseModel):
    """Alert response model."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    message: str
    alert_type: str
    severity: str
    status: str
    created_at: str
    resource_id: Optional[int] = None
    resource_type: Optional[str] = None


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """List dynamic alerts derived from certificate and monitoring data."""
    logger.info("Listing alerts", user_id=current_user.id, skip=skip, limit=limit)

    alerts: List[dict] = []

    active_certs = _get_certificates_by_status(db, CertificateStatus.ACTIVE)
    expired_certs = _get_certificates_by_status(db, CertificateStatus.EXPIRED)
    revoked_certs = _get_certificates_by_status(db, CertificateStatus.REVOKED)
    monitored_certs = (
        db.query(Certificate)
        .filter(Certificate.monitoring_enabled.is_(True))
        .all()
    )

    # Fetch acknowledgments
    acknowledgments = {
        ack.alert_key: ack 
        for ack in db.query(AlertAcknowledgment).all()
    }

    _append_expired_certificate_alerts(alerts, expired_certs, active_certs, acknowledgments)
    _append_expiring_certificate_alerts(alerts, active_certs, acknowledgments)
    _append_revoked_certificate_alerts(alerts, revoked_certs, acknowledgments)
    _append_monitoring_alerts(alerts, monitored_certs, acknowledgments)

    alerts.sort(key=lambda item: item["created_at"], reverse=True)

    start_idx = skip
    end_idx = skip + limit if limit else None
    paginated = alerts[start_idx:end_idx]

    for alert in paginated:
        alert["created_at"] = alert["created_at"].astimezone(timezone.utc).isoformat()

    logger.info("Retrieved alerts", count=len(paginated))
    return paginated


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_operator_or_admin)
) -> Any:
    """Acknowledge an alert."""
    alert_key = ""
    
    if 1000000 <= alert_id < 2000000:
        resource_id = alert_id - 1000000
        alert_key = f"cert_expiry_{resource_id}"
    elif 2000000 <= alert_id < 3000000:
        resource_id = alert_id - 2000000
        alert_key = f"cert_revoked_{resource_id}"
    elif 3000000 <= alert_id < 3500000:
        resource_id = alert_id - 3000000
        alert_key = f"monitoring_{resource_id}"
    elif 3500000 <= alert_id < 4000000:
        resource_id = alert_id - 3500000
        alert_key = f"monitoring_config_{resource_id}"
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid alert ID"
        )
        
    # Check if already acknowledged
    existing = db.query(AlertAcknowledgment).filter(
        AlertAcknowledgment.alert_key == alert_key
    ).first()
    
    if existing:
        return {"status": "already_acknowledged"}
        
    # Create acknowledgment
    ack = AlertAcknowledgment(
        alert_key=alert_key,
        acknowledged_by_id=current_user.id,
        acknowledged_at=datetime.now(timezone.utc)
    )
    db.add(ack)
    db.commit()
    
    logger.info("Alert acknowledged", alert_id=alert_id, key=alert_key, user=current_user.username)
    
    return {"status": "acknowledged"}


def _get_certificates_by_status(db: Session, status: CertificateStatus) -> List[Certificate]:
    return (
        db.query(Certificate)
        .filter(Certificate.status == status)
        .order_by(Certificate.not_valid_after.asc())
        .all()
    )


def _append_expired_certificate_alerts(
    alerts: List[dict],
    expired: List[Certificate],
    active: List[Certificate],
    acknowledgments: dict,
) -> None:
    now = _utcnow()

    for cert in expired:
        expires_at = _ensure_aware(cert.not_valid_after)
        updated_at = _ensure_aware(cert.updated_at)
        when = expires_at or updated_at or now
        _add_alert(
            alerts,
            title=f"Certificate expired: {cert.common_name}",
            message=f"{cert.common_name} expired on {_human_timestamp(when)}.",
            alert_type="certificate_expiry",
            severity="critical",
            created_at=when,
            resource_id=cert.id,
            resource_type="certificate",
            acknowledgments=acknowledgments,
        )

    for cert in active:
        expires_at = _ensure_aware(cert.not_valid_after)
        if not expires_at:
            continue
        if expires_at >= now:
            continue
        _add_alert(
            alerts,
            title=f"Certificate overdue: {cert.common_name}",
            message=f"Validity ended on {_human_timestamp(expires_at)} but status is still active.",
            alert_type="certificate_expiry",
            severity="critical",
            created_at=expires_at,
            resource_id=cert.id,
            resource_type="certificate",
            acknowledgments=acknowledgments,
        )


def _append_expiring_certificate_alerts(
    alerts: List[dict], 
    active: List[Certificate],
    acknowledgments: dict
) -> None:
    for cert in active:
        if not cert.not_valid_after:
            continue
        days = cert.days_until_expiry
        if days <= 0:
            continue
        window = _select_expiry_window(days)
        if not window:
            continue
        threshold, severity = window
        plural = "s" if days != 1 else ""
        message = f"{cert.common_name} expires in {days} day{plural} (within {threshold}-day alert window)."
        _add_alert(
            alerts,
            title=f"Certificate expiring soon: {cert.common_name}",
            message=message,
            alert_type="certificate_expiry",
            severity=severity,
            created_at=cert.updated_at or _utcnow(),
            resource_id=cert.id,
            resource_type="certificate",
            acknowledgments=acknowledgments,
        )


def _append_revoked_certificate_alerts(
    alerts: List[dict], 
    revoked: List[Certificate],
    acknowledgments: dict
) -> None:
    for cert in revoked:
        _add_alert(
            alerts,
            title=f"Certificate revoked: {cert.common_name}",
            message=f"Certificate revoked on {_human_timestamp(cert.revoked_at)}.",
            alert_type="certificate_revoked",
            severity="warning",
            status="active",
            created_at=cert.revoked_at,
            resource_id=cert.id,
            resource_type="certificate",
            acknowledgments=acknowledgments,
        )


def _append_monitoring_alerts(
    alerts: List[dict], 
    monitored: List[Certificate],
    acknowledgments: dict
) -> None:
    if not monitored:
        return

    for cert in monitored:
        if cert.status == CertificateStatus.REVOKED:
            _add_alert(
                alerts,
                title=f"Monitoring still enabled: {cert.common_name}",
                message="Disable monitoring or remove the endpoint for revoked certificates.",
                alert_type="monitoring_configuration",
                severity="info",
                created_at=cert.updated_at,
                resource_id=cert.id,
                resource_type="certificate",
                acknowledgments=acknowledgments,
            )
            continue

        # Use stored monitoring results instead of performing live checks
        if not cert.monitoring_services:
            continue

        for service in cert.monitoring_services:
            if not service.last_check_result:
                continue

            timestamp = service.last_check_at or _utcnow()
            
            if service.last_check_result == CheckResult.FAILURE:
                _add_alert(
                    alerts,
                    title=f"Monitoring failure: {cert.common_name}",
                    message=f"Check failed: {service.last_error_message or 'Unknown error'}",
                    alert_type="monitoring_error",
                    severity="critical",
                    created_at=timestamp,
                    resource_id=service.id,
                    resource_type="monitoring_service",
                    acknowledgments=acknowledgments,
                )
            elif service.last_check_result == CheckResult.WARNING:
                _add_alert(
                    alerts,
                    title=f"Monitoring warning: {cert.common_name}",
                    message=f"Warning: {service.last_error_message or 'Check warning'}",
                    alert_type="monitoring_warning",
                    severity="warning",
                    created_at=timestamp,
                    resource_id=service.id,
                    resource_type="monitoring_service",
                    acknowledgments=acknowledgments,
                )
            elif service.last_check_result == CheckResult.ERROR:
                _add_alert(
                    alerts,
                    title=f"Monitoring error: {cert.common_name}",
                    message=f"System error during check: {service.last_error_message or 'Unknown error'}",
                    alert_type="monitoring_error",
                    severity="warning",
                    created_at=timestamp,
                    resource_id=service.id,
                    resource_type="monitoring_service",
                    acknowledgments=acknowledgments,
                )


def _select_expiry_window(days_until_expiry: int) -> Optional[tuple[int, str]]:
    windows = [
        (1, settings.ALERT_EXPIRY_1_DAY, "critical"),
        (7, settings.ALERT_EXPIRY_7_DAYS, "warning"),
        (14, settings.ALERT_EXPIRY_14_DAYS, "warning"),
        (30, settings.ALERT_EXPIRY_30_DAYS, "info"),
    ]

    for window, enabled, severity in windows:
        if not enabled:
            continue
        if days_until_expiry <= window:
            return window, severity
    return None


def _add_alert(
    alerts: List[dict],
    *,
    title: str,
    message: str,
    alert_type: str,
    severity: str,
    status: str = "active",
    created_at: Optional[datetime] = None,
    resource_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    acknowledgments: dict = None,
) -> None:
    timestamp = _normalize_timestamp(created_at)
    
    # Generate stable ID and Key
    alert_id = 0
    alert_key = ""
    
    if alert_type == "certificate_expiry":
        alert_id = 1000000 + (resource_id or 0)
        alert_key = f"cert_expiry_{resource_id}"
    elif alert_type == "certificate_revoked":
        alert_id = 2000000 + (resource_id or 0)
        alert_key = f"cert_revoked_{resource_id}"
    elif alert_type.startswith("monitoring_"):
        if resource_type == "monitoring_service":
             alert_id = 3000000 + (resource_id or 0)
             alert_key = f"monitoring_{resource_id}"
        else:
             # monitoring_configuration (cert level)
             alert_id = 3500000 + (resource_id or 0)
             alert_key = f"monitoring_config_{resource_id}"
    else:
        # Fallback for unknown types
        alert_id = 9000000 + len(alerts)
        alert_key = f"unknown_{len(alerts)}"

    # Check acknowledgment
    ack_status = status
    ack_info = {}
    
    if acknowledgments and alert_key in acknowledgments:
        ack = acknowledgments[alert_key]
        ack_status = "acknowledged"
        ack_info = {
            "acknowledged_at": ack.acknowledged_at.isoformat(),
            "acknowledged_by": ack.acknowledged_by_id
        }

    alert_obj = {
        "id": alert_id,
        "title": title,
        "message": message,
        "alert_type": alert_type,
        "severity": severity.lower(),
        "status": ack_status,
        "created_at": timestamp,
        "resource_id": resource_id,
        "resource_type": resource_type,
    }
    alert_obj.update(ack_info)
    
    alerts.append(alert_obj)


def _human_timestamp(value: Optional[datetime]) -> str:
    ts = _ensure_aware(value) or _utcnow()
    return ts.strftime("%Y-%m-%d %H:%M UTC")


def _normalize_timestamp(value: Optional[datetime]) -> datetime:
    ts = _ensure_aware(value)
    if ts is not None:
        return ts
    return _utcnow()


def _ensure_aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)