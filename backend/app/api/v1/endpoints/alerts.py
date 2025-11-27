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

    _append_expired_certificate_alerts(alerts, expired_certs, active_certs)
    _append_expiring_certificate_alerts(alerts, active_certs)
    _append_revoked_certificate_alerts(alerts, revoked_certs)
    _append_monitoring_alerts(alerts, monitored_certs)

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
    # TODO: Implement alert acknowledgment
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Alert acknowledgment not yet implemented"
    )


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
        )


def _append_expiring_certificate_alerts(alerts: List[dict], active: List[Certificate]) -> None:
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
        )


def _append_revoked_certificate_alerts(alerts: List[dict], revoked: List[Certificate]) -> None:
    for cert in revoked:
        _add_alert(
            alerts,
            title=f"Certificate revoked: {cert.common_name}",
            message=f"Certificate revoked on {_human_timestamp(cert.revoked_at)}.",
            alert_type="certificate_revoked",
            severity="warning",
            status="active",
            created_at=cert.revoked_at,
        )


def _append_monitoring_alerts(alerts: List[dict], monitored: List[Certificate]) -> None:
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
                )
            elif service.last_check_result == CheckResult.WARNING:
                _add_alert(
                    alerts,
                    title=f"Monitoring warning: {cert.common_name}",
                    message=f"Warning: {service.last_error_message or 'Check warning'}",
                    alert_type="monitoring_warning",
                    severity="warning",
                    created_at=timestamp,
                )
            elif service.last_check_result == CheckResult.ERROR:
                _add_alert(
                    alerts,
                    title=f"Monitoring error: {cert.common_name}",
                    message=f"System error during check: {service.last_error_message or 'Unknown error'}",
                    alert_type="monitoring_error",
                    severity="warning",
                    created_at=timestamp,
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
) -> None:
    timestamp = _normalize_timestamp(created_at)
    alerts.append(
        {
            "id": len(alerts) + 1,
            "title": title,
            "message": message,
            "alert_type": alert_type,
            "severity": severity.lower(),
            "status": status,
            "created_at": timestamp,
        }
    )


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