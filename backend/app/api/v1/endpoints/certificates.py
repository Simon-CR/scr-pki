"""Certificate management endpoints backed by certificate_service."""

from datetime import datetime
from typing import Any, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from app.core.auth import get_current_active_user, require_operator_or_admin
from app.core.database import get_db
from app.models.certificate import Certificate, CertificateStatus, CertificateType
from app.models.user import User, UserRole
from app.services.certificate_service import certificate_service
from app.services.ca_service import ca_service

logger = structlog.get_logger(__name__)

router = APIRouter()


class CertificateIssueRequest(BaseModel):
    """Certificate issuance request model."""

    common_name: str
    certificate_type: str = "server"
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: str = "US"
    state: Optional[str] = None
    locality: Optional[str] = None
    email: Optional[str] = None
    subject_alt_names: List[str] = Field(default_factory=list)
    validity_days: Optional[int] = Field(default=None, ge=1)
    key_size: Optional[int] = Field(default=None, ge=2048)
    deployment_locations: Optional[List[str]] = None
    notes: Optional[str] = None
    monitoring_enabled: bool = False
    monitoring_target_url: Optional[str] = None
    monitoring_target_port: Optional[int] = Field(default=None, ge=1, le=65535)
    monitoring_channels: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_monitoring(cls, values: "CertificateIssueRequest") -> "CertificateIssueRequest":
        if values.monitoring_enabled and not values.monitoring_target_url:
            raise ValueError("Monitoring target URL is required when monitoring is enabled")
        return values


class CertificateRenewRequest(BaseModel):
    """Certificate renewal request."""

    validity_days: Optional[int] = Field(default=None, ge=1)


class CertificateRevokeRequest(BaseModel):
    """Certificate revocation request."""

    reason: Optional[str] = Field(default="unspecified", max_length=255)


class CertificateMonitoringRequest(BaseModel):
    """Monitoring preference update payload."""

    monitoring_enabled: bool
    monitoring_target_url: Optional[str] = None
    monitoring_target_port: Optional[int] = Field(default=None, ge=1, le=65535)
    monitoring_channels: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_monitoring(cls, values: "CertificateMonitoringRequest") -> "CertificateMonitoringRequest":
        if values.monitoring_enabled and not values.monitoring_target_url:
            raise ValueError("Monitoring target URL is required when monitoring is enabled")
        return values


class CertificateResponse(BaseModel):
    """Certificate response model."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    common_name: str
    subject_alt_names: List[str]
    status: str
    certificate_type: str
    serial_number: str
    key_size: int
    signature_algorithm: str
    issued_at: Optional[datetime] = None
    not_valid_before: Optional[datetime] = None
    not_valid_after: Optional[datetime] = None
    days_until_expiry: int
    deployment_locations: List[str]
    issuer_ca_id: Optional[int] = None
    issuer_common_name: Optional[str] = None
    created_by_user_id: Optional[int] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    pem_available: bool = True
    monitoring_enabled: bool
    monitoring_target_url: Optional[str] = None
    monitoring_target_port: Optional[int] = None
    monitoring_channels: List[str]


def _parse_certificate_status(value: Optional[str]) -> Optional[CertificateStatus]:
    """Convert status query parameter to CertificateStatus."""
    if value is None or value.lower() == "all":
        return None

    try:
        return CertificateStatus(value.lower())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid certificate status") from exc


def _parse_certificate_type(value: Optional[str]) -> Optional[CertificateType]:
    """Convert certificate type string to CertificateType."""
    if value is None:
        return None
    try:
        return CertificateType(value.lower())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid certificate type") from exc


def _serialize_certificate(cert: Certificate) -> CertificateResponse:
    """Serialize ORM certificate to API response."""
    deployment_locations = cert.get_deployment_locations_list()
    issuer_common_name = cert.issuer_ca.common_name if cert.issuer_ca else None
    return CertificateResponse(
        id=cert.id,
        common_name=cert.common_name,
        subject_alt_names=cert.get_subject_alt_names_list(),
        status=cert.status.value,
        certificate_type=cert.certificate_type.value,
        serial_number=cert.serial_number,
        key_size=cert.key_size,
        signature_algorithm=cert.signature_algorithm,
        issued_at=cert.issued_at or cert.created_at,
        not_valid_before=cert.not_valid_before,
        not_valid_after=cert.not_valid_after,
        days_until_expiry=cert.days_until_expiry,
        deployment_locations=deployment_locations,
        issuer_ca_id=cert.issuer_ca_id,
        issuer_common_name=issuer_common_name,
        created_by_user_id=cert.created_by,
        revoked_at=cert.revoked_at,
        revocation_reason=cert.revocation_reason,
        pem_available=bool(cert.pem_certificate),
        monitoring_enabled=cert.monitoring_enabled,
        monitoring_target_url=cert.monitoring_target_url,
        monitoring_target_port=cert.monitoring_target_port,
        monitoring_channels=cert.get_monitoring_channels(),
    )


@router.get("/", response_model=List[CertificateResponse])
async def list_certificates(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    certificate_type: Optional[str] = None,
    search: Optional[str] = None,
    expiring_days: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """List certificates with optional filtering."""
    logger.info(
        "Listing certificates",
        user_id=current_user.id,
        skip=skip,
        limit=limit,
        status=status_filter,
        certificate_type=certificate_type,
        search=search,
        expiring_days=expiring_days,
    )

    status_enum = _parse_certificate_status(status_filter)
    type_enum = _parse_certificate_type(certificate_type)

    # Filter by user if not admin
    user_id_filter = None
    if current_user.role != UserRole.ADMIN:
        user_id_filter = current_user.id

    certificates = certificate_service.list_certificates(
        db=db,
        skip=skip,
        limit=min(limit, 500),
        status=status_enum,
        certificate_type=type_enum,
        search=search,
        expiring_days=expiring_days,
        user_id=user_id_filter
    )

    return [_serialize_certificate(cert) for cert in certificates]


@router.post("/issue", response_model=CertificateResponse, status_code=status.HTTP_201_CREATED)
async def issue_certificate(
    request: CertificateIssueRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_operator_or_admin),
) -> CertificateResponse:
    """Issue a new certificate."""
    logger.info(
        "Issuing certificate",
        common_name=request.common_name,
        cert_type=request.certificate_type,
        user_id=current_user.id,
    )

    certificate_type_enum = _parse_certificate_type(request.certificate_type) or CertificateType.SERVER

    try:
        certificate = certificate_service.issue_certificate(
            db=db,
            common_name=request.common_name,
            subject_alt_names=request.subject_alt_names,
            certificate_type=certificate_type_enum,
            key_size=request.key_size,
            validity_days=request.validity_days,
            deployment_locations=request.deployment_locations,
            notes=request.notes,
            created_by_user_id=current_user.id,
            monitoring_enabled=request.monitoring_enabled,
            monitoring_target_url=request.monitoring_target_url,
            monitoring_target_port=request.monitoring_target_port,
            monitoring_channels=request.monitoring_channels,
        )
    except ValueError as exc:
        logger.error("Certificate issuance failed", error=str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    logger.info("Certificate issued successfully", certificate_id=certificate.id)
    return _serialize_certificate(certificate)


@router.get("/{certificate_id}", response_model=CertificateResponse)
async def get_certificate(
    certificate_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> CertificateResponse:
    """Get certificate details."""
    cert = certificate_service.get_certificate_details(db, certificate_id)
    if not cert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")

    return _serialize_certificate(cert)


@router.get("/{certificate_id}/download")
async def download_certificate(
    certificate_id: int,
    include_chain: bool = True,
    include_private_key: bool = False,
    include_leaf_certificate: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Response:
    """Download a certificate PEM bundle (leaf, optional private key, optional chain)."""
    cert = certificate_service.get_certificate_details(db, certificate_id)
    if not cert or not cert.pem_certificate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")

    private_key_pem: Optional[str] = None
    if include_private_key:
        private_key_pem = certificate_service.export_private_key_pem(cert)
        if not private_key_pem:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Certificate private key not available for download",
            )

    chain_pem: Optional[str] = None
    if include_chain and cert.issuer_ca:
        chain_pem = ca_service.build_certificate_chain(cert.issuer_ca) or None

    bundle_parts = []
    if private_key_pem:
        bundle_parts.append(private_key_pem.strip())
    
    if include_leaf_certificate:
        bundle_parts.append(cert.pem_certificate.strip())
        
    if chain_pem:
        bundle_parts.append(chain_pem.strip())

    pem_bundle = "\n".join(part for part in bundle_parts if part).strip() + "\n"

    # Determine filename based on content
    if include_private_key and not include_leaf_certificate and not include_chain:
        suffix = "key"
    elif not include_private_key and include_leaf_certificate and not include_chain:
        suffix = "crt"
    else:
        suffix = "pem"

    filename = f"{cert.common_name.replace(' ', '_')}_{cert.serial_number}.{suffix}"
    headers = {"Content-Disposition": f"attachment; filename=\"{filename}\""}

    logger.info(
        "Certificate downloaded",
        certificate_id=certificate_id,
        include_chain=include_chain,
        include_private_key=bool(private_key_pem),
        user_id=current_user.id,
    )

    return Response(content=pem_bundle, media_type="application/x-pem-file", headers=headers)


@router.post("/{certificate_id}/revoke")
async def revoke_certificate(
    certificate_id: int,
    request: Optional[CertificateRevokeRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_operator_or_admin),
) -> Any:
    """Revoke a certificate."""
    reason = request.reason if request and request.reason else "unspecified"
    logger.info("Revoking certificate", certificate_id=certificate_id, user_id=current_user.id, reason=reason)

    try:
        certificate_service.revoke_certificate(
            db=db,
            certificate_id=certificate_id,
            reason=reason,
            created_by_user_id=current_user.id,
        )
    except ValueError as exc:
        logger.error("Failed to revoke certificate", error=str(exc), certificate_id=certificate_id)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid certificate status") from exc

    return {"message": f"Certificate {certificate_id} revoked successfully"}


@router.post("/{certificate_id}/renew", response_model=CertificateResponse)
async def renew_certificate(
    certificate_id: int,
    request: Optional[CertificateRenewRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_operator_or_admin),
) -> CertificateResponse:
    """Renew a certificate."""
    logger.info("Renewing certificate", certificate_id=certificate_id, user_id=current_user.id)

    validity_days = request.validity_days if request else None

    try:
        renewed = certificate_service.renew_certificate(
            db=db,
            certificate_id=certificate_id,
            validity_days=validity_days,
            created_by_user_id=current_user.id,
        )
    except ValueError as exc:
        logger.error("Failed to renew certificate", error=str(exc), certificate_id=certificate_id)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid certificate status") from exc

    logger.info("Certificate renewed successfully", certificate_id=renewed.id)
    return _serialize_certificate(renewed)


@router.delete("/{certificate_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_certificate(
    certificate_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_operator_or_admin),
) -> None:
    """Permanently delete a certificate that is no longer active."""

    logger.info("Deleting certificate", certificate_id=certificate_id, user_id=current_user.id)

    try:
        certificate_service.delete_certificate(
            db=db,
            certificate_id=certificate_id,
            created_by_user_id=current_user.id,
        )
    except ValueError as exc:
        logger.error("Failed to delete certificate", error=str(exc), certificate_id=certificate_id)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.put("/{certificate_id}/monitoring", response_model=CertificateResponse)
async def update_certificate_monitoring(
    certificate_id: int,
    request: CertificateMonitoringRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_operator_or_admin),
) -> CertificateResponse:
    """Enable or disable monitoring for a certificate."""

    try:
        cert = certificate_service.update_monitoring_preferences(
            db=db,
            certificate_id=certificate_id,
            monitoring_enabled=request.monitoring_enabled,
            monitoring_target_url=request.monitoring_target_url,
            monitoring_target_port=request.monitoring_target_port,
            monitoring_channels=request.monitoring_channels,
        )
    except ValueError as exc:
        logger.error("Failed to update certificate monitoring", error=str(exc), certificate_id=certificate_id)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return _serialize_certificate(cert)

