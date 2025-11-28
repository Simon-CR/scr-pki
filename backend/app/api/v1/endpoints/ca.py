"""Certificate Authority endpoints for CA management."""

from datetime import datetime
from typing import Any, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.auth import get_current_active_user, require_admin
from app.core.database import get_db
from app.models.user import User
from app.services.ca_service import ca_service

logger = structlog.get_logger(__name__)

router = APIRouter()


class CAInfo(BaseModel):
    """CA information response model."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    common_name: str
    organization: str
    organizational_unit: Optional[str] = None
    country: str
    state: Optional[str] = None
    locality: Optional[str] = None
    email: Optional[str] = None
    status: str
    serial_number: str
    not_valid_before: Optional[datetime] = None
    not_valid_after: Optional[datetime] = None
    issued_certificates_count: int
    is_root: bool
    is_offline: bool
    parent_ca_id: Optional[int] = None
    child_count: int
    days_until_expiry: int


class CAHierarchyResponse(BaseModel):
    """Full CA hierarchy response model."""

    root_ca: Optional[CAInfo]
    intermediate_cas: List[CAInfo] = []


class CAInitializeRequest(BaseModel):
    """Payload for initializing CA hierarchy."""

    common_name: str = Field(..., description="Root CA common name")
    organization: str
    organizational_unit: Optional[str] = None
    country: str = "US"
    state: Optional[str] = None
    locality: Optional[str] = None
    email: Optional[str] = None
    validity_days: Optional[int] = Field(None, ge=365)
    key_size: Optional[int] = Field(None, ge=2048)
    create_intermediate: bool = True
    intermediate_common_name: Optional[str] = None
    parent_ca_id: Optional[int] = None
    offline_root: bool = True
    path_length: Optional[int] = 0


class CARevokeRequest(BaseModel):
    """Request payload for CA revocation."""

    reason: Optional[str] = Field(default="unspecified", max_length=255)


class CARootImportRequest(BaseModel):
    """Payload for importing an externally managed root CA."""

    pem_certificate: str = Field(..., description="PEM encoded root certificate")
    pem_private_key: Optional[str] = Field(None, description="PEM encoded private key (optional)")
    private_key_password: Optional[str] = Field(
        None, description="Password for encrypted private key, if applicable"
    )
    offline_root: bool = True


class CAIntermediateImportRequest(BaseModel):
    """Payload for importing an externally issued intermediate CA."""

    pem_certificate: str = Field(..., description="PEM encoded intermediate certificate")
    pem_private_key: str = Field(..., description="PEM encoded private key for the intermediate")
    private_key_password: Optional[str] = Field(
        None, description="Password for encrypted intermediate private key"
    )
    parent_ca_id: Optional[int] = Field(None, description="Existing parent/root CA ID")
    root_certificate_pem: Optional[str] = Field(
        None,
        description="Optional PEM encoded root certificate to import alongside the intermediate",
    )
    is_offline: bool = False


@router.get("/root/download")
async def download_root_ca_public(
    db: Session = Depends(get_db),
) -> Response:
    """Download Root CA certificate (public endpoint)."""
    ca = ca_service.get_root_ca(db)
    if not ca:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Root CA not found")

    filename = f"{ca.common_name.replace(' ', '_')}.crt"
    headers = {"Content-Disposition": f"attachment; filename={filename}"}
    
    return Response(content=ca.pem_certificate, media_type="application/x-pem-file", headers=headers)


@router.get("/info", response_model=CAHierarchyResponse)
async def get_ca_info(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """Return Certificate Authority hierarchy summary."""
    logger.info("Fetching CA hierarchy", user_id=current_user.id)
    return ca_service.get_hierarchy_summary(db)


@router.get("/certificate")
async def download_ca_certificate(
    root: bool = False,
    ca_id: Optional[int] = None,
    include_chain: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Response:
    """Download CA certificate (optionally with chain) in PEM format."""
    if ca_id:
        ca = ca_service.get_ca_by_id(db, ca_id)
    elif root:
        ca = ca_service.get_root_ca(db)
    else:
        ca = ca_service.get_active_issuing_ca(db)

    if not ca:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate Authority not found")

    pem_data = ca.pem_certificate
    if include_chain and not root:
        pem_data = ca_service.build_certificate_chain(ca)

    filename = f"{ca.common_name.replace(' ', '_')}.pem"
    headers = {"Content-Disposition": f"attachment; filename={filename}"}

    logger.info(
        "Downloading CA certificate",
        ca_id=ca.id,
        requested_by=current_user.id,
        include_chain=include_chain,
    )

    return Response(content=pem_data, media_type="application/x-pem-file", headers=headers)


@router.post("/initialize", response_model=CAHierarchyResponse, status_code=status.HTTP_201_CREATED)
async def initialize_ca(
    request: CAInitializeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
) -> Any:
    """Initialize Certificate Authority hierarchy (admin only)."""
    try:
        created = ca_service.initialize_hierarchy(db, **request.dict())
        logger.info(
            "CA hierarchy initialized",
            created_count=len(created),
            user_id=current_user.id,
        )
    except ValueError as exc:
        logger.error("Failed to initialize CA hierarchy", error=str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ca_service.get_hierarchy_summary(db)


@router.post("/{ca_id}/revoke")
async def revoke_ca(
    ca_id: int,
    request: CARevokeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
) -> Any:
    """Revoke a Certificate Authority and cascade to dependents."""
    ca = ca_service.get_ca_by_id(db, ca_id)
    if not ca:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate Authority not found")

    ca_service.revoke_ca(db, ca, reason=request.reason or "unspecified")
    logger.warning(
        "Certificate Authority revoked via API",
        ca_id=ca_id,
        user_id=current_user.id,
        reason=request.reason,
    )

    return {
        "message": f"Certificate Authority {ca.common_name} revoked",
        "ca_id": ca_id,
    }


@router.post("/import/root", response_model=CAInfo, status_code=status.HTTP_201_CREATED)
async def import_root_ca(
    request: CARootImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> Any:
    """Import an externally managed root certificate into the hierarchy."""

    try:
        ca = ca_service.import_external_root_ca(
            db,
            pem_certificate=request.pem_certificate,
            offline_root=request.offline_root,
            pem_private_key=request.pem_private_key,
            private_key_password=request.private_key_password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    logger.info("External root imported", ca_id=ca.id, user_id=current_user.id)
    return ca_service.serialize_ca(ca)


@router.post("/import/intermediate", response_model=CAInfo, status_code=status.HTTP_201_CREATED)
async def import_intermediate_ca(
    request: CAIntermediateImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> Any:
    """Import an intermediate CA certificate and make it available for issuance."""

    try:
        ca = ca_service.import_intermediate_ca(
            db,
            pem_certificate=request.pem_certificate,
            pem_private_key=request.pem_private_key,
            private_key_password=request.private_key_password,
            parent_ca_id=request.parent_ca_id,
            root_certificate_pem=request.root_certificate_pem,
            is_offline=request.is_offline,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    logger.info("External intermediate imported", ca_id=ca.id, user_id=current_user.id)
    return ca_service.serialize_ca(ca)


@router.post("/{ca_id}/set-active", response_model=CAInfo)
async def set_active_issuing_ca(
    ca_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> Any:
    """Designate which CA should issue new certificates."""

    try:
        ca = ca_service.set_active_issuing_ca(db, ca_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    logger.info("Issuing CA updated via API", ca_id=ca.id, user_id=current_user.id)
    return ca_service.serialize_ca(ca)


@router.delete("/{ca_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ca(
    ca_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    """Delete an unused intermediate Certificate Authority."""

    ca = ca_service.get_ca_by_id(db, ca_id)
    if not ca:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate Authority not found")

    try:
        ca_service.delete_ca(db, ca)
    except ValueError as exc:
        logger.error("Failed to delete CA", ca_id=ca_id, error=str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

        logger.info("Certificate Authority deleted via API", ca_id=ca_id, user_id=current_user.id)



