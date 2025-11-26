from datetime import datetime, timedelta, timezone

import pytest

from app.core.auth import get_password_hash
from app.core.config import settings
from app.models.certificate import Certificate, CertificateStatus
from app.models.user import User, UserRole


@pytest.fixture
def admin_user(db_session):
    user = User(
        username=settings.ADMIN_USERNAME,
        email=settings.ADMIN_EMAIL,
        hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
        full_name="Test Admin",
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(client, admin_user):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": admin_user.username, "password": settings.ADMIN_PASSWORD},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_alerts_include_expiring_certificate(client, db_session, auth_headers):
    cert = Certificate(
        common_name="expiring.example.com",
        serial_number="expiring-123",
        status=CertificateStatus.ACTIVE,
        not_valid_before=datetime.now(timezone.utc) - timedelta(days=10),
        not_valid_after=datetime.now(timezone.utc) + timedelta(days=5),
        monitoring_enabled=False,
    )
    db_session.add(cert)
    db_session.commit()

    response = client.get("/api/v1/alerts/", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert any(alert["alert_type"] == "certificate_expiry" for alert in data)


def test_alerts_include_expired_certificate(client, db_session, auth_headers):
    cert = Certificate(
        common_name="expired.example.com",
        serial_number="expired-123",
        status=CertificateStatus.EXPIRED,
        not_valid_before=datetime.now(timezone.utc) - timedelta(days=400),
        not_valid_after=datetime.now(timezone.utc) - timedelta(days=1),
        monitoring_enabled=False,
    )
    db_session.add(cert)
    db_session.commit()

    response = client.get("/api/v1/alerts/", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert any("expired" in alert["title"].lower() for alert in data)
