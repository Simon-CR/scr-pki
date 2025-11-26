import pytest

from app.core.auth import get_password_hash
from app.core.config import settings
from app.models.user import User, UserRole
from app.services.ca_service import ca_service
from app.services.certificate_service import certificate_service


@pytest.fixture
def admin_user(db_session):
    existing = (
        db_session.query(User)
        .filter(User.username == settings.ADMIN_USERNAME)
        .first()
    )
    if existing:
        return existing

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


@pytest.fixture
def issued_certificate(db_session, admin_user):
    ca_service.initialize_hierarchy(
        db_session,
        common_name="Test Root CA",
        organization="Test Org",
        offline_root=True,
        create_intermediate=True,
    )

    cert = certificate_service.issue_certificate(
        db=db_session,
        common_name="bundle.test",
        subject_alt_names=["bundle.test"],
        created_by_user_id=admin_user.id,
    )
    return cert


def test_bundle_download_includes_private_key(client, auth_headers, issued_certificate):
    response = client.get(
        f"/api/v1/certificates/{issued_certificate.id}/download",
        headers=auth_headers,
        params={"include_chain": "true", "include_private_key": "true"},
    )
    assert response.status_code == 200
    body = response.text
    assert "BEGIN PRIVATE KEY" in body
    assert "BEGIN CERTIFICATE" in body
    assert body.index("BEGIN PRIVATE KEY") < body.index("BEGIN CERTIFICATE")


def test_leaf_download_excludes_private_key(client, auth_headers, issued_certificate):
    response = client.get(
        f"/api/v1/certificates/{issued_certificate.id}/download",
        headers=auth_headers,
        params={"include_chain": "false"},
    )
    assert response.status_code == 200
    body = response.text
    assert "BEGIN PRIVATE KEY" not in body
    assert "BEGIN CERTIFICATE" in body
