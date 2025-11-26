"""
Basic tests for PKI Platform API.
"""

def test_health_endpoint(client):
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "timestamp" in data
    assert "version" in data


def test_root_endpoint(client):
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert data["message"] == "PKI Platform API"
    assert data["version"] == "1.0.0"


def test_auth_endpoints_exist(client):
    """Test that authentication endpoints exist."""
    # Test login endpoint (should return 422 without credentials)
    response = client.post("/api/v1/auth/login")
    assert response.status_code == 422  # Validation error for missing form data
    
    # Test me endpoint (should return 401 without token)
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_ca_endpoints_exist(client):
    """Test that CA endpoints exist."""
    # Should return 401 without authentication
    response = client.get("/api/v1/ca/info")
    assert response.status_code == 401


def test_certificate_endpoints_exist(client):
    """Test that certificate endpoints exist."""
    # Should return 401 without authentication
    response = client.get("/api/v1/certificates/")
    assert response.status_code == 401