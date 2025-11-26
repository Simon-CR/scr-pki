# API Documentation

RESTful API documentation for the HomeLab PKI Platform.

## Base URL

```
https://pki.homelab.local/api/v1
```

## Authentication

All API endpoints (except login) require authentication using JWT tokens.

### Obtain Token

```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your-password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

### Use Token

Include token in Authorization header:

```http
GET /certificates
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## API Endpoints

### Authentication

#### Login

```http
POST /auth/login
```

**Request:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "string",
  "refresh_token": "string",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

#### Refresh Token

```http
POST /auth/refresh
```

**Request:**
```json
{
  "refresh_token": "string"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "string",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

#### Logout

```http
POST /auth/logout
Authorization: Bearer {token}
```

**Response:** `204 No Content`

#### Get Current User

```http
GET /auth/me
Authorization: Bearer {token}
```

**Response:** `200 OK`
```json
{
  "id": "user_123",
  "username": "admin",
  "email": "admin@homelab.local",
  "role": "admin",
  "created_at": "2025-01-01T00:00:00Z",
  "last_login": "2025-11-13T10:00:00Z"
}
```

### Certificate Authority

#### Get CA Information

```http
GET /ca
Authorization: Bearer {token}
```

**Response:** `200 OK`
```json
{
  "id": "ca_001",
  "common_name": "HomeLab Root CA",
  "organization": "HomeLab",
  "country": "US",
  "serial_number": "1A:2B:3C:4D:5E:6F",
  "valid_from": "2025-01-01T00:00:00Z",
  "valid_until": "2045-01-01T00:00:00Z",
  "status": "active",
  "key_size": 4096,
  "signature_algorithm": "SHA256",
  "issued_certificates_count": 15
}
```

#### Download CA Certificate

```http
GET /ca/download
Authorization: Bearer {token}
```

**Response:** `200 OK`
- Content-Type: `application/x-pem-file`
- Body: PEM-encoded certificate

#### Initialize CA

```http
POST /ca/init
Authorization: Bearer {token}
```

**Request:**
```json
{
  "common_name": "HomeLab Root CA",
  "organization": "HomeLab",
  "organizational_unit": "Certificate Authority",
  "country": "US",
  "state": "California",
  "locality": "San Francisco",
  "validity_days": 7300,
  "key_size": 4096
}
```

**Response:** `201 Created`
```json
{
  "id": "ca_001",
  "common_name": "HomeLab Root CA",
  "status": "active",
  "serial_number": "1A:2B:3C:4D:5E:6F"
}
```

#### Get CRL (Certificate Revocation List)

```http
GET /ca/crl
```

**Response:** `200 OK`
- Content-Type: `application/pkix-crl`
- Body: DER-encoded CRL

### Certificates

#### List Certificates

```http
GET /certificates?status=active&limit=50&offset=0
Authorization: Bearer {token}
```

**Query Parameters:**
- `status` (optional): Filter by status (active, expired, revoked)
- `search` (optional): Search by common name
- `limit` (optional): Results per page (default: 50)
- `offset` (optional): Pagination offset (default: 0)

**Response:** `200 OK`
```json
{
  "total": 15,
  "limit": 50,
  "offset": 0,
  "items": [
    {
      "id": "cert_123",
      "common_name": "homeassistant.local",
      "serial_number": "2B:3C:4D:5E:6F:7A",
      "valid_from": "2025-01-01T00:00:00Z",
      "valid_until": "2035-01-01T00:00:00Z",
      "status": "active",
      "key_size": 4096,
      "deployment_url": "https://homeassistant.local",
      "monitoring_status": "healthy",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

#### Get Certificate Details

```http
GET /certificates/{certificate_id}
Authorization: Bearer {token}
```

**Response:** `200 OK`
```json
{
  "id": "cert_123",
  "ca_id": "ca_001",
  "common_name": "homeassistant.local",
  "san_entries": ["homeassistant.local", "192.168.1.100"],
  "serial_number": "2B:3C:4D:5E:6F:7A",
  "subject_dn": "CN=homeassistant.local,O=HomeLab,C=US",
  "issuer_dn": "CN=HomeLab Root CA,O=HomeLab,C=US",
  "valid_from": "2025-01-01T00:00:00Z",
  "valid_until": "2035-01-01T00:00:00Z",
  "key_size": 4096,
  "key_type": "RSA",
  "signature_algorithm": "SHA256",
  "status": "active",
  "deployment_location": "Raspberry Pi 4 - Living Room",
  "deployment_url": "https://homeassistant.local",
  "created_at": "2025-01-01T00:00:00Z",
  "created_by": "admin"
}
```

#### Issue Certificate

```http
POST /certificates/issue
Authorization: Bearer {token}
Content-Type: application/json
```

**Request:**
```json
{
  "common_name": "grafana.local",
  "san_entries": ["grafana.local", "192.168.1.101"],
  "organization": "HomeLab",
  "organizational_unit": "Monitoring",
  "locality": "San Francisco",
  "state": "California",
  "country": "US",
  "validity_days": 3650,
  "key_size": 4096,
  "key_type": "RSA",
  "signature_algorithm": "SHA256"
}
```

**Response:** `201 Created`
```json
{
  "id": "cert_456",
  "common_name": "grafana.local",
  "serial_number": "3C:4D:5E:6F:7A:8B",
  "valid_from": "2025-11-13T00:00:00Z",
  "valid_until": "2035-11-13T00:00:00Z",
  "status": "active",
  "download_urls": {
    "certificate": "/certificates/cert_456/download/cert",
    "private_key": "/certificates/cert_456/download/key",
    "ca_chain": "/certificates/cert_456/download/chain",
    "full_chain": "/certificates/cert_456/download/fullchain",
    "bundle": "/certificates/cert_456/download/bundle",
    "pkcs12": "/certificates/cert_456/download/pkcs12"
  }
}
```

#### Download Certificate

```http
GET /certificates/{certificate_id}/download/{type}
Authorization: Bearer {token}
```

**Path Parameters:**
- `type`: cert | key | chain | fullchain | bundle | pkcs12

**Response:** `200 OK`
- Various content types depending on download type

#### Renew Certificate

```http
POST /certificates/{certificate_id}/renew
Authorization: Bearer {token}
```

**Request (optional):**
```json
{
  "validity_days": 3650,
  "key_size": 4096
}
```

**Response:** `201 Created`
```json
{
  "id": "cert_789",
  "common_name": "homeassistant.local",
  "serial_number": "4D:5E:6F:7A:8B:9C",
  "status": "active",
  "download_urls": { }
}
```

#### Revoke Certificate

```http
POST /certificates/{certificate_id}/revoke
Authorization: Bearer {token}
```

**Request:**
```json
{
  "reason": "key_compromise"
}
```

**Reasons:**
- `unspecified`
- `key_compromise`
- `ca_compromise`
- `affiliation_changed`
- `superseded`
- `cessation_of_operation`

**Response:** `200 OK`
```json
{
  "id": "cert_123",
  "status": "revoked",
  "revoked_at": "2025-11-13T10:30:00Z",
  "revocation_reason": "key_compromise"
}
```

#### Update Deployment Info

```http
PATCH /certificates/{certificate_id}/deployment
Authorization: Bearer {token}
```

**Request:**
```json
{
  "deployment_url": "https://homeassistant.local",
  "deployment_location": "Raspberry Pi 4 - Living Room",
  "description": "Home Assistant instance"
}
```

**Response:** `200 OK`
```json
{
  "id": "cert_123",
  "deployment_url": "https://homeassistant.local",
  "deployment_location": "Raspberry Pi 4 - Living Room",
  "monitoring_enabled": true
}
```

### Monitoring

#### List Monitored Services

```http
GET /monitoring/services?status=healthy
Authorization: Bearer {token}
```

**Query Parameters:**
- `status` (optional): healthy | warning | down

**Response:** `200 OK`
```json
{
  "total": 10,
  "items": [
    {
      "id": "monitor_123",
      "certificate_id": "cert_123",
      "service_name": "Home Assistant",
      "url": "https://homeassistant.local",
      "status": "healthy",
      "last_check": "2025-11-13T10:25:00Z",
      "response_time_ms": 145,
      "status_code": 200,
      "ssl_valid": true,
      "ssl_expires_in_days": 347,
      "check_interval": 300,
      "enabled": true
    }
  ]
}
```

#### Get Service Details

```http
GET /monitoring/services/{service_id}
Authorization: Bearer {token}
```

**Response:** `200 OK`
```json
{
  "id": "monitor_123",
  "certificate_id": "cert_123",
  "service_name": "Home Assistant",
  "url": "https://homeassistant.local",
  "status": "healthy",
  "check_interval": 300,
  "timeout": 10,
  "enabled": true,
  "last_check": "2025-11-13T10:25:00Z",
  "response_time_ms": 145,
  "status_code": 200,
  "ssl_details": {
    "valid": true,
    "expires_at": "2035-01-01T00:00:00Z",
    "days_until_expiry": 347,
    "issuer": "CN=HomeLab Root CA",
    "subject": "CN=homeassistant.local",
    "serial_number": "2B:3C:4D:5E:6F:7A",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "protocol": "TLSv1.3"
  },
  "uptime_percentage_30d": 99.8,
  "average_response_time_30d_ms": 152
}
```

#### Trigger Manual Check

```http
POST /monitoring/services/{service_id}/check
Authorization: Bearer {token}
```

**Response:** `200 OK`
```json
{
  "id": "monitor_123",
  "status": "healthy",
  "checked_at": "2025-11-13T10:30:00Z",
  "response_time_ms": 145,
  "ssl_valid": true
}
```

#### Check All Services

```http
POST /monitoring/check-all
Authorization: Bearer {token}
```

**Response:** `202 Accepted`
```json
{
  "message": "Health checks triggered for all services",
  "services_count": 10,
  "job_id": "job_abc123"
}
```

#### Update Service Configuration

```http
PATCH /monitoring/services/{service_id}
Authorization: Bearer {token}
```

**Request:**
```json
{
  "check_interval": 300,
  "timeout": 10,
  "enabled": true
}
```

**Response:** `200 OK`

#### Get Check History

```http
GET /monitoring/services/{service_id}/history?days=7
Authorization: Bearer {token}
```

**Response:** `200 OK`
```json
{
  "service_id": "monitor_123",
  "period_days": 7,
  "checks": [
    {
      "checked_at": "2025-11-13T10:25:00Z",
      "status": "healthy",
      "response_time_ms": 145,
      "status_code": 200,
      "ssl_valid": true
    }
  ],
  "statistics": {
    "total_checks": 336,
    "successful_checks": 335,
    "failed_checks": 1,
    "uptime_percentage": 99.7,
    "average_response_time_ms": 152
  }
}
```

### Alerts

#### List Alert Rules

```http
GET /alerts/rules
Authorization: Bearer {token}
```

**Response:** `200 OK`
```json
{
  "items": [
    {
      "id": "rule_123",
      "name": "Certificate Expiration Warning",
      "type": "expiration",
      "certificate_id": "cert_123",
      "threshold_days": 30,
      "enabled": true,
      "notification_channels": ["email", "slack"],
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

#### Create Alert Rule

```http
POST /alerts/rules
Authorization: Bearer {token}
```

**Request:**
```json
{
  "name": "Critical Service Down",
  "type": "health",
  "certificate_id": "cert_123",
  "consecutive_failures": 3,
  "enabled": true,
  "notification_channels": ["email", "slack", "webhook"]
}
```

**Response:** `201 Created`

#### List Alerts

```http
GET /alerts?status=active&severity=critical
Authorization: Bearer {token}
```

**Response:** `200 OK`
```json
{
  "items": [
    {
      "id": "alert_123",
      "rule_id": "rule_456",
      "certificate_id": "cert_789",
      "type": "expiration",
      "severity": "warning",
      "status": "active",
      "message": "Certificate 'grafana.local' expires in 28 days",
      "triggered_at": "2025-11-13T10:00:00Z",
      "acknowledged": false
    }
  ]
}
```

#### Acknowledge Alert

```http
POST /alerts/{alert_id}/acknowledge
Authorization: Bearer {token}
```

**Response:** `200 OK`

### Users (Admin Only)

#### List Users

```http
GET /users
Authorization: Bearer {token}
```

**Response:** `200 OK`
```json
{
  "items": [
    {
      "id": "user_123",
      "username": "admin",
      "email": "admin@homelab.local",
      "role": "admin",
      "created_at": "2025-01-01T00:00:00Z",
      "last_login": "2025-11-13T10:00:00Z",
      "active": true
    }
  ]
}
```

#### Create User

```http
POST /users
Authorization: Bearer {token}
```

**Request:**
```json
{
  "username": "operator1",
  "email": "operator@homelab.local",
  "password": "SecurePassword123!",
  "role": "operator"
}
```

**Response:** `201 Created`

#### Update User

```http
PATCH /users/{user_id}
Authorization: Bearer {token}
```

**Request:**
```json
{
  "email": "newemail@homelab.local",
  "role": "viewer",
  "active": true
}
```

**Response:** `200 OK`

#### Delete User

```http
DELETE /users/{user_id}
Authorization: Bearer {token}
```

**Response:** `204 No Content`

### Health

#### System Health Check

```http
GET /health
```

**Response:** `200 OK`
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "services": {
    "database": "healthy",
    "vault": "healthy",
    "monitoring": "healthy"
  },
  "timestamp": "2025-11-13T10:30:00Z"
}
```

## Error Responses

### Standard Error Format

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Certificate not found",
    "details": {
      "certificate_id": "cert_invalid"
    }
  }
}
```

### HTTP Status Codes

- `200 OK` - Success
- `201 Created` - Resource created
- `204 No Content` - Success with no response body
- `400 Bad Request` - Invalid request
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict
- `422 Unprocessable Entity` - Validation error
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service temporarily unavailable

### Error Codes

- `AUTHENTICATION_FAILED` - Invalid credentials
- `INVALID_TOKEN` - JWT token invalid or expired
- `INSUFFICIENT_PERMISSIONS` - User lacks required permissions
- `RESOURCE_NOT_FOUND` - Requested resource doesn't exist
- `VALIDATION_ERROR` - Request validation failed
- `DUPLICATE_RESOURCE` - Resource already exists
- `RATE_LIMIT_EXCEEDED` - Too many requests
- `VAULT_ERROR` - Vault operation failed
- `DATABASE_ERROR` - Database operation failed
- `CERTIFICATE_ERROR` - Certificate operation failed

## Rate Limiting

API endpoints are rate limited:

- **Per IP**: 100 requests/hour
- **Per User**: 500 requests/hour
- **Certificate Issuance**: 10 requests/hour

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1699875600
```

## Pagination

List endpoints support pagination:

```http
GET /certificates?limit=50&offset=100
```

Response includes pagination info:
```json
{
  "total": 250,
  "limit": 50,
  "offset": 100,
  "items": []
}
```

## Filtering and Searching

Most list endpoints support filtering:

```http
GET /certificates?status=active&search=homeassistant&sort=created_at:desc
```

## Webhooks

Configure webhooks to receive real-time notifications:

### Webhook Payload Format

```json
{
  "event": "certificate.expiring",
  "timestamp": "2025-11-13T10:30:00Z",
  "data": {
    "certificate_id": "cert_123",
    "common_name": "homeassistant.local",
    "expires_in_days": 28,
    "expires_at": "2025-12-11T00:00:00Z"
  }
}
```

### Webhook Events

- `certificate.issued`
- `certificate.renewed`
- `certificate.revoked`
- `certificate.expiring`
- `certificate.expired`
- `service.down`
- `service.recovered`
- `alert.triggered`

## SDK Examples

### Python

```python
import requests

class PKIClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.token = self._login(username, password)
    
    def _login(self, username, password):
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={"username": username, "password": password}
        )
        return response.json()["access_token"]
    
    def issue_certificate(self, common_name, **kwargs):
        response = requests.post(
            f"{self.base_url}/certificates/issue",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"common_name": common_name, **kwargs}
        )
        return response.json()

# Usage
client = PKIClient("https://pki.homelab.local/api/v1", "admin", "password")
cert = client.issue_certificate("test.local", validity_days=3650)
```

### JavaScript/Node.js

```javascript
class PKIClient {
  constructor(baseURL, username, password) {
    this.baseURL = baseURL;
    this.login(username, password);
  }

  async login(username, password) {
    const response = await fetch(`${this.baseURL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await response.json();
    this.token = data.access_token;
  }

  async issueCertificate(commonName, options = {}) {
    const response = await fetch(`${this.baseURL}/certificates/issue`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ common_name: commonName, ...options })
    });
    return response.json();
  }
}

// Usage
const client = new PKIClient('https://pki.homelab.local/api/v1', 'admin', 'password');
const cert = await client.issueCertificate('test.local', { validity_days: 3650 });
```

## See Also

- [Getting Started](GETTING_STARTED.md)
- [Certificate Management](CERTIFICATE_MANAGEMENT.md)
- [Development Guide](DEVELOPMENT.md)
- [Database Schema](DATABASE.md)
