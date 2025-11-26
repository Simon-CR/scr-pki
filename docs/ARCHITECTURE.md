# Architecture Overview

## System Architecture

HomeLab PKI Platform follows a microservices architecture with containerized components communicating over a private Docker network.

```
┌─────────────────────────────────────────────────────────────┐
│                         User Browser                         │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTPS
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      Nginx (Reverse Proxy)                   │
│                    - SSL Termination                         │
│                    - Load Balancing                          │
└─────────────┬──────────────────────────┬────────────────────┘
              │                          │
              │ HTTP                     │ HTTP
              ▼                          ▼
┌─────────────────────────┐    ┌─────────────────────────────┐
│   Frontend Container    │    │    Backend API Container     │
│   - React UI            │    │    - FastAPI                 │
│   - Static Assets       │    │    - Certificate Operations  │
│   - Nginx Server        │    │    - Authentication          │
└─────────────────────────┘    └──┬──────────────┬───────┬───┘
                                  │              │       │
                    ┌─────────────┘              │       └─────────────┐
                    │ PostgreSQL                 │                     │
                    ▼                            ▼                     ▼
          ┌───────────────────┐    ┌────────────────────┐  ┌──────────────────┐
          │   Database        │    │  HashiCorp Vault   │  │  Monitor Service │
          │   - Cert Metadata │    │  - Private Keys    │  │  - Health Checks │
          │   - User Data     │    │  - CA Keys         │  │  - Alerts        │
          │   - Audit Logs    │    │  - Secrets         │  │  - Status Updates│
          └───────────────────┘    └────────────────────┘  └──────────────────┘
```

## Components

### 1. Frontend (React UI)

**Purpose**: User-facing web interface for certificate management

**Technologies**:
- React 18 with TypeScript
- TailwindCSS for styling
- React Router for navigation
- Axios for API communication
- React Query for data fetching

**Key Features**:
- Certificate dashboard with search/filter
- Certificate issuance wizard
- Root CA download page
- Installation instructions
- Service monitoring dashboard
- Alert management interface
- User authentication flows

**Container Details**:
- Base Image: `node:18-alpine`
- Build: Multi-stage (build + nginx serve)
- Port: 3000 (internal)
- Volume: None (stateless)

### 2. Backend API (FastAPI)

**Purpose**: Core business logic and API endpoints

**Technologies**:
- Python 3.11
- FastAPI framework
- SQLAlchemy ORM
- Cryptography library
- Pydantic for validation
- HVAC for Vault integration

**Key Responsibilities**:
- Certificate Authority initialization
- Certificate issuance and management
- Certificate revocation (CRL generation)
- User authentication and authorization
- API endpoint exposure
- Database operations
- Vault integration for key management

**Endpoints**:
- `/api/v1/auth/*` - Authentication
- `/api/v1/ca/*` - CA operations
- `/api/v1/certificates/*` - Certificate management
- `/api/v1/monitoring/*` - Service monitoring
- `/api/v1/alerts/*` - Alert configuration
- `/api/v1/health` - Health check

**Container Details**:
- Base Image: `python:3.11-slim`
- Port: 8000 (internal)
- Volumes: 
  - CA data (persistent)
  - Logs (persistent)

### 3. Database (PostgreSQL)

**Purpose**: Persistent storage for certificate metadata and application data

**Schema**:

```sql
-- Certificate Authority
ca_certificates (
    id, name, subject_dn, valid_from, valid_until, 
    serial_number, status, created_at
)

-- Issued Certificates
certificates (
    id, ca_id, common_name, subject_dn, san_entries,
    serial_number, valid_from, valid_until, key_size,
    signature_algorithm, deployment_location, status,
    vault_key_path, created_at, revoked_at
)

-- Monitoring
service_monitors (
    id, certificate_id, url, check_interval, 
    last_check, status, response_time, created_at
)

-- Alerts
alert_rules (
    id, certificate_id, alert_type, threshold_days,
    enabled, last_triggered, created_at
)

alert_history (
    id, rule_id, triggered_at, resolved_at, 
    severity, message
)

-- Users & Auth
users (
    id, username, email, password_hash, role,
    created_at, last_login
)

-- Audit Logs
audit_logs (
    id, user_id, action, resource_type, resource_id,
    details, ip_address, timestamp
)
```

**Container Details**:
- Image: `postgres:15-alpine`
- Port: 5432 (internal only)
- Volume: PostgreSQL data (persistent)

### 4. HashiCorp Vault

**Purpose**: Secure storage for private keys and sensitive data

**What's Stored**:
- CA private keys
- Certificate private keys
- API tokens/secrets
- Encryption keys

**Secrets Organization**:
```
secret/
├── pki/
│   ├── ca/
│   │   └── root-ca-key
│   └── certificates/
│       ├── {serial_number}/
│       │   └── private-key
├── auth/
│   ├── jwt-secret
│   └── api-keys
└── monitoring/
    └── webhook-tokens
```

**Security Features**:
- Transit encryption engine for data at rest
- Dynamic secrets for database credentials
- Audit logging enabled
- Seal/unseal mechanism
- Policy-based access control

**Container Details**:
- Image: `hashicorp/vault:latest`
- Port: 8200 (internal only)
- Volume: Vault data (persistent)
- Mode: Development (for home lab), Production (optional)

### 5. Monitor Service

**Purpose**: Automated health checking and alerting

**Responsibilities**:
- Periodic HTTPS health checks for deployed certificates
- Certificate expiration monitoring
- Alert generation and delivery
- Status updates to database

**Technologies**:
- Python 3.11
- APScheduler for job scheduling
- aiohttp for async HTTP checks
- SMTP/webhook libraries for notifications

**Check Types**:
1. **SSL Certificate Validation**
   - Verify cert chain
   - Check expiration
   - Validate hostname

2. **Service Availability**
   - HTTP status code check
   - Response time measurement
   - Custom health endpoint validation

3. **Expiration Alerts**
   - Check daily for upcoming expirations
   - Multi-level warnings (30, 14, 7, 1 days)

**Container Details**:
- Base Image: `python:3.11-slim`
- No exposed ports
- Volumes: Shared logs

### 6. Nginx (Reverse Proxy)

**Purpose**: Entry point, SSL termination, routing

**Configuration**:
```nginx
upstream frontend {
    server frontend:3000;
}

upstream backend {
    server backend:8000;
}

server {
    listen 443 ssl http2;
    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    
    location / {
        proxy_pass http://frontend;
    }
    
    location /api/ {
        proxy_pass http://backend;
    }
}
```

**Container Details**:
- Image: `nginx:alpine`
- Ports: 80, 443
- Volumes: SSL certificates, config

## Data Flow

### Certificate Issuance Flow

```
1. User submits certificate request via UI
   ↓
2. Frontend sends POST /api/v1/certificates/issue
   ↓
3. Backend validates request parameters
   ↓
4. Backend generates certificate using CA key from Vault
   ↓
5. Backend stores private key in Vault
   ↓
6. Backend saves certificate metadata to PostgreSQL
   ↓
7. Backend returns certificate + download links
   ↓
8. User downloads certificate bundle
   ↓
9. User deploys certificate and updates deployment location
   ↓
10. Monitor service begins health checks
```

### Monitoring Flow

```
1. APScheduler triggers health check job
   ↓
2. Monitor service queries active certificates from DB
   ↓
3. For each certificate with deployment_location:
   a. Perform HTTPS request to service
   b. Validate SSL certificate
   c. Measure response time
   ↓
4. Update service_monitors table with results
   ↓
5. If status changed, create alert if configured
   ↓
6. Send notifications via configured channels
```

## Security Architecture

### Authentication & Authorization

- **JWT-based authentication**
- **Role-based access control (RBAC)**
  - Admin: Full access
  - User: Certificate management only
  - Viewer: Read-only access

### Network Security

- All services on internal Docker network
- Only Nginx exposed to host network
- TLS 1.3 enforced for external connections
- Internal services communicate over HTTP (encrypted Docker network)

### Key Management

- Private keys never leave Vault
- Certificate operations use Vault transit encryption
- Automated key rotation (planned)
- Audit trail for all key access

### Data Protection

- Database credentials stored in Vault
- Passwords hashed with bcrypt
- Sensitive data encrypted at rest
- Audit logging for all operations

## Scalability Considerations

### Current Design (Home Lab)
- Single instance of each service
- Suitable for 100s of certificates
- Local/network access only

### Future Scaling Options
- Multiple backend replicas behind Nginx
- Redis for session management
- Separate monitoring cluster
- Vault HA configuration
- PostgreSQL replication

## Monitoring & Observability

### Logs
- All services log to stdout
- Centralized log collection (Docker logs)
- Structured JSON logging

### Metrics (Future)
- Prometheus metrics exposure
- Grafana dashboards
- Key metrics:
  - Certificate issuance rate
  - Active certificates count
  - Service health check success rate
  - API response times

### Health Checks
- Each container has health check endpoint
- Docker health checks configured
- Automatic restart on failure

## Backup & Recovery

### What to Backup
1. **Critical**:
   - Vault data (encrypted)
   - CA private key (in Vault)
   - PostgreSQL database

2. **Important**:
   - Issued certificates metadata
   - Audit logs
   - Configuration files

### Backup Strategy
- Automated daily backups
- Encrypted backup storage
- 30-day retention
- Documented restore procedure

## Deployment Environments

### Development
- Docker Compose on local machine
- Vault in dev mode
- Hot reload enabled
- Debug logging

### Production (Home Lab)
- Docker Compose on dedicated server
- Vault in production mode (sealed)
- Optimized builds
- Info-level logging
- Regular backups
