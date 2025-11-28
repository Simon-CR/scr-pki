# Security Guide

Security best practices and implementation details for the HomeLab PKI Platform.

## Security Model

### Threat Model

**Assets to Protect:**
- CA private key (highest priority)
- Certificate private keys
- User credentials
- Certificate metadata
- Audit logs

**Threat Actors:**
- Unauthorized network users
- Compromised home lab services
- Physical access to host system
- Software vulnerabilities

**Out of Scope:**
- Nation-state attackers
- Advanced persistent threats
- Public internet attacks (home lab use only)

## Cryptographic Standards

### Supported Algorithms

#### Asymmetric Encryption

**RSA:**
- Key sizes: 2048, 4096 bits
- Default: 4096 bits
- Use case: General purpose certificates

**ECDSA (Future):**
- Curves: P-256, P-384
- Use case: Resource-constrained devices

#### Hash Functions

**Supported:**
- SHA-256 (default)
- SHA-384
- SHA-512

**Prohibited:**
- MD5
- SHA-1

#### Signature Algorithms

**Allowed:**
- RSA-SHA256 (default)
- RSA-SHA384
- RSA-SHA512
- ECDSA-SHA256 (future)

**Prohibited:**
- RSA-MD5
- RSA-SHA1

### TLS/SSL Configuration

#### Minimum TLS Version

- TLS 1.2 (minimum)
- TLS 1.3 (preferred)
- SSL 3.0, TLS 1.0, TLS 1.1 (disabled)

#### Cipher Suites

**Recommended:**
```
TLS_AES_256_GCM_SHA384              (TLS 1.3)
TLS_CHACHA20_POLY1305_SHA256        (TLS 1.3)
TLS_AES_128_GCM_SHA256              (TLS 1.3)
ECDHE-RSA-AES256-GCM-SHA384         (TLS 1.2)
ECDHE-RSA-AES128-GCM-SHA256         (TLS 1.2)
```

**Prohibited:**
- Any cipher suite with:
  - NULL encryption
  - Anonymous authentication
  - EXPORT-grade encryption
  - RC4
  - DES/3DES
  - MD5

#### Example nginx Configuration

```nginx
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

## Key Management

### Certificate Authority Key

**Storage:**
- Stored in HashiCorp Vault
- Encrypted at rest with Vault's encryption
- Never exposed through API
- Access logged in Vault audit log

**Access Control:**
- Backend service only
- Uses Vault AppRole authentication
- Limited token TTL (1 hour)
- Automatic token rotation

**Backup:**
- Vault data backed up daily
- Encrypted backup storage
- Offline backup stored securely
- Regular restore testing

**Lifecycle:**
- CA key generated once during initialization
- 20-year validity (home lab use)
- Key rotation not supported (would invalidate all certs)

### Certificate Private Keys

**Generation:**
- Generated server-side using cryptography library
- Never transmitted in plain text
- Securely random (os.urandom)

**Storage:**
- Stored in Vault under `/secret/pki/certificates/{serial}/`
- Encrypted at rest
- Access controlled by Vault policies

**Distribution:**
- Downloaded once during certificate issuance
- Transmitted over HTTPS
- Deleted from browser download folder after deployment
- Not stored in database

**File Permissions:**
```bash
# Correct permissions for private keys
chmod 600 /path/to/private.key
chown root:root /path/to/private.key
```

### Vault Configuration

#### Production Mode

**Seal/Unseal:**
- Vault starts sealed
- Requires unseal keys to access
- 5 unseal key shares (3 required)
- Store unseal keys separately and securely

**Initialization:**
```bash
# Initialize Vault (first time only)
docker-compose exec vault vault operator init

# Save output securely:
# - Unseal keys (5 keys)
# - Root token

# Unseal Vault
docker-compose exec vault vault operator unseal
# Enter unseal key 1
docker-compose exec vault vault operator unseal
# Enter unseal key 2
docker-compose exec vault vault operator unseal
# Enter unseal key 3
```

#### Auto-Unseal (Advanced)

For automatic unsealing using external key management:

```hcl
# vault-config.hcl
seal "transit" {
  address         = "https://external-vault:8200"
  token           = "..."
  disable_renewal = "false"
  
  key_name        = "autounseal"
  mount_path      = "transit/"
}
```

#### Vault Policies

**PKI Backend Policy:**
```hcl
# pki-backend-policy.hcl
path "secret/data/pki/ca/*" {
  capabilities = ["read"]
}

path "secret/data/pki/certificates/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

**Apply policy:**
```bash
vault policy write pki-backend pki-backend-policy.hcl
```

## Authentication & Authorization

### ⚠️ Critical Security Setting: AUTH_DISABLED

> **WARNING**: The `AUTH_DISABLED` environment variable completely bypasses all authentication 
> and authorization checks when set to `true`. This is an extremely dangerous setting that 
> should NEVER be used in production environments.

**When AUTH_DISABLED=true:**
- All API requests bypass authentication
- All requests are treated as having full admin privileges
- No user verification or token validation occurs
- Complete audit trail is compromised

**Appropriate Use Cases:**
- Local development only
- Isolated test environments
- Initial debugging during setup

**Production Safeguards:**
- Default value is `false`
- A critical warning is logged at startup if enabled
- A warning banner is printed to stderr

**To ensure this is disabled:**
```bash
# In docker-compose.yml or .env file
AUTH_DISABLED=false

# Or simply remove the variable (defaults to false)
```

### User Authentication

**Supported Methods:**
- Username/password (bcrypt hashed)
- JWT tokens for API access
- Session cookies for web interface

**Password Requirements:**
- Minimum length: 12 characters
- Must include: uppercase, lowercase, number, special character
- No common passwords (dictionary check)
- Password expiry: 90 days (configurable)

**Multi-Factor Authentication (Future):**
- TOTP (Time-based One-Time Password)
- WebAuthn/FIDO2

### Authorization Model

**Role-Based Access Control (RBAC):**

1. **Admin**
   - Full access to all features
   - CA management
   - User management
   - Certificate issuance, renewal, revocation
   - System configuration
   - Audit log access

2. **Operator**
   - Certificate issuance, renewal, revocation
   - Monitoring dashboard access
   - Alert configuration
   - Cannot modify CA or users

3. **Viewer**
   - Read-only access
   - View certificates
   - View monitoring data
   - Cannot issue or revoke certificates

### Session Management

**Web Sessions:**
- Secure session cookies
- HttpOnly flag set
- SameSite=Strict
- Session timeout: 8 hours
- Idle timeout: 1 hour

**API Tokens:**
- JWT tokens with expiration
- Token TTL: 24 hours
- Refresh token support
- Token revocation support

**Example token request:**
```bash
curl -X POST https://pki.homelab.local/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

## Network Security

### Docker Network Isolation

**Network Configuration:**

```yaml
networks:
  frontend-net:
    driver: bridge
    internal: false  # Connects to host
  
  backend-net:
    driver: bridge
    internal: true   # Isolated internal network
  
  vault-net:
    driver: bridge
    internal: true   # Vault isolated
```

**Service Placement:**
- Nginx: frontend-net (exposed to host)
- Frontend: frontend-net + backend-net
- Backend: backend-net + vault-net
- Database: backend-net only
- Vault: vault-net only
- Monitor: backend-net only

### Firewall Configuration

**Host Firewall (iptables/nftables):**

```bash
# Allow HTTPS to nginx
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Block direct access to backend services
iptables -A INPUT -p tcp --dport 8000 -j DROP  # Backend
iptables -A INPUT -p tcp --dport 5432 -j DROP  # PostgreSQL
iptables -A INPUT -p tcp --dport 8200 -j DROP  # Vault

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

**Docker Firewall:**
- Use Docker's built-in network isolation
- Don't expose internal service ports to host
- Use network policies for service-to-service communication

### Network Segmentation

**Recommended Network Setup:**

```
┌─────────────────────────────────────┐
│        Management Network           │
│        (VLAN 10)                    │
│    192.168.10.0/24                  │
│                                     │
│  ┌──────────────────────────┐      │
│  │   PKI Server             │      │
│  │   192.168.10.10          │      │
│  └──────────────────────────┘      │
└─────────────────────────────────────┘
           │
           │ Firewall Rules
           │
┌─────────────────────────────────────┐
│      Service Network                │
│      (VLAN 20)                      │
│   192.168.20.0/24                   │
│                                     │
│  Services using PKI certs           │
└─────────────────────────────────────┘
```

## Application Security

### Input Validation

**Certificate Parameters:**
- Common Name: Max 64 characters, valid hostname format
- SANs: Max 10 entries, valid hostname or IP format
- Validity: 1-7300 days
- Organization: Max 64 characters, alphanumeric + spaces

**SQL Injection Prevention:**
- SQLAlchemy ORM (parameterized queries)
- No raw SQL queries
- Input validation and sanitization

**XSS Prevention:**
- React automatically escapes output
- Content Security Policy headers
- No inline scripts

**CSRF Prevention:**
- CSRF tokens for all state-changing operations
- SameSite cookie attribute
- Origin header validation

### API Security

**Rate Limiting:**

```python
# Per IP address
RATE_LIMIT_PER_IP = "100/hour"

# Per user account
RATE_LIMIT_PER_USER = "500/hour"

# Certificate issuance
RATE_LIMIT_CERT_ISSUANCE = "10/hour"
```

**API Authentication:**
- All endpoints require authentication (except login)
- JWT token in Authorization header
- Token validation on every request

**API Authorization:**
- Role-based access control
- Endpoint-level permissions
- Resource-level permissions (own certificates only, except admins)

### Secure Headers

**HTTP Security Headers:**

```nginx
# Prevent clickjacking
add_header X-Frame-Options "DENY" always;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# Enable XSS protection
add_header X-XSS-Protection "1; mode=block" always;

# Content Security Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'" always;

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Referrer Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions Policy
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

## Audit Logging

### What is Logged

**Certificate Operations:**
- Certificate issuance (who, what, when)
- Certificate renewal
- Certificate revocation (reason)
- CA initialization

**Authentication:**
- Login attempts (success/failure)
- Logout events
- Token generation
- Password changes

**Configuration Changes:**
- Alert rule changes
- Monitoring configuration
- User management
- System settings

**Access:**
- API endpoint access
- Certificate downloads
- Vault key access (via Vault audit log)

### Log Format

```json
{
  "timestamp": "2025-11-13T10:30:00.000Z",
  "event_type": "certificate.issued",
  "user_id": "user_123",
  "username": "admin",
  "ip_address": "192.168.1.100",
  "resource_type": "certificate",
  "resource_id": "cert_456",
  "action": "create",
  "details": {
    "common_name": "grafana.local",
    "validity_days": 3650,
    "key_size": 4096
  },
  "status": "success"
}
```

### Log Storage

**Location:**
- Application logs: `/var/log/pki/app.log`
- Audit logs: `/var/log/pki/audit.log`
- Vault audit logs: `/vault/logs/audit.log`

**Retention:**
- Application logs: 30 days
- Audit logs: 1 year
- Vault audit logs: 1 year

**Protection:**
- Append-only
- Immutable (cannot be edited)
- Regular backups
- Encrypted at rest

### Log Monitoring

**Alert on suspicious activity:**
- Multiple failed login attempts
- Certificate issuance from unknown IP
- Bulk certificate operations
- Configuration changes outside maintenance window
- Vault seal/unseal events

## Data Protection

### Encryption at Rest

**Database:**
- PostgreSQL with encryption enabled
- Tablespace encryption (optional)
- Sensitive fields additionally encrypted with application-level encryption

**Vault:**
- All data encrypted with AES-256-GCM
- Encryption keys never leave Vault
- Master key encrypted with unseal keys

**Backups:**
- All backups encrypted with GPG
- Separate encryption key for backups
- Key stored separately from backups

### Encryption in Transit

**Internal Communication:**
- Service-to-service over Docker network (encrypted network optional)
- Backend to Database: SSL/TLS connection
- Backend to Vault: HTTPS

**External Communication:**
- All external access over HTTPS/TLS 1.3
- Certificate validation enforced
- No plaintext HTTP (redirected to HTTPS)

## Secure Deployment

### Production Checklist

- [ ] Change all default passwords
- [ ] Configure Vault in production mode
- [ ] Enable Vault audit logging
- [ ] Configure TLS for PostgreSQL connections
- [ ] Set up secure backups
- [ ] Configure firewall rules
- [ ] Enable rate limiting
- [ ] Set up monitoring and alerting
- [ ] Review and minimize exposed ports
- [ ] Configure secure session settings
- [ ] Enable HSTS
- [ ] Set up audit log monitoring
- [ ] Test disaster recovery procedures
- [ ] Document security procedures
- [ ] Restrict physical access to host system

### Environment Variables Security

**Don't commit secrets to git:**
```bash
# .gitignore
.env
.env.local
*.key
*.crt
vault-keys.txt
```

**Use secure environment variable management:**
- Never hardcode secrets in code
- Use `.env` file (not committed to git)
- Consider Docker secrets for production
- Rotate secrets regularly

### Docker Security

**Run containers as non-root:**
```dockerfile
# In Dockerfile
RUN addgroup -g 1000 pki && \
    adduser -D -u 1000 -G pki pki
USER pki
```

**Use read-only root filesystem:**
```yaml
services:
  backend:
    read_only: true
    tmpfs:
      - /tmp
```

**Limit container resources:**
```yaml
services:
  backend:
    mem_limit: 512m
    cpus: 1.0
```

**Security scanning:**
```bash
# Scan images for vulnerabilities
docker scan pki-backend:latest
```

## Incident Response

### Security Incident Procedures

**CA Key Compromise:**
1. Immediately seal Vault
2. Revoke all issued certificates
3. Notify all certificate users
4. Generate new CA
5. Re-issue all certificates
6. Conduct security audit

**Certificate Key Compromise:**
1. Revoke compromised certificate immediately
2. Issue new certificate with new key
3. Update deployment
4. Monitor for misuse of compromised certificate
5. Document incident in audit log

**Unauthorized Access:**
1. Lock affected user accounts
2. Reset all user passwords
3. Revoke all active sessions/tokens
4. Review audit logs for extent of breach
5. Implement additional security controls
6. Notify affected parties

**System Compromise:**
1. Isolate system from network
2. Seal Vault
3. Revoke all certificates
4. Conduct forensic analysis
5. Rebuild from clean backup
6. Implement fixes before restoring service

### Audit and Compliance

**Regular Security Reviews:**
- Monthly: Review audit logs
- Quarterly: Security configuration review
- Annually: Full security audit
- After incidents: Incident review and lessons learned

**Security Checklist:**
- [ ] Review active certificates
- [ ] Check for weak keys or algorithms
- [ ] Review user accounts and permissions
- [ ] Verify backup integrity
- [ ] Test disaster recovery
- [ ] Review firewall rules
- [ ] Check for security updates
- [ ] Review audit logs for anomalies

## Security Best Practices

### For Administrators

1. **Use Strong Passwords**
   - Minimum 16 characters
   - Use password manager
   - Enable MFA when available

2. **Principle of Least Privilege**
   - Grant minimum necessary permissions
   - Regular permission reviews
   - Remove unused accounts

3. **Regular Backups**
   - Daily automated backups
   - Test restore procedures
   - Secure backup storage

4. **Keep Software Updated**
   - Regular security patches
   - Monitor security advisories
   - Test updates in non-production first

5. **Monitor Actively**
   - Review alerts daily
   - Check audit logs weekly
   - Set up anomaly detection

### For Certificate Users

1. **Protect Private Keys**
   - Never share private keys
   - Secure file permissions (600)
   - Delete from downloads after deployment

2. **Use Appropriate Validity**
   - Don't use unnecessarily long validity periods
   - Balance convenience with security

3. **Renew Before Expiration**
   - Monitor expiration alerts
   - Renew at least 7 days before expiration
   - Test renewal process

4. **Report Compromises**
   - Immediately report key compromise
   - Request revocation
   - Generate new certificate

5. **Follow Deployment Best Practices**
   - Use strong TLS configurations
   - Keep web servers updated
   - Monitor for vulnerabilities

## Compliance and Standards

### Alignment with Standards

**CA/Browser Forum Baseline Requirements:**
- Key sizes meet minimum requirements (2048+ bits)
- Hash algorithms meet requirements (SHA-256+)
- Certificate validity periods within limits

**NIST Guidelines:**
- Follows NIST SP 800-57 (Key Management)
- Follows NIST SP 800-52 (TLS Guidelines)

**Note:** This platform is designed for private home lab use and is not intended for compliance with external PKI standards like WebTrust or compliance frameworks like PCI DSS.

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [HashiCorp Vault Security](https://www.vaultproject.io/docs/internals/security)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)

## See Also

- [Architecture Overview](ARCHITECTURE.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Incident Response](INCIDENT_RESPONSE.md)
- [Backup and Recovery](BACKUP_RECOVERY.md)
