# Certificate Management Guide

Complete guide to managing certificates in the HomeLab PKI Platform.

## Table of Contents

- [Certificate Lifecycle](#certificate-lifecycle)
- [Issuing Certificates](#issuing-certificates)
- [Certificate Types](#certificate-types)
- [Deployment](#deployment)
- [Renewal](#renewal)
- [Revocation](#revocation)
- [Intermediate CA Rotation](#intermediate-ca-rotation)
- [Best Practices](#best-practices)

## Certificate Lifecycle

```
┌─────────────┐
│   Request   │
│ Certificate │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Issue    │
│ Certificate │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Active    │◄─── Monitoring
│             │     Health Checks
└──────┬──────┘     Alerts
       │
       ├──────────┐
       │          │
       ▼          ▼
┌──────────┐ ┌─────────┐
│  Renew   │ │ Revoke  │
└────┬─────┘ └────┬────┘
     │            │
     │            ▼
     │      ┌──────────┐
     │      │ Revoked  │
     │      └──────────┘
     │
     ▼
┌──────────┐
│ Expired  │
└──────────┘
```

## Issuing Certificates

### Via Web Interface

#### Step 1: Navigate to Certificate Issuance

1. Log in to the PKI platform
2. Click **Certificates** in the navigation menu
3. Click **Issue New Certificate** button

#### Step 2: Fill Certificate Details

**Required Fields:**

- **Common Name (CN)**: Primary hostname
  - Example: `homeassistant.local`
  - Must be a valid hostname or IP address

**Optional Fields:**

- **Subject Alternative Names (SANs)**: Additional hostnames/IPs
  - Example: `homeassistant.local, 192.168.1.100, ha.local`
  - Comma-separated list
  - Supports wildcards: `*.homelab.local`

- **Organization (O)**: Your organization name
  - Example: `HomeLab`

- **Organizational Unit (OU)**: Department or unit
  - Example: `Infrastructure`

- **Locality (L)**: City
  - Example: `San Francisco`

- **State/Province (ST)**: State or province
  - Example: `California`

- **Country (C)**: Two-letter country code
  - Example: `US`

**Certificate Options:**

- **Validity Period**: How long the certificate is valid
  - Default: `3650 days` (10 years)
  - Range: `1-7300 days`
  - Recommendation: 3650 days for home lab use

- **Key Size**: RSA key size in bits
  - Options: `2048, 4096`
  - Default: `4096`
  - Recommendation: 4096 for better security

- **Key Type**: Cryptographic algorithm
  - Options: `RSA, ECDSA`
  - Default: `RSA`

- **Signature Algorithm**: Hash algorithm
  - Options: `SHA-256, SHA-384, SHA-512`
  - Default: `SHA-256`

#### Step 3: Issue Certificate

1. Review all details
2. Click **Issue Certificate**
3. Wait for generation (5-10 seconds for 4096-bit keys)
4. Certificate details page will appear

#### Step 4: Download Certificate

**Available Downloads:**

1. **Certificate Only** (`.crt`)
   - Server certificate in PEM format
   - Use when you already have the private key

2. **Private Key** (`.key`)
   - RSA private key in PEM format
   - ⚠️ Keep this secure!

3. **Certificate Bundle** (`.zip`)
   - Includes:
     - Server certificate (`.crt`)
     - Private key (`.key`)
     - CA certificate chain (`.ca-bundle.crt`)
     - Full chain (`.fullchain.crt`)
     - README with deployment instructions

4. **Full Chain** (`.fullchain.crt`)
   - Server certificate + CA chain
   - Use for nginx, Apache, etc.

5. **PKCS#12 Bundle** (`.p12`)
   - Certificate + key in single encrypted file
   - Password-protected
   - Use for Windows IIS, Java keystores

### Via API

#### Basic Certificate Issuance

```bash
curl -X POST https://pki.homelab.local/api/v1/certificates/issue \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "grafana.local",
    "san_entries": ["grafana.local", "192.168.1.101"],
    "validity_days": 3650,
    "key_size": 4096,
    "organization": "HomeLab",
    "country": "US"
  }'
```

#### Response

```json
{
  "id": "cert_123456",
  "serial_number": "1A:2B:3C:4D:5E:6F",
  "common_name": "grafana.local",
  "valid_from": "2025-01-01T00:00:00Z",
  "valid_until": "2035-01-01T00:00:00Z",
  "status": "active",
  "download_urls": {
    "certificate": "/api/v1/certificates/cert_123456/download/cert",
    "private_key": "/api/v1/certificates/cert_123456/download/key",
    "bundle": "/api/v1/certificates/cert_123456/download/bundle",
    "pkcs12": "/api/v1/certificates/cert_123456/download/pkcs12"
  }
}
```

## Certificate Types

### Server Certificates

**Use Case**: Web servers, API endpoints, admin interfaces

**Configuration:**
- Common Name: Hostname of the service
- SAN: All hostnames/IPs where service is accessible
- Extended Key Usage: `Server Authentication`
- Key Size: 4096 bits
- Validity: 3650 days (10 years)

**Examples:**
- Home Assistant: `homeassistant.local`
- Grafana: `grafana.homelab.local`
- Proxmox: `proxmox.local, 192.168.1.50`

### Wildcard Certificates

**Use Case**: Multiple subdomains under same domain

**Configuration:**
- Common Name: `*.homelab.local`
- SAN: `*.homelab.local, homelab.local`
- Valid for all `*.homelab.local` subdomains

**Note**: Wildcard certs are convenient but less secure than individual certs. Use for trusted home lab environments only.

### IP Address Certificates

**Use Case**: Services accessed by IP only

**Configuration:**
- Common Name: IP address (e.g., `192.168.1.100`)
- SAN: Same IP address
- Valid for IP-based access

## Deployment

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name homeassistant.local;
    
    # Certificate files
    ssl_certificate     /etc/nginx/certs/homeassistant.fullchain.crt;
    ssl_certificate_key /etc/nginx/certs/homeassistant.key;
    
    # Strong SSL configuration
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;
    
    location / {
        proxy_pass http://localhost:8123;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Apache

```apache
<VirtualHost *:443>
    ServerName grafana.local
    
    SSLEngine on
    SSLCertificateFile /etc/apache2/certs/grafana.crt
    SSLCertificateKeyFile /etc/apache2/certs/grafana.key
    SSLCertificateChainFile /etc/apache2/certs/ca-bundle.crt
    
    # Strong SSL configuration
    SSLProtocol -all +TLSv1.3 +TLSv1.2
    SSLCipherSuite HIGH:!aNULL:!MD5
    SSLHonorCipherOrder on
    
    ProxyPass / http://localhost:3000/
    ProxyPassReverse / http://localhost:3000/
</VirtualHost>
```

### Docker Container (nginx)

```yaml
version: '3.8'

services:
  app:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs/homeassistant.fullchain.crt:/etc/nginx/certs/server.crt:ro
      - ./certs/homeassistant.key:/etc/nginx/certs/server.key:ro
```

### Home Assistant

Add to `configuration.yaml`:

```yaml
http:
  ssl_certificate: /ssl/homeassistant.fullchain.crt
  ssl_key: /ssl/homeassistant.key
  server_host: 0.0.0.0
  server_port: 8123
```

### Proxmox

1. **Issue Certificate**:
   - Go to **Certificates** → **Issue Certificate**
   - Common Name: `proxmox.local` (or your hostname)
   - Subject Alternative Names: Add the IP address (e.g., `192.168.1.50`)
   - Click **Issue**

2. **Download Files** (Proxmox requires separate files):
   - Click **Download Key** to get the private key file (`.key`)
   - Click **Download Chain** to get the certificate with CA chain (`.pem`)
   
   > **Note**: Do not use "Full Bundle" for Proxmox - it combines the key and certificate into one file, which Proxmox does not accept.

3. **Install via Web Interface**:
   - Go to Proxmox **Datacenter** → **Node** → **System** → **Certificates**
   - Click **Upload Custom Certificate**
   - Upload the `.key` file as the Private Key
   - Upload the `.pem` file as the Certificate

4. **Or via CLI**:
   - Upload both files to your Proxmox server
   ```bash
   # Copy the key file
   cp proxmox.key /etc/pve/local/pveproxy-ssl.key
   
   # Copy the certificate chain
   cp proxmox.pem /etc/pve/local/pveproxy-ssl.pem
   
   # Set permissions
   chmod 600 /etc/pve/local/pveproxy-ssl.key
   
   # Restart proxy
   systemctl restart pveproxy
   ```

### Synology NAS

1. Go to **Control Panel** → **Security** → **Certificate**
2. Click **Add** → **Add a new certificate**
3. Select **Import certificate**
4. Upload:
   - Private Key: `synology.key`
   - Certificate: `synology.crt`
   - Intermediate Certificate: `ca-bundle.crt`
5. Click **OK**

### Update Deployment Information

After deploying a certificate:

1. Go to certificate details in PKI platform
2. Click **Edit Deployment**
3. Add:
   - **Service URL**: `https://homeassistant.local`
   - **Service Name**: `Home Assistant`
   - **Description**: `Home automation platform`
   - **Location**: `Raspberry Pi 4 - Living Room`
4. Click **Save**

This enables automatic monitoring and health checks.

## Renewal

### When to Renew

- 30 days before expiration (recommended)
- When changing hostnames/SANs
- After key compromise
- When upgrading key size

### Renewal Process

#### Via Web Interface

1. Go to **Certificates**
2. Find the certificate to renew
3. Click certificate name to open details
4. Click **Renew Certificate** button
5. Review/modify settings if needed
6. Click **Confirm Renewal**
7. Download new certificate bundle
8. Deploy to service (same process as initial deployment)
9. Update deployment info if needed

#### Automated Renewal (Planned Feature)

Future versions will support automatic renewal:
- Configurable renewal threshold (e.g., 30 days before expiration)
- Automatic certificate generation
- Webhook notifications for manual deployment
- API for automated deployment

### Rolling Updates

For zero-downtime renewal:

1. Generate new certificate
2. Configure service to accept both old and new certificates
3. Deploy new certificate
4. Verify new certificate works
5. Remove old certificate configuration
6. Revoke old certificate

## Revocation

### When to Revoke

- Private key compromised or exposed
- Service decommissioned
- Hostname changed (issue new cert instead)
- Security incident

### Revocation Process

1. Go to **Certificates**
2. Find the certificate to revoke
3. Click certificate name to open details
4. Click **Revoke Certificate**
5. Select reason:
   - Key Compromise
   - CA Compromise
   - Affiliation Changed
   - Superseded
   - Cessation of Operation
6. Click **Confirm Revocation**

### After Revocation

- Certificate is added to CRL (Certificate Revocation List)
- Service monitoring is disabled
- Certificate status changes to "Revoked"
- Cannot be un-revoked (issue new certificate instead)

### Certificate Revocation List (CRL)

Access CRL at:
```
https://pki.homelab.local/api/v1/ca/crl
```

CRL is automatically updated when certificates are revoked.

## Intermediate CA Rotation

When your Intermediate CA is approaching expiration (or if you need to replace it for security reasons), you don't "renew" it in the traditional sense. Instead, you create a new Intermediate CA which takes over the role of issuing new certificates.

### Workflow

1.  **Create New Intermediate CA**:
    *   Go to the **Certificate Authorities** page.
    *   Click **Add Intermediate CA**.
    *   Fill in the details (Common Name, etc.). You might want to increment a version number in the name (e.g., "HomeLab Issuing CA v2").
    *   Click **Create**.

2.  **Automatic Switchover**:
    *   The system automatically selects the **newest active** Intermediate CA for issuing all *new* certificates.
    *   No manual "activation" step is required.

3.  **Old Intermediate CA**:
    *   The old Intermediate CA remains **Active** in the system.
    *   This is important because it allows existing certificates signed by it to remain valid until they expire.
    *   Do **not** revoke the old Intermediate CA unless you want to immediately invalidate all certificates it issued.

4.  **Verification**:
    *   Issue a test certificate.
    *   Inspect the certificate chain to ensure it is signed by the new Intermediate CA.

## Best Practices

### Security

1. **Protect Private Keys**
   - Never share private keys
   - Use secure file permissions (600)
   - Store keys encrypted when possible
   - Delete keys from download location after deployment

2. **Use Strong Key Sizes**
   - Minimum: 2048 bits
   - Recommended: 4096 bits

3. **Limit Certificate Validity**
   - While 10 years is convenient for home lab, shorter periods are more secure
   - Consider 2-3 years for better security
   - Balance convenience with security needs

4. **Use SANs Properly**
   - Include all hostnames/IPs where service is accessible
   - Don't over-provision (adds unnecessary exposure)

5. **Regular Audits**
   - Review issued certificates quarterly
   - Revoke unused certificates
   - Update deployment information

### Organization

1. **Naming Convention**
   - Use consistent, descriptive common names
   - Example: `service.category.local`
   - `grafana.monitoring.local`
   - `homeassistant.automation.local`

2. **Documentation**
   - Keep deployment locations updated
   - Document certificate purpose
   - Note any special configurations

3. **Certificate Inventory**
   - Regularly review certificate list
   - Ensure all active services are listed
   - Remove entries for decommissioned services

### Monitoring

1. **Enable Health Checks**
   - Add service URLs for all deployed certificates
   - Configure appropriate check intervals
   - Monitor dashboard regularly

2. **Configure Alerts**
   - Set up email notifications
   - Use multiple alert thresholds (30, 14, 7 days)
   - Test alert delivery regularly

3. **Respond to Alerts**
   - Renew certificates before expiration
   - Investigate failed health checks
   - Update deployment info as needed

### Backup

1. **Backup CA Key**
   - Vault automatically backs up keys
   - Keep offline backup of Vault data
   - Test restore procedures

2. **Export Certificates**
   - Download certificate bundles for all active certs
   - Store in secure, backed-up location
   - Update backups after renewals

## Troubleshooting

### Certificate Not Trusted

- Ensure Root CA is installed on client device
- Check certificate chain is complete
- Verify hostname matches CN or SAN
- Check certificate is not expired or revoked

### Private Key Mismatch

- Ensure you're using the correct private key
- Verify key file is not corrupted
- Check file permissions

### Service Won't Start

- Check certificate and key file paths
- Verify file permissions (nginx needs read access)
- Review service logs for specific error messages
- Ensure certificate is in correct format (PEM)

### Browser Shows "NET::ERR_CERT_AUTHORITY_INVALID"

- Root CA not installed on this device
- Follow OS-specific installation instructions
- Restart browser after installation

## Advanced Topics

### Certificate Profiles

Create reusable certificate profiles:
- Default profile: 4096-bit, 10 years
- Short-lived profile: 2048-bit, 90 days
- High-security profile: 4096-bit, 1 year

### Batch Issuance

Issue multiple certificates at once via API:

```bash
#!/bin/bash

SERVICES=("grafana" "prometheus" "homeassistant" "proxmox")

for service in "${SERVICES[@]}"; do
  curl -X POST https://pki.homelab.local/api/v1/certificates/issue \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"common_name\": \"${service}.local\",
      \"san_entries\": [\"${service}.local\"],
      \"validity_days\": 3650
    }"
done
```

### Certificate Templates

Save common configurations as templates for quick reuse.

## See Also

- [Security Best Practices](SECURITY.md)
- [Monitoring Configuration](MONITORING.md)
- [API Documentation](API.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)
