# Getting Started

This guide will help you set up and run the HomeLab PKI Platform on your home network.

## Prerequisites

### Required Software

- **Docker**: Version 20.10 or higher
  - [Install Docker for Mac](https://docs.docker.com/desktop/install/mac-install/)
  - [Install Docker for Linux](https://docs.docker.com/engine/install/)
  - [Install Docker for Windows](https://docs.docker.com/desktop/install/windows-install/)

- **Docker Compose**: Version 2.0 or higher (usually included with Docker Desktop)

### System Requirements

- **CPU**: 2 cores minimum (4+ recommended)
- **RAM**: 4GB minimum (8GB+ recommended)
- **Storage**: 10GB free space minimum
- **Network**: Static IP or hostname for your PKI server

## Installation

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd pki
```

### Step 2: Configure Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your preferred settings:

```bash
nano .env
```

Key configuration options:

```bash
# General Settings
PKI_DOMAIN=pki.homelab.local  # Your PKI server hostname
WEB_PORT=8080                  # Web interface port

# Certificate Authority Settings
CA_COMMON_NAME=HomeLab Root CA
CA_ORGANIZATION=HomeLab
CA_COUNTRY=US
CA_VALIDITY_DAYS=7300          # 20 years for root CA

# Default Certificate Settings
DEFAULT_CERT_VALIDITY_DAYS=3650  # 10 years
DEFAULT_KEY_SIZE=4096
DEFAULT_SIGNATURE_ALGORITHM=SHA256

# Monitoring Settings
HEALTH_CHECK_INTERVAL=300      # 5 minutes
HEALTH_CHECK_TIMEOUT=10        # 10 seconds
ALERT_DAYS_BEFORE_EXPIRY=30    # Alert 30 days before expiration

# Database Settings
POSTGRES_USER=pki_user
POSTGRES_PASSWORD=change_this_password
POSTGRES_DB=pki

# Vault Settings
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=                   # Will be generated on first run

# Admin User (created on first run)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_this_password
ADMIN_EMAIL=admin@homelab.local

# Alert Settings
SMTP_ENABLED=false
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
ALERT_EMAIL_FROM=pki@homelab.local
ALERT_EMAIL_TO=admin@homelab.local
```

### Step 3: Start the Platform

Start all services:

```bash
docker-compose up -d
```

Check that all services are running:

```bash
docker-compose ps
```

You should see all services in the "Up" state:
- nginx
- frontend
- backend
- postgres
- vault
- monitor

### Step 4: Initialize the System

Wait for all services to be healthy (about 30 seconds):

```bash
# Check logs
docker-compose logs -f backend
```

Look for: `✓ Application started successfully`

### Step 5: Access the Web Interface

Open your browser and navigate to:

```
http://localhost:8080
```

Or use your configured domain:

```
http://pki.homelab.local:8080
```

**First-time login**:
- Username: `admin` (or your configured `ADMIN_USERNAME`)
- Password: `change_this_password` (or your configured `ADMIN_PASSWORD`)

⚠️ **Change the default password immediately after first login!**

## Initial Setup

### 1. Initialize Certificate Authority

After logging in, you'll be prompted to initialize your Certificate Authority.

1. Go to **Settings** → **Certificate Authority**
2. Review the CA settings:
   - Common Name: `HomeLab Root CA`
   - Organization: `HomeLab`
   - Country: `US`
   - Validity: `7300 days` (20 years)
3. Click **Initialize CA**
4. Wait for initialization to complete (10-20 seconds)
5. Download your Root CA certificate

### 2. Install Root CA Certificate

To trust certificates issued by your PKI, you need to install the Root CA certificate on your devices.

#### macOS

1. Download the Root CA certificate (`HomeLab-Root-CA.crt`)
2. Double-click the certificate file
3. In Keychain Access, select **System** keychain
4. Find the "HomeLab Root CA" certificate
5. Double-click and expand **Trust**
6. Set "When using this certificate" to **Always Trust**
7. Close the window and enter your password

#### Windows

1. Download the Root CA certificate (`HomeLab-Root-CA.crt`)
2. Right-click and select **Install Certificate**
3. Choose **Local Machine** → **Next**
4. Select **Place all certificates in the following store**
5. Click **Browse** → Select **Trusted Root Certification Authorities**
6. Click **Next** → **Finish**
7. Accept the security warning

#### Linux (Ubuntu/Debian)

```bash
# Copy certificate to system trust store
sudo cp HomeLab-Root-CA.crt /usr/local/share/ca-certificates/homelab-root-ca.crt

# Update certificate store
sudo update-ca-certificates
```

#### Firefox (All Platforms)

Firefox uses its own certificate store:

1. Open Firefox Settings
2. Search for "Certificates"
3. Click **View Certificates** → **Authorities** tab
4. Click **Import**
5. Select your Root CA certificate
6. Check **Trust this CA to identify websites**
7. Click **OK**

#### iOS/iPadOS

1. Email the Root CA certificate to yourself or host it on a web server
2. Open the certificate on your device
3. Tap **Allow** to download the profile
4. Go to **Settings** → **Profile Downloaded**
5. Tap **Install** and enter your passcode
6. Tap **Install** again to confirm
7. Go to **Settings** → **General** → **About** → **Certificate Trust Settings**
8. Enable full trust for your Root CA

#### Android

1. Download the Root CA certificate
2. Go to **Settings** → **Security** → **Encryption & credentials**
3. Tap **Install a certificate** → **CA certificate**
4. Tap **Install anyway** (warning message)
5. Navigate to and select your Root CA certificate
6. Name it "HomeLab Root CA"

## Issue Your First Certificate

### Via Web Interface

1. Click **Certificates** in the navigation menu
2. Click **Issue New Certificate**
3. Fill in the certificate details:
   - **Common Name**: `homeassistant.local` (your service hostname)
   - **Subject Alternative Names**: `homeassistant.local, 192.168.1.100`
   - **Validity**: `3650 days` (10 years)
   - **Key Size**: `4096 bits`
4. Click **Issue Certificate**
5. Download the certificate bundle (includes certificate + private key + CA chain)
   - Open the **Certificates** table, click your new certificate, and use **Download Bundle** in the details panel to retrieve the PEM bundle that contains the private key.

### Deploy the Certificate

Extract the bundle and deploy to your web server. Example for nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name homeassistant.local;
    
    ssl_certificate     /etc/nginx/certs/homeassistant.crt;
    ssl_certificate_key /etc/nginx/certs/homeassistant.key;
    
    # Include other SSL settings
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Your application settings
    location / {
        proxy_pass http://localhost:8123;
    }
}
```

### Track Deployment

1. Go back to the certificate details page
2. In the **Deployment** section, add:
   - **Service URL**: `https://homeassistant.local`
   - **Description**: `Home Assistant`
3. Click **Save Deployment Info**

The monitoring service will now automatically check this service every 5 minutes.

## Configure Monitoring

### Set Up Service Monitoring

1. Go to **Monitoring** → **Services**
2. View the list of monitored services
3. Click on a service to customize:
   - **Check Interval**: `300 seconds` (5 minutes)
   - **Timeout**: `10 seconds`
   - **Expected Status Code**: `200`
4. Click **Test Now** to run an immediate check

### Configure Alerts

1. Go to **Settings** → **Alerts**
2. Configure expiration warnings:
   - **30 days before expiration**: Email notification
   - **14 days before expiration**: Email notification
   - **7 days before expiration**: Email + webhook
   - **1 day before expiration**: Email + webhook
3. Set up notification channels:
   - **Email**: Configure SMTP settings in `.env`
   - **Webhook**: Add webhook URLs for services like Slack, Discord, etc.

### Configure Email Alerts (Optional)

Edit `.env` file:

```bash
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_FROM=pki@homelab.local
ALERT_EMAIL_TO=admin@homelab.local
```

Restart the monitor service:

```bash
docker-compose restart monitor
```

## Common Tasks

### View All Certificates

Navigate to **Certificates** to see:
- Active certificates
- Expiration dates
- Deployment status
- Service health status

### Renew a Certificate

1. Go to **Certificates**
2. Click on the certificate to renew
3. Click **Renew Certificate**
4. Download the new certificate bundle
5. Update your deployment

### Revoke a Certificate

1. Go to **Certificates**
2. Click on the certificate to revoke
3. Click **Revoke Certificate**
4. Confirm the action
5. The certificate will be added to the CRL

### Download Root CA Again

Go to **Settings** → **Certificate Authority** → **Download Root CA**

## Troubleshooting

### Services Not Starting

Check service logs:

```bash
docker-compose logs backend
docker-compose logs vault
docker-compose logs monitor
```

### Cannot Access Web Interface

1. Check if nginx is running:
   ```bash
   docker-compose ps nginx
   ```

2. Check nginx logs:
   ```bash
   docker-compose logs nginx
   ```

3. Verify port is not in use:
   ```bash
   lsof -i :8080
   ```

### Vault Sealed

If Vault becomes sealed:

```bash
docker-compose exec vault vault operator unseal
```

Enter the unseal key(s) when prompted.

### Database Connection Issues

Restart PostgreSQL:

```bash
docker-compose restart postgres
```

Check database logs:

```bash
docker-compose logs postgres
```

### Monitoring Not Working

1. Check monitor service logs:
   ```bash
   docker-compose logs monitor
   ```

2. Verify deployment URLs are correct
3. Check firewall rules if services are on different networks

## Updating the Platform

### Pull Latest Changes

```bash
git pull origin main
```

### Rebuild Containers

```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Backup Before Updating

```bash
# Backup database
docker-compose exec postgres pg_dump -U pki_user pki > backup.sql

# Backup Vault data
docker-compose exec vault vault operator raft snapshot save /vault/data/snapshot.snap
docker cp pki_vault_1:/vault/data/snapshot.snap ./vault-backup.snap
```

## Next Steps

- [Certificate Management Guide](CERTIFICATE_MANAGEMENT.md)
- [Monitoring Configuration](MONITORING.md)
- [Security Best Practices](SECURITY.md)
- [API Documentation](API.md)
- [Development Guide](DEVELOPMENT.md)

## Getting Help

- Check the [FAQ](FAQ.md)
- Review [Troubleshooting Guide](TROUBLESHOOTING.md)
- Open an issue on GitHub
- Join community discussions
