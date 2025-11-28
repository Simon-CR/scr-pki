# Deployment Guide

Production deployment guide for the HomeLab PKI Platform.

## Deployment Options

### Option 1: Docker Compose (Recommended for Home Lab)

Simple, single-server deployment using Docker Compose.

**Pros:**
- Easy to set up and maintain
- All services on one host
- Built-in networking
- Simple backups

**Cons:**
- Single point of failure
- Limited scalability
- Resource contention

**Best for:**
- Home lab environments
- 1-50 certificates
- Single administrator

### Option 2: Docker Swarm

Multi-node deployment with orchestration.

**Pros:**
- High availability
- Load balancing
- Service replication
- Rolling updates

**Cons:**
- More complex setup
- Requires multiple hosts
- More overhead

**Best for:**
- Larger home labs
- 50+ certificates
- Multiple administrators
- Critical infrastructure

### Option 3: Kubernetes

Enterprise-grade orchestration (overkill for most home labs).

**Pros:**
- Maximum scalability
- Advanced features
- Industry standard
- Rich ecosystem

**Cons:**
- Very complex
- High resource requirements
- Steep learning curve

**Best for:**
- Large scale deployments
- Multiple locations
- Enterprise environments

## Docker Compose Deployment (Recommended)

### Hardware Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 4GB
- Storage: 20GB
- Network: 100Mbps

**Recommended:**
- CPU: 4 cores
- RAM: 8GB
- Storage: 50GB SSD
- Network: 1Gbps

### Server Selection

**Suitable Hardware:**
- Raspberry Pi 4 (4GB+ RAM)
- Intel NUC
- Old desktop/laptop
- Virtual machine
- Proxmox LXC container

**Operating System:**
- Ubuntu Server 22.04 LTS (recommended)
- Debian 11/12
- Rocky Linux 9
- Any Linux with Docker support

### Pre-Installation Steps

#### 1. Update System

```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# RHEL/Rocky
sudo dnf update -y
```

#### 2. Install Docker

```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Log out and back in for group changes to take effect

# Verify installation
docker --version
docker compose version
```

#### 3. Configure Firewall

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp  # SSH
sudo ufw enable

# RHEL/Rocky (firewalld)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

#### 4. Set Static IP (Optional but Recommended)

```bash
# Ubuntu - netplan
sudo nano /etc/netplan/01-netcfg.yaml
```

```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: no
      addresses:
        - 192.168.1.10/24
      gateway4: 192.168.1.1
      nameservers:
        addresses: [192.168.1.1, 8.8.8.8]
```

```bash
sudo netplan apply
```

#### 5. Configure DNS (Optional)

Add DNS entry for your PKI server:
- Domain: `pki.homelab.local`
- IP: Your server IP

Or add to `/etc/hosts` on client machines:
```
192.168.1.10  pki.homelab.local pki
```

### Installation

#### 1. Clone Repository

```bash
cd /opt
sudo git clone <repository-url> pki
cd pki
sudo chown -R $USER:$USER /opt/pki
```

#### 2. Configure Environment

```bash
cp .env.example .env
nano .env
```

**Critical settings to change:**

```bash
# Domain and Ports
PKI_DOMAIN=pki.homelab.local
WEB_PORT=443

# Host Validation - Set to your domain(s) to prevent host header injection
# Comma-separated list of allowed hostnames
ALLOWED_HOSTS=pki.homelab.local,localhost,127.0.0.1

# Change ALL default passwords
POSTGRES_PASSWORD=<generate-strong-password>
ADMIN_PASSWORD=<generate-strong-password>
VAULT_TOKEN=<will-be-generated-during-init>

# CA Configuration
CA_COMMON_NAME=HomeLab Root CA
CA_ORGANIZATION=Your HomeLab
CA_COUNTRY=US

# Password Policy (optional - defaults are permissive for home lab)
# PASSWORD_MIN_LENGTH=8
# PASSWORD_REQUIRE_UPPERCASE=false
# PASSWORD_REQUIRE_LOWERCASE=false
# PASSWORD_REQUIRE_DIGIT=false
# PASSWORD_REQUIRE_SPECIAL=false

# Email Alerts (optional)
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=admin@homelab.local

# Monitoring
HEALTH_CHECK_INTERVAL=300
ALERT_DAYS_BEFORE_EXPIRY=30
```

**Generate secure passwords:**
```bash
# Generate random passwords
openssl rand -base64 32
```

#### 3. Create Required Directories

```bash
mkdir -p data/{postgres,vault,certs,logs,backups}
chmod 700 data/vault
chmod 700 data/certs
```

#### 4. Configure Docker Compose

Review `docker-compose.yml` and adjust resource limits if needed:

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
```

#### 5. Start Services

```bash
# Pull images
docker compose pull

# Start services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f
```

#### 6. Initialize Vault

**First time only:**

```bash
# Initialize Vault
docker compose exec vault vault operator init -key-shares=5 -key-threshold=3

# Save the output securely! You'll get:
# - 5 unseal keys (need 3 to unseal)
# - 1 root token

# Example output:
Unseal Key 1: ABC123...
Unseal Key 2: DEF456...
Unseal Key 3: GHI789...
Unseal Key 4: JKL012...
Unseal Key 5: MNO345...

Initial Root Token: s.XYZ789...

# SAVE THESE SECURELY! Store in password manager or encrypted file
```

**Unseal Vault:**

```bash
# Unseal with 3 of 5 keys
docker compose exec vault vault operator unseal
# Enter key 1

docker compose exec vault vault operator unseal
# Enter key 2

docker compose exec vault vault operator unseal
# Enter key 3

# Verify unsealed
docker compose exec vault vault status
```

**Configure Vault:**

```bash
# Login with root token
docker compose exec vault vault login
# Enter root token

# Enable audit logging
docker compose exec vault vault audit enable file file_path=/vault/logs/audit.log

# Create policy for backend service
docker compose exec vault vault policy write pki-backend /vault/config/policy.hcl
```

#### 7. Update Environment with Vault Token

```bash
# Add Vault token to .env
nano .env
```

```bash
VAULT_TOKEN=s.XYZ789...  # Root token from initialization
```

```bash
# Restart backend to use Vault token
docker compose restart backend
```

#### 8. Initialize Application

```bash
# Run database migrations
docker compose exec backend alembic upgrade head

# Create admin user
docker compose exec backend python -m app.cli create-admin

# Initialize CA
docker compose exec backend python -m app.cli init-ca
```

#### 9. Verify Installation

```bash
# Check all services are healthy
docker compose ps

# Check logs for errors
docker compose logs backend
docker compose logs frontend
docker compose logs monitor

# Access web interface
curl -k https://pki.homelab.local
# Or open in browser
```

#### 10. Download Root CA Certificate

1. Open web interface: `https://pki.homelab.local`
2. Login with admin credentials
3. Go to **Settings** → **Certificate Authority**
4. Click **Download Root CA Certificate**
5. Install on all devices (see [GETTING_STARTED.md](GETTING_STARTED.md))

### Post-Installation

#### 1. Change Admin Password

```bash
# Via web interface
Settings → Account → Change Password

# Or via CLI
docker compose exec backend python -m app.cli change-password admin
```

#### 2. Configure Backups

```bash
# Create backup script
nano /opt/pki/scripts/backup.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/opt/pki/data/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup database
docker compose exec -T postgres pg_dump -U pki_user pki | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# Backup Vault
docker compose exec vault vault operator raft snapshot save /vault/data/snapshot_$DATE.snap
docker cp pki_vault_1:/vault/data/snapshot_$DATE.snap "$BACKUP_DIR/"

# Backup certificates
tar -czf "$BACKUP_DIR/certs_$DATE.tar.gz" data/certs/

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.snap" -mtime +30 -delete

echo "Backup completed: $DATE"
```

```bash
chmod +x /opt/pki/scripts/backup.sh

# Add to crontab (daily at 2 AM)
crontab -e
```

```
0 2 * * * /opt/pki/scripts/backup.sh >> /opt/pki/data/logs/backup.log 2>&1
```

#### 3. Configure Log Rotation

```bash
sudo nano /etc/logrotate.d/pki
```

```
/opt/pki/data/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        docker compose -f /opt/pki/docker-compose.yml restart backend monitor
    endscript
}
```

#### 4. Set Up Monitoring

```bash
# Install monitoring tools (optional)
sudo apt install prometheus-node-exporter

# Or use existing monitoring (Grafana, Prometheus, etc.)
```

#### 5. Configure Automatic Updates (Optional)

```bash
# Auto-update system packages
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# For Docker images, create update script
nano /opt/pki/scripts/update.sh
```

```bash
#!/bin/bash
cd /opt/pki

# Pull latest images
docker compose pull

# Backup before update
./scripts/backup.sh

# Restart with new images
docker compose up -d

echo "Update completed: $(date)"
```

## SSL/TLS Certificate for Web Interface

### Option 1: Self-Signed Certificate (Bootstrap)

Initially, use a self-signed certificate:

```bash
cd /opt/pki/nginx/ssl

# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=pki.homelab.local"

# Set permissions
chmod 600 server.key
chmod 644 server.crt
```

### Option 2: Certificate from PKI Platform

Once PKI platform is running, issue its own certificate:

1. Access web interface (accept self-signed cert warning)
2. Issue certificate for `pki.homelab.local`
3. Download certificate bundle
4. Replace nginx certificates:

```bash
cd /opt/pki/nginx/ssl
cp ~/Downloads/pki.homelab.local.crt server.crt
cp ~/Downloads/pki.homelab.local.key server.key
chmod 600 server.key
chmod 644 server.crt

# Reload nginx
docker compose restart nginx
```

### Option 3: Let's Encrypt (If Publicly Accessible)

Only if PKI server is accessible from internet:

```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone \
  -d pki.yourdomain.com \
  --email your-email@example.com

# Copy certificates
sudo cp /etc/letsencrypt/live/pki.yourdomain.com/fullchain.pem /opt/pki/nginx/ssl/server.crt
sudo cp /etc/letsencrypt/live/pki.yourdomain.com/privkey.pem /opt/pki/nginx/ssl/server.key

# Set up auto-renewal
sudo certbot renew --dry-run
```

## Production Hardening

### 1. Network Security

```bash
# Restrict access to specific networks
# In nginx.conf:
```

```nginx
location / {
    allow 192.168.1.0/24;  # Home network
    deny all;
}
```

### 2. Rate Limiting

```nginx
# In nginx.conf
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    
    server {
        location /api/ {
            limit_req zone=api burst=20;
        }
    }
}
```

### 3. Fail2ban Integration

```bash
sudo apt install fail2ban

sudo nano /etc/fail2ban/jail.local
```

```ini
[pki-auth]
enabled = true
port = http,https
logpath = /opt/pki/data/logs/backend.log
maxretry = 5
findtime = 600
bantime = 3600
```

### 4. Security Headers

Already configured in nginx.conf:
- HSTS
- X-Frame-Options
- X-Content-Type-Options
- CSP

### 5. Regular Security Updates

```bash
# Create update schedule
crontab -e
```

```
# Security updates - weekly on Sunday 3 AM
0 3 * * 0 apt update && apt upgrade -y
```

## Monitoring and Alerting

### Application Monitoring

Monitor via web dashboard or set up external monitoring:

```bash
# Prometheus metrics (if enabled)
curl http://localhost:8000/metrics

# Health check endpoint
curl http://localhost:8000/api/v1/health
```

### Docker Monitoring

```bash
# View resource usage
docker stats

# Monitor logs
docker compose logs -f --tail=100

# Set up log aggregation (optional)
# - ELK Stack
# - Loki + Grafana
# - Splunk
```

### System Monitoring

```bash
# Install monitoring tools
sudo apt install htop iotop nethogs

# Check system resources
htop
df -h
free -h
```

## Backup and Recovery

### Automated Backups

Already configured in post-installation. Verify:

```bash
# Check backup cronjob
crontab -l

# Manually run backup
/opt/pki/scripts/backup.sh

# Verify backups exist
ls -lh /opt/pki/data/backups/
```

### Off-Site Backups

```bash
# Sync to remote server
rsync -avz /opt/pki/data/backups/ user@backup-server:/backups/pki/

# Or use cloud storage
# AWS S3
aws s3 sync /opt/pki/data/backups/ s3://your-bucket/pki-backups/

# Backblaze B2
b2 sync /opt/pki/data/backups/ b2://your-bucket/pki-backups/
```

### Restore Procedure

```bash
# Stop services
docker compose down

# Restore database
gunzip < /opt/pki/data/backups/db_20251113_020000.sql.gz | \
  docker compose exec -T postgres psql -U pki_user pki

# Restore Vault
docker compose up -d vault
docker compose exec vault vault operator unseal  # Unseal 3 times
docker cp /opt/pki/data/backups/snapshot_20251113_020000.snap pki_vault_1:/tmp/
docker compose exec vault vault operator raft snapshot restore /tmp/snapshot_20251113_020000.snap

# Restore certificates
tar -xzf /opt/pki/data/backups/certs_20251113_020000.tar.gz -C /opt/pki/

# Start services
docker compose up -d
```

## Scaling and High Availability

### Add Read Replicas

For read-heavy workloads:

```yaml
# docker-compose.yml
services:
  postgres-replica:
    image: postgres:15-alpine
    environment:
      POSTGRES_MASTER: postgres
    # Configure replication
```

### Load Balancing

Use multiple backend instances:

```yaml
services:
  backend-1:
    build: ./backend
    # configuration
  
  backend-2:
    build: ./backend
    # configuration
  
  nginx:
    depends_on:
      - backend-1
      - backend-2
```

Update nginx.conf:
```nginx
upstream backend {
    server backend-1:8000;
    server backend-2:8000;
}
```

## Troubleshooting

### Services Won't Start

```bash
# Check logs
docker compose logs

# Check disk space
df -h

# Check memory
free -h

# Restart services
docker compose restart
```

### Vault Sealed After Restart

```bash
# This is normal - unseal Vault
docker compose exec vault vault operator unseal
# Repeat 3 times with different keys
```

### Database Connection Issues

```bash
# Check PostgreSQL logs
docker compose logs postgres

# Restart database
docker compose restart postgres

# Verify connection
docker compose exec postgres psql -U pki_user -d pki -c "SELECT 1;"
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Increase resources in docker-compose.yml
# Restart services
docker compose down && docker compose up -d
```

## Maintenance

### Regular Tasks

**Daily:**
- Check monitoring dashboard
- Review alerts
- Verify backups completed

**Weekly:**
- Review audit logs
- Check for certificate expirations
- Update system packages

**Monthly:**
- Review issued certificates
- Clean up old certificates
- Test restore procedures
- Review security settings

**Quarterly:**
- Full security audit
- Rotate credentials
- Update documentation
- Capacity planning

## Migration and Upgrades

### Upgrading Application

```bash
cd /opt/pki

# Backup first!
./scripts/backup.sh

# Pull latest code
git pull origin main

# Pull new images
docker compose pull

# Run migrations
docker compose up -d postgres
docker compose exec backend alembic upgrade head

# Restart all services
docker compose up -d
```

### Migrating to New Server

```bash
# On old server - backup everything
./scripts/backup.sh
tar -czf pki-complete-backup.tar.gz data/

# Transfer to new server
scp pki-complete-backup.tar.gz newserver:/opt/

# On new server - extract and restore
cd /opt
tar -xzf pki-complete-backup.tar.gz
# Follow installation steps
# Run restore procedures
```

## See Also

- [Getting Started Guide](GETTING_STARTED.md)
- [Security Guide](SECURITY.md)
- [Development Guide](DEVELOPMENT.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)
- [Backup and Recovery](BACKUP_RECOVERY.md)
