# Monitoring Guide

Complete guide to monitoring certificates and services in the HomeLab PKI Platform.

## Overview

The monitoring system provides:
- Automated health checks for services using issued certificates
- Certificate expiration tracking
- Alert generation and delivery
- Real-time status dashboard
- Historical monitoring data

## Monitoring Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Monitor Service                           │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │  Scheduler   │───▶│ Health Check │───▶│    Alert     │ │
│  │ (APScheduler)│    │   Engine     │    │   Manager    │ │
│  └──────────────┘    └──────────────┘    └──────────────┘ │
│         │                    │                    │         │
└─────────┼────────────────────┼────────────────────┼─────────┘
          │                    │                    │
          ▼                    ▼                    ▼
   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
   │   Database   │   │   Services   │   │ Notification │
   │   (Status)   │   │  (HTTPS)     │   │  Channels    │
   └──────────────┘   └──────────────┘   └──────────────┘
```

## Service Monitoring

### How It Works

1. **Certificate Deployment**: When you add deployment information to a certificate, monitoring is automatically enabled
2. **Scheduled Checks**: Monitor service runs health checks at configured intervals
3. **Status Updates**: Results are stored in the database
4. **Alert Generation**: Alerts are created based on configured rules
5. **Notifications**: Alerts are sent via configured channels

### Health Check Types

#### SSL/TLS Certificate Validation

Verifies:
- Certificate chain validity
- Certificate not expired
- Hostname matches certificate
- Certificate not revoked
- Certificate signature valid
- Using secure cipher suite

#### Service Availability

Checks:
- Service responds to HTTPS request
- Response time within threshold
- Expected HTTP status code
- Optional: Custom health endpoint

#### Expiration Monitoring

Monitors:
- Days until certificate expiration
- Triggers alerts based on thresholds
- Multiple alert levels (30, 14, 7, 1 days)

## Configuration

### Enable Monitoring for a Certificate

#### Via Web Interface

1. Go to **Certificates** → Select certificate
2. Scroll to **Deployment Information**
3. Click **Add Deployment**
4. Fill in:
   - **Service URL**: `https://grafana.local`
   - **Service Name**: `Grafana`
   - **Description**: `Monitoring and visualization`
   - **Location**: `Docker container - server1`
5. Click **Save**

Monitoring will start automatically within the next check interval.

#### Via API

```bash
curl -X POST https://pki.homelab.local/api/v1/certificates/cert_123456/deployment \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://grafana.local",
    "name": "Grafana",
    "description": "Monitoring dashboard",
    "location": "Docker - server1"
  }'
```

### Configure Check Interval

#### Global Settings

Edit `.env` file:

```bash
# Default check interval for all services (seconds)
HEALTH_CHECK_INTERVAL=300  # 5 minutes

# Timeout for health checks (seconds)
HEALTH_CHECK_TIMEOUT=10

# Retry count for failed checks
HEALTH_CHECK_RETRY_COUNT=3

# Delay between retries (seconds)
HEALTH_CHECK_RETRY_DELAY=30
```

Restart monitor service:
```bash
docker-compose restart monitor
```

#### Per-Service Settings

1. Go to **Monitoring** → **Services**
2. Click on service to configure
3. Adjust settings:
   - **Check Interval**: `60-3600 seconds`
   - **Timeout**: `5-60 seconds`
   - **Enabled**: Toggle monitoring on/off
4. Click **Save**

### Custom Health Endpoints

Some services provide dedicated health endpoints:

```bash
# Configure custom health endpoint
curl -X PATCH https://pki.homelab.local/api/v1/monitoring/service_123 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "health_endpoint": "/api/health",
    "expected_status": 200,
    "expected_content": "healthy"
  }'
```

### Advanced Check Configuration

#### Custom Headers

Add authentication headers for protected services:

```json
{
  "url": "https://grafana.local",
  "headers": {
    "Authorization": "Bearer grafana-token",
    "X-Custom-Header": "value"
  }
}
```

#### Status Code Expectations

Specify acceptable status codes:

```json
{
  "url": "https://api.homelab.local",
  "expected_status_codes": [200, 202, 204]
}
```

#### Response Time Thresholds

Set alerts for slow responses:

```json
{
  "url": "https://homeassistant.local",
  "response_time_warning": 2000,   // milliseconds
  "response_time_critical": 5000   // milliseconds
}
```

## Monitoring Dashboard

### View Service Status

Navigate to **Monitoring** → **Dashboard**

**Status Indicators:**
- 🟢 **Green**: Service healthy, certificate valid
- 🟡 **Yellow**: Warning (slow response, expiring soon)
- 🔴 **Red**: Service down or certificate invalid
- ⚪ **Gray**: Monitoring disabled or not configured

### Dashboard Features

#### Service List

| Service | Status | Last Check | Response Time | Expires In |
|---------|--------|------------|---------------|------------|
| Home Assistant | 🟢 | 2 min ago | 145ms | 347 days |
| Grafana | 🟡 | 1 min ago | 2.3s | 28 days |
| Proxmox | 🟢 | 3 min ago | 89ms | 512 days |
| API Server | 🔴 | 5 min ago | Timeout | 156 days |

#### Filters

- **Status**: Show only services with specific status
- **Expiration**: Show certificates expiring within X days
- **Location**: Filter by deployment location
- **Service Type**: Filter by service name/type

#### Bulk Actions

- **Test All**: Trigger manual check for all services
- **Enable All**: Enable monitoring for all services
- **Disable All**: Disable monitoring for all services
- **Export**: Export monitoring data as CSV

### Service Details

Click on a service to view:

**Current Status:**
- Health status (up/down)
- Certificate validity
- Last check timestamp
- Response time
- SSL/TLS details

**Certificate Information:**
- Issuer
- Valid from/to
- Serial number
- Expiration countdown

**Check History:**
- Graph of response times
- Uptime percentage
- Recent check results

**Alerts:**
- Active alerts
- Alert history
- Notification status

## Manual Health Checks

### Trigger Single Check

#### Via Web Interface

1. Go to **Monitoring** → **Services**
2. Click on service
3. Click **Test Now** button
4. Wait for check to complete (5-10 seconds)
5. View results

#### Via API

```bash
curl -X POST https://pki.homelab.local/api/v1/monitoring/service_123/check \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

Response:
```json
{
  "status": "healthy",
  "response_time_ms": 145,
  "ssl_valid": true,
  "ssl_expires_in_days": 347,
  "checked_at": "2025-11-13T10:30:00Z",
  "details": {
    "status_code": 200,
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "protocol": "TLSv1.3"
  }
}
```

### Bulk Testing

Test all services at once:

```bash
curl -X POST https://pki.homelab.local/api/v1/monitoring/check-all \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Alert Configuration

### Alert Types

1. **Certificate Expiration**
   - 30 days before expiration
   - 14 days before expiration
   - 7 days before expiration
   - 1 day before expiration
   - Certificate expired

2. **Service Health**
   - Service down (failed health check)
   - Service slow (response time threshold)
   - SSL/TLS error (certificate validation failed)

3. **Certificate Revocation**
   - Certificate revoked

### Configure Expiration Alerts

Edit `.env`:

```bash
# Alert thresholds (days before expiration)
ALERT_THRESHOLD_WARNING=30
ALERT_THRESHOLD_URGENT=14
ALERT_THRESHOLD_CRITICAL=7
ALERT_THRESHOLD_EMERGENCY=1

# Alert frequency (hours between repeat alerts)
ALERT_FREQUENCY_WARNING=168    # 7 days
ALERT_FREQUENCY_URGENT=48      # 2 days
ALERT_FREQUENCY_CRITICAL=24    # 1 day
ALERT_FREQUENCY_EMERGENCY=6    # 6 hours
```

### Configure Service Health Alerts

Via Web Interface:

1. Go to **Settings** → **Alerts** → **Health Monitoring**
2. Configure:
   - **Alert on first failure**: Yes/No
   - **Alert after consecutive failures**: 3 (default)
   - **Alert on recovery**: Yes/No
3. Click **Save**

### Per-Certificate Alert Rules

Create custom alert rules for specific certificates:

1. Go to **Certificates** → Select certificate
2. Click **Alert Rules** tab
3. Click **Add Rule**
4. Configure:
   - **Rule Name**: `Critical Service Alert`
   - **Alert Type**: `Expiration` or `Health`
   - **Threshold**: `14 days` or `2 failed checks`
   - **Severity**: `Critical`
   - **Notification Channels**: Email, Webhook
5. Click **Save**

## Notification Channels

### Email Notifications

#### Configuration

Edit `.env`:

```bash
# Enable email notifications
SMTP_ENABLED=true

# SMTP server settings
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password

# Email settings
ALERT_EMAIL_FROM=pki@homelab.local
ALERT_EMAIL_TO=admin@homelab.local,team@homelab.local
ALERT_EMAIL_SUBJECT_PREFIX=[PKI Alert]
```

#### Gmail Setup

1. Enable 2-factor authentication
2. Generate app-specific password:
   - Go to Google Account → Security
   - Select "App passwords"
   - Generate password for "Mail"
3. Use app password in `SMTP_PASSWORD`

#### Test Email

```bash
curl -X POST https://pki.homelab.local/api/v1/alerts/test/email \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "admin@homelab.local",
    "subject": "Test Alert",
    "message": "This is a test email from PKI platform"
  }'
```

### Webhook Notifications

Send alerts to external services (Slack, Discord, custom endpoints).

#### Slack Integration

1. Create Slack Incoming Webhook:
   - Go to Slack App Directory
   - Search for "Incoming WebHooks"
   - Add to workspace
   - Copy webhook URL

2. Configure in PKI platform:

```bash
# Add to .env
WEBHOOK_SLACK_ENABLED=true
WEBHOOK_SLACK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

Or via Web Interface:
1. Go to **Settings** → **Notifications** → **Webhooks**
2. Click **Add Webhook**
3. Fill in:
   - **Name**: `Slack - #homelab`
   - **URL**: `https://hooks.slack.com/services/...`
   - **Method**: `POST`
   - **Content Type**: `application/json`
   - **Template**: Use Slack template
4. Click **Save**

#### Discord Integration

Similar to Slack:

1. Create Discord Webhook:
   - Server Settings → Integrations → Webhooks
   - Create webhook
   - Copy URL

2. Configure:
```bash
WEBHOOK_DISCORD_ENABLED=true
WEBHOOK_DISCORD_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK
```

#### Custom Webhooks

Send to any HTTP endpoint:

```json
{
  "name": "Custom Monitoring System",
  "url": "https://monitoring.homelab.local/api/alerts",
  "method": "POST",
  "headers": {
    "Authorization": "Bearer custom-token",
    "Content-Type": "application/json"
  },
  "body_template": {
    "event_type": "{{alert_type}}",
    "severity": "{{severity}}",
    "certificate": "{{common_name}}",
    "message": "{{message}}",
    "timestamp": "{{timestamp}}"
  }
}
```

### Mobile Push Notifications (via Pushover)

```bash
# Add to .env
PUSHOVER_ENABLED=true
PUSHOVER_USER_KEY=your-user-key
PUSHOVER_API_TOKEN=your-api-token
PUSHOVER_PRIORITY=0  # -2 to 2
```

## Monitoring Data & Reporting

### View Historical Data

1. Go to **Monitoring** → **History**
2. Select date range
3. Filter by service, status, or certificate
4. View:
   - Check results over time
   - Response time graphs
   - Uptime percentage
   - Alert frequency

### Export Monitoring Data

```bash
# Export as CSV
curl https://pki.homelab.local/api/v1/monitoring/export \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d "format=csv&start_date=2025-01-01&end_date=2025-11-13" \
  > monitoring-data.csv

# Export as JSON
curl https://pki.homelab.local/api/v1/monitoring/export \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d "format=json" \
  > monitoring-data.json
```

### Uptime Reports

Generate uptime reports:

1. Go to **Monitoring** → **Reports**
2. Select:
   - **Report Type**: `Uptime Report`
   - **Period**: `Last 30 days`
   - **Services**: Select services
3. Click **Generate Report**

Report includes:
- Overall uptime percentage
- Average response time
- Number of incidents
- Mean time to detection (MTTD)
- Certificate status

### Automated Reports

Schedule automated reports via email:

1. Go to **Settings** → **Reports**
2. Click **Add Scheduled Report**
3. Configure:
   - **Report Type**: `Weekly Uptime Report`
   - **Schedule**: `Every Monday at 9:00 AM`
   - **Recipients**: `admin@homelab.local`
   - **Format**: `PDF`
4. Click **Save**

## Troubleshooting

### Monitoring Not Working

**Check monitor service status:**
```bash
docker-compose ps monitor
docker-compose logs monitor
```

**Common issues:**
- Monitor service not running
- Database connection failed
- Invalid service URLs

### Health Checks Failing

**Possible causes:**
1. Service actually down
2. Network connectivity issues
3. Firewall blocking health checks
4. Certificate mismatch
5. Timeout too short

**Debug:**
```bash
# Test manually with curl
curl -v https://homeassistant.local

# Check certificate
openssl s_client -connect homeassistant.local:443 -servername homeassistant.local

# Check from monitor container
docker-compose exec monitor curl -v https://homeassistant.local
```

### Alerts Not Sending

**Check alert configuration:**
1. Go to **Settings** → **Alerts**
2. Verify notification channels are enabled
3. Check SMTP settings
4. Test notification delivery

**Check logs:**
```bash
docker-compose logs monitor | grep -i alert
```

### False Positives

Reduce false positives:
1. Increase retry count
2. Add retry delay
3. Adjust timeout values
4. Use consecutive failure threshold

## Best Practices

### Monitoring Strategy

1. **Start Simple**: Enable basic health checks for all services
2. **Tune Thresholds**: Adjust based on actual service behavior
3. **Alert Fatigue**: Don't over-alert; use appropriate thresholds
4. **Regular Review**: Check monitoring dashboard weekly

### Alert Management

1. **Prioritize Alerts**: Not all alerts need immediate attention
2. **Multiple Channels**: Use email for low priority, push for critical
3. **On-Call Rotation**: If running critical services, set up rotation
4. **Alert Escalation**: Configure escalation paths for unacknowledged alerts

### Performance

1. **Check Intervals**: Balance monitoring frequency with resource usage
2. **Batch Checks**: Monitor service batches checks efficiently
3. **Database Cleanup**: Regularly archive old monitoring data
4. **Resource Limits**: Ensure monitor service has adequate resources

### Security

1. **Secure Webhooks**: Use HTTPS for webhook endpoints
2. **Authenticate Webhooks**: Verify webhook signatures
3. **Limit Data**: Don't include sensitive data in alerts
4. **Audit Access**: Monitor who accesses monitoring data

## Advanced Topics

### Custom Health Check Scripts

Write custom check scripts for complex services:

```python
# custom_check.py
import requests
import sys

def check_service(url):
    try:
        response = requests.get(f"{url}/api/health", timeout=5)
        health_data = response.json()
        
        if health_data.get('status') == 'healthy':
            print(f"OK: Service healthy")
            return 0
        else:
            print(f"WARNING: Service degraded - {health_data.get('message')}")
            return 1
    except Exception as e:
        print(f"CRITICAL: Service down - {str(e)}")
        return 2

if __name__ == "__main__":
    url = sys.argv[1]
    sys.exit(check_service(url))
```

### Integration with External Monitoring

Forward monitoring data to external systems:

```bash
# Prometheus metrics endpoint
curl https://pki.homelab.local/api/v1/monitoring/metrics
```

### API-Based Monitoring

Query monitoring data programmatically:

```python
import requests

def get_service_status(api_url, token):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{api_url}/api/v1/monitoring/services", headers=headers)
    return response.json()

def check_expired_certs(services):
    expiring_soon = [s for s in services if s['expires_in_days'] < 30]
    return expiring_soon
```

## See Also

- [Certificate Management](CERTIFICATE_MANAGEMENT.md)
- [Alert Configuration](ALERTS.md)
- [API Documentation](API.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)
