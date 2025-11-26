# Frequently Asked Questions

Common questions about the HomeLab PKI Platform.

## General

### What is a PKI platform?

PKI (Public Key Infrastructure) is a system for creating, managing, and distributing digital certificates. This platform lets you run your own Certificate Authority (CA) to issue SSL/TLS certificates for services in your home lab, eliminating browser security warnings.

### Why would I need this?

If you run web services in your home lab (Home Assistant, Grafana, Proxmox, etc.), you've probably seen "Your connection is not secure" warnings. This platform lets you issue proper SSL certificates that your browsers will trust, removing those warnings.

### Is this production-ready?

This platform is designed for **home lab and private network use only**. It's not intended for public-facing production environments or commercial use. However, it implements industry-standard cryptography and security practices suitable for home use.

### Is it free?

Yes! This project is open source under the MIT license. It's completely free to use, modify, and distribute.

## Installation & Setup

### What are the system requirements?

**Minimum:**
- 2 CPU cores
- 4GB RAM
- 20GB storage
- Docker 20.10+
- Docker Compose 2.0+

**Recommended:**
- 4 CPU cores
- 8GB RAM
- 50GB SSD storage

### Can I run this on a Raspberry Pi?

Yes! A Raspberry Pi 4 with 4GB+ RAM works well. Installation process is the same as any Linux system.

### How long does installation take?

Initial setup takes about 15-30 minutes, including:
- Docker container download and startup
- Vault initialization
- CA creation
- First certificate issuance

### Do I need a domain name?

No! You can use `.local` hostnames or IP addresses. The platform works entirely within your private network.

### Can I use this with Let's Encrypt?

This platform is an alternative to Let's Encrypt for private networks. Let's Encrypt requires public internet access and domain validation, which doesn't work for internal-only services.

## Certificates

### How many certificates can I issue?

There's no hard limit. The platform can easily handle hundreds of certificates. For larger deployments (1000+), you may need to increase system resources.

### How long can certificates be valid?

You can set any validity period up to 20 years (7300 days). For home lab use, 10 years (3650 days) is a good default. This is much longer than public CAs allow (typically 1 year maximum).

### Can I issue wildcard certificates?

Yes! Issue a certificate with common name `*.homelab.local` to cover all subdomains.

### What's the difference between certificate types?

Currently, the platform primarily supports **server certificates** for web services. Future versions will support:
- Client certificates (for authentication)
- Code signing certificates
- Email signing certificates

### Can I import existing certificates?

Not yet, but this feature is planned for a future release.

### What happens when a certificate expires?

The monitoring system will alert you before expiration. You'll need to:
1. Renew the certificate via the web interface
2. Download the new certificate
3. Deploy it to your service
4. Restart the service

## Security

### Is it secure to run my own CA?

Yes, if properly secured. The platform implements:
- Secure key storage in Vault
- Strong cryptographic algorithms
- Audit logging
- Network isolation

However, you're responsible for:
- Securing the host system
- Protecting the Vault unseal keys
- Regular backups
- Following security best practices

### What if the CA key is compromised?

If your CA private key is compromised:
1. All issued certificates become untrustworthy
2. You'll need to create a new CA
3. Re-issue all certificates
4. Re-install the new root CA on all devices

**Prevention:** Keep backups secure, limit access, monitor audit logs.

### Should I install the root CA on all my devices?

Yes, to avoid security warnings. Install the root CA certificate on:
- Desktop computers
- Laptops
- Mobile devices
- Any device that will access your home lab services

### Can I use this for public-facing websites?

**No.** This platform is designed for private networks only. For public websites:
- Use Let's Encrypt (free)
- Use a commercial CA
- Use a cloud provider's certificate service

### What encryption algorithms are supported?

**Key Types:**
- RSA (2048, 4096 bits)
- ECDSA (planned for future release)

**Hash Functions:**
- SHA-256 (default)
- SHA-384
- SHA-512

**TLS Versions:**
- TLS 1.3 (preferred)
- TLS 1.2 (minimum)

## Monitoring

### How does monitoring work?

The monitor service periodically:
1. Makes HTTPS requests to services
2. Validates SSL certificates
3. Measures response time
4. Updates status in database
5. Triggers alerts if needed

### Can I monitor services on different networks?

Yes, as long as the PKI server can reach those services over the network. Configure firewall rules accordingly.

### What happens if a service goes down?

1. Monitor detects failure
2. Retries according to configuration
3. If still failing, changes status to "down"
4. Triggers alerts via configured channels
5. Records incident in database

### Can I disable monitoring for specific certificates?

Yes. In the certificate deployment settings, you can:
- Disable monitoring entirely
- Adjust check interval
- Temporarily pause checks

## Troubleshooting

### Services won't start

**Check:**
```bash
docker-compose ps
docker-compose logs
```

**Common causes:**
- Port already in use
- Insufficient disk space
- Insufficient memory
- Docker not running

### Vault is sealed

This is normal after restart. Unseal Vault:
```bash
docker-compose exec vault vault operator unseal
# Repeat 3 times with different keys
```

Consider enabling auto-unseal for production use.

### Can't access web interface

**Check:**
1. Is nginx running? `docker-compose ps nginx`
2. Correct port? Default is 8080
3. Firewall rules? Allow port 8080
4. Browser cache? Try incognito mode

### Certificates not trusted in browser

**Ensure:**
1. Root CA installed on device
2. Browser restarted after installation
3. Firefox users: Install in Firefox separately
4. Hostname matches certificate CN or SAN

### Email alerts not working

**Verify:**
1. SMTP settings correct in `.env`
2. SMTP credentials valid
3. For Gmail: Use app-specific password
4. Check monitor service logs
5. Test with manual alert

## Backup & Recovery

### What should I backup?

**Critical:**
- Vault data (contains all private keys)
- PostgreSQL database
- `.env` file
- Vault unseal keys (stored separately!)

**Important:**
- Issued certificate metadata
- Audit logs
- Configuration files

### How often should I backup?

**Recommended:**
- Automated daily backups
- Before major changes
- After issuing important certificates

### Can I restore to a different server?

Yes! Follow the restore procedure in [DEPLOYMENT.md](DEPLOYMENT.md). You'll need:
- Database backup
- Vault snapshot
- Configuration files
- Vault unseal keys

### What if I lose the Vault unseal keys?

**Without unseal keys, Vault data is permanently inaccessible.** This means:
- All certificate private keys are lost
- CA private key is lost
- You must start over with a new CA

**Prevention:** Store unseal keys securely in multiple locations.

## Performance

### How much resources does it use?

**Typical usage (idle):**
- CPU: <5%
- RAM: ~2GB
- Disk: ~5GB
- Network: Minimal

**Under load (issuing certificates, monitoring):**
- CPU: 10-30%
- RAM: ~3GB
- Disk I/O: Moderate

### Can I run multiple instances?

Yes, for high availability. See [DEPLOYMENT.md](DEPLOYMENT.md) for HA configuration.

### How many health checks per hour?

Default: 12 checks/hour per service (every 5 minutes)

For 10 services: 120 checks/hour

Adjust `HEALTH_CHECK_INTERVAL` to change frequency.

## Integration

### Can I automate certificate deployment?

Yes! Use the REST API to:
- Issue certificates programmatically
- Download certificates
- Deploy via Ansible/scripts
- Integrate with CI/CD

See [API.md](API.md) for details.

### Does it integrate with Kubernetes?

Not yet, but it's planned for version 2.0. Current workaround:
- Issue certificate via API
- Create Kubernetes secret manually
- Reference in ingress configuration

### Can I use with Terraform?

Not yet. A Terraform provider is planned for a future release.

### Does it work with reverse proxies?

Yes! Works great with:
- nginx
- Traefik
- HAProxy
- Caddy
- Any reverse proxy that supports standard SSL certificates

## Development

### Can I contribute?

Yes! Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### How do I report a bug?

Open an issue on GitHub with:
- Clear description
- Steps to reproduce
- Expected vs actual behavior
- Environment details
- Logs (if applicable)

### How do I request a feature?

Open a feature request on GitHub. Include:
- Use case
- Proposed solution
- Alternative approaches
- Willingness to implement

### Is there a public roadmap?

Yes! See [ROADMAP.md](ROADMAP.md) for planned features and timeline.

## Upgrades

### How do I upgrade to a new version?

```bash
cd /opt/pki
./scripts/backup.sh  # Backup first!
git pull origin main
docker-compose pull
docker-compose up -d
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for details.

### Will my certificates still work after upgrade?

Yes! Existing certificates continue to work. The upgrade process preserves:
- CA certificate and key
- Issued certificates
- Configuration
- Database

### Are upgrades automatic?

No. You must manually upgrade. This gives you control over when updates are applied.

### Do upgrades require downtime?

Yes, brief downtime (1-5 minutes) during:
- Database migrations
- Service restart

For zero-downtime, consider HA deployment.

## Licensing

### What license is this under?

MIT License - very permissive. You can:
- Use commercially
- Modify
- Distribute
- Sublicense

With the requirement to:
- Include license notice
- Include copyright notice

### Can I use this in my company?

Yes, but it's designed for home labs. For company use, consider:
- Enhanced security measures
- Professional support
- Compliance requirements
- Commercial PKI solutions

### Can I sell this?

Yes, under MIT license. However, we encourage contributing improvements back to the community.

## Getting Help

### Where can I get help?

1. Check this FAQ
2. Read the [documentation](docs/)
3. Search [GitHub Issues](https://github.com/OWNER/pki/issues)
4. Ask in [GitHub Discussions](https://github.com/OWNER/pki/discussions)
5. Join community chat (if available)

### How do I report a security vulnerability?

**Do not create public issues for security issues.**

Email: security@example.com (replace with actual contact)

See [SECURITY.md](SECURITY.md) for details.

### Is there professional support?

Currently, this is a community-supported project. Professional support may be available in the future.

## Still Have Questions?

Open a discussion on GitHub or check the documentation:
- [Getting Started](GETTING_STARTED.md)
- [Architecture](ARCHITECTURE.md)
- [Security](SECURITY.md)
- [API Documentation](API.md)
