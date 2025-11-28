# Project Roadmap

Future features and improvements planned for the HomeLab PKI Platform.

## Version 1.0.0 (Current MVP)

- [x] Certificate Authority initialization
- [x] Certificate issuance (RSA)
- [x] Certificate renewal
- [x] Certificate revocation
- [x] Service health monitoring
- [x] Expiration alerts
- [x] Email notifications
- [x] Web-based management interface
- [x] HashiCorp Vault integration
- [x] Docker Compose deployment
- [x] Basic authentication
- [x] Audit logging (Server-side only)
- [x] Intermediate CA Support

## Version 1.1.0 (Q1 2026)

### Features
- [ ] **ECDSA Certificate Support**
  - Support for ECDSA keys (P-256, P-384, P-521)
  - Key type selection in UI
  
- [ ] **Certificate Templates**
  - Predefined certificate profiles
  - Quick issuance with saved settings
  - Template management UI
  
- [ ] **Batch Operations**
  - Issue multiple certificates at once
  - Bulk renewal
  - Export multiple certificates
  
- [ ] **Enhanced Monitoring**
  - Custom health check endpoints
  - HTTP header validation
  - Response content matching
  - Service dependency mapping

### Improvements
- [ ] Performance optimizations
- [ ] Enhanced error messages
- [ ] Better mobile UI
- [ ] Search and filter improvements

## Version 1.2.0 (Q2 2026)

### Features
- [ ] **Automated Certificate Renewal**
  - Automatic renewal before expiration
  - Webhook notifications for deployment
  - Renewal status tracking
  
- [ ] **Multi-Factor Authentication**
  - TOTP support
  - WebAuthn/FIDO2
  - Backup codes
  
- [ ] **API Key Management**
  - Long-lived API keys for automation
  - Key rotation
  - Permission scoping
  
- [ ] **Certificate Profiles**
  - Different security levels
  - Purpose-based profiles (server, client, code signing)
  - Extended key usage support

### Improvements
- [ ] REST API v2 with improved design
- [ ] GraphQL API (optional)
- [ ] Webhook retry logic
- [ ] Better audit log searching

## Version 1.3.0 (Q3 2026)

### Features
- [ ] **Client Certificates**
  - Client authentication certificates
  - VPN certificates
  - Email signing certificates
  
- [ ] **Certificate Signing Requests (CSR)**
  - Upload and sign CSRs
  - CSR validation
  - Import existing certificates
  
- [ ] **Advanced Monitoring**
  - Prometheus metrics export
  - Grafana dashboard templates
  - Custom alerting rules

### Improvements
- [ ] Plugin system for extensibility
- [ ] Custom notification channels
- [ ] Advanced filtering and reporting

## Version 2.0.0 (Q4 2026)

### Major Features

- [ ] **High Availability**
  - Multi-instance deployment
  - Database replication
  - Vault HA configuration
  - Load balancing
  
- [ ] **RBAC Enhancements**
  - Custom roles
  - Fine-grained permissions
  - Resource-level access control
  - Delegation
  
- [ ] **Certificate Lifecycle Automation**
  - Auto-deployment via SSH/Ansible
  - Integration with configuration management tools
  - Kubernetes certificate management

### Infrastructure
- [ ] Kubernetes deployment option
- [ ] Cloud deployment templates (AWS, Azure, GCP)
- [ ] Backup and restore improvements
- [ ] Disaster recovery procedures

## Future Considerations

### Advanced PKI Features
- [ ] Certificate pinning support
- [ ] OCSP responder
- [ ] Certificate transparency logging
- [ ] Hardware Security Module (HSM) support
- [ ] Time-stamping authority (TSA)

### Integration
- [ ] Active Directory integration
- [ ] LDAP authentication
- [ ] SAML/OAuth2 support
- [ ] Terraform provider
- [ ] Ansible module
- [ ] CLI tool

### Monitoring & Analytics
- [ ] Certificate usage analytics
- [ ] Compliance reporting
- [ ] Security scoring
- [ ] Trend analysis
- [ ] Predictive expiration warnings

### User Experience
- [ ] Dark mode
- [ ] Localization (i18n)
- [ ] Mobile app
- [ ] Certificate visualization
- [ ] Interactive tutorials

## Community Requests

Features requested by the community will be prioritized based on:
- Number of requests
- Complexity
- Alignment with project goals
- Available resources

Submit feature requests via [GitHub Issues](https://github.com/OWNER/pki/issues).

## Breaking Changes

We follow semantic versioning. Breaking changes will:
- Be announced in advance
- Include migration guides
- Provide deprecation warnings
- Only occur in major versions

## Contributing

Want to help implement these features? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Status Legend

- [x] Completed
- [ ] Planned
- 🚧 In Progress
- ⏸️ On Hold
- ❌ Cancelled

---

**Last Updated:** November 13, 2025

**Note:** This roadmap is subject to change based on community feedback, security requirements, and project priorities.
