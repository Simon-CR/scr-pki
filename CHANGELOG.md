# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2025-11-28

### Fixed
- **Database Connection**: Fixed `ModuleNotFoundError: No module named 'psycopg2'` by ensuring the connection string uses `postgresql+psycopg://` in all configurations (Prod/Dev) and fallbacks.
- **Production Config**: Updated `docker-compose.prod.yml` to use the correct database driver and JWT algorithm (RS256).

## [0.2.1] - 2025-11-27

### Security
- **Authentication Hardening**: Upgraded password hashing to use `bcrypt` and `argon2` (via `passlib`). Added backward compatibility for existing passwords.
- **JWT Security**: Switched from Symmetric (HS256) to Asymmetric (RS256) signing for JWT tokens. Keys are automatically generated on startup.
- **Nginx Hardening**: Disabled server tokens, removed deprecated XSS headers, and implemented a strict Content Security Policy (CSP).
- **Production Mode**: Added entrypoint script to enforce production settings (no reload, multiple workers) when `ENVIRONMENT=production`.
- **Database Driver**: Upgraded to `psycopg` (v3) for better performance and security.

### Changed
- **Docker Configuration**: Removed `user: root` from `docker-compose.yml` to respect Dockerfile user settings (except where necessary).

### Project Initialization
- Complete project documentation and architecture
- Docker Compose configuration
- Service structure and API design
- Development and deployment guides
- Security framework and best practices

## [0.2.0] - 2025-11-27

### Added
- **Background Scheduler**: Implemented `APScheduler` to run periodic tasks (monitoring checks, expiration alerts).
- **Alert Acknowledgment**: Added ability to acknowledge alerts in the UI.
- **DockerHub Integration**: Version check now verifies if the Docker image is available on DockerHub.
- **SMTP Security**: Masked SMTP password in system settings API response.

### Changed
- **ACME Removal**: Completely removed ACME protocol support to focus on internal PKI use cases.
- **Documentation**: Updated Roadmap and QA Gaps to reflect current state.

## [0.1.0] - 2025-11-27

### Added
- **Auto-Restart Nginx**: Added ability to automatically restart the Nginx container when updating the system certificate.
- **Parallel Monitoring**: Optimized monitoring checks to run in parallel, significantly improving dashboard load times.
- **System Updates**: Added version tracking and update checking for stack containers.

### Fixed
- **System Cert Serialization**: Fixed a bug where the private key was not being serialized correctly before writing to disk.
- **Nginx Crash Loop**: Fixed an issue where a corrupted key file would cause Nginx to enter a restart loop.

## [1.0.0] - 2025-11-22

### Added
- **Granular Backup & Restore**: Added ability to backup and restore Application Data (Users, Cert Metadata) and Vault Data (Keys) independently.
- **System Reset**: Added "Danger Zone" feature to completely reset the system, including wiping the database and restarting the Vault container to clear its state.
- **Security Policy**: Added `SECURITY.md` detailing the security architecture and risks.

### Fixed
- **Vault Reset Issue**: Fixed an issue where the "System Reset" would not correctly clear the Vault memory state.
- **Docker Client Compatibility**: Downgraded `docker` python library to `6.1.3` and pinned `urllib3`/`requests` to resolve `http+docker` scheme errors when restarting containers.
- **Restore Logic**: Fixed Docker socket connection string in restore logic.

### Planned Features

#### Certificate Management
- Certificate Authority initialization
- RSA certificate issuance (2048, 4096-bit)
- Certificate renewal
- Certificate revocation with CRL generation
- Support for long validity periods (up to 20 years)
- Subject Alternative Names (SANs)
- Multiple certificate download formats
- Deployment location tracking

#### Monitoring & Alerts
- Automated HTTPS health checks
- SSL/TLS certificate validation
- Service availability monitoring
- Response time measurement
- Configurable check intervals
- Manual on-demand health checks
- Multi-level expiration alerts
- Email notifications (SMTP)
- Webhook notifications (Slack, Discord, custom)

#### Security
- HashiCorp Vault integration
- JWT-based authentication
- Role-based access control
- Audit logging
- TLS 1.3 support
- Secure cipher suites
- Rate limiting
- Security headers

#### User Interface
- React-based web interface
- Certificate dashboard
- Monitoring dashboard
- Alert management
- User management
- Settings configuration

#### API
- RESTful API
- JWT authentication
- Comprehensive documentation
- Rate limiting
- Error handling

#### Infrastructure
- Docker Compose deployment
- PostgreSQL database
- HashiCorp Vault
- Nginx reverse proxy
- Health checks
- Automated backups

### Documentation
- Complete user documentation
- API documentation
- Architecture overview
- Security guide
- Development guide
- Deployment guide
- Contributing guidelines

## Version History Format

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Features that will be removed in future versions

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security-related changes

---

**Note:** Version 1.0.0 is in active development. This changelog will be updated as features are implemented.
