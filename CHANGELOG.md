# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.6] - 2025-12-03

### Added
- **Certificate Validity Presets**: Added tiered validity options with browser compatibility information:
  - ≤398 days: Full Apple PKI/Safari compliance
  - ≤825 days: macOS 10.15/iOS 13 compatible
  - >825 days: Works with Chrome, Firefox, Opera (Safari may show warnings)
- **825-day Preset**: New validity option for maximum Safari compatibility

### Changed
- **Validity UI**: Updated certificate validity dropdown with clearer browser compatibility notes
- **Backend Logging**: Changed validity logging from warning to info level for homelab use cases
- **Proxmox Documentation**: Updated instructions to use separate key/certificate downloads instead of combined bundle
- **Production Compose**: Removed VERSION file bind mount - version is now read from inside the Docker image, allowing standalone docker-compose usage without cloning the full repo

### Fixed
- **Timezone Comparison**: Fixed "can't compare offset-naive and offset-aware datetimes" error in certificate renewal by adding `ensure_utc()` helper function

## [0.2.5] - 2025-11-28

### Fixed
- **ALLOWED_HOSTS Parsing**: Fixed environment variable parsing for `ALLOWED_HOSTS`, `CORS_ORIGINS`, and `CERT_ALLOWED_KEY_SIZES` to properly handle both comma-separated strings and JSON arrays from environment variables.

### Changed
- **Frontend Dependencies**: Updated all frontend dependencies to latest versions, eliminating deprecation warnings during builds.
- **ESLint 9**: Upgraded from deprecated ESLint 8.x to ESLint 9.x with new flat config format.

## [0.2.4] - 2025-11-28

### Security
- **Rate Limiting**: Added rate limiting on authentication endpoints using `slowapi` to prevent brute force attacks.
- **Token Blacklist**: Implemented token blacklist for proper logout functionality. Tokens are now invalidated on logout.
- **Setup Race Condition**: Fixed race condition in initial setup endpoint using PostgreSQL advisory locks.
- **Error Sanitization**: Sanitized error messages to prevent information disclosure. Detailed errors are logged internally.
- **AUTH_DISABLED Warning**: Added prominent startup warnings and documentation for dangerous `AUTH_DISABLED` setting.
- **Source Maps Disabled**: Production builds no longer include source maps to prevent code exposure.
- **Server Tokens Disabled**: Added `server_tokens off` to nginx configuration.
- **CSP Cleanup**: Removed duplicate Content-Security-Policy headers from nginx config.
- **Network Segmentation**: Made `vault-net` internal-only for improved network isolation.
- **ALLOWED_HOSTS**: Changed from wildcard to configurable via environment variable. Documented best practices.
- **Security Headers**: Added security headers middleware to backend (X-Content-Type-Options, X-Frame-Options, Cache-Control).
- **Health Rate Limiting**: Added rate limiting to health check endpoints.

### Fixed
- **Deprecated datetime.utcnow()**: Replaced all deprecated `datetime.utcnow()` calls with timezone-aware `datetime.now(timezone.utc)`.
- **Token Storage Consistency**: Fixed inconsistent token retrieval in SystemSettings to use `tokenStorage` utility.

### Changed
- **Confirmation Dialogs**: Replaced native browser `confirm()` dialogs with custom styled modal dialogs for better UX.

### Added
- **ConfirmDialog Component**: Added reusable confirmation dialog component with danger/warning/info variants.
- **Error Handling Utility**: Added centralized error handling utility for consistent secure error responses.
- **Password Complexity**: Configurable password complexity validation (min length, uppercase, lowercase, digit, special).
- **Session Timeout**: Frontend session timeout with configurable inactivity period (default 2 hours).
- **Password Requirements API**: New `/api/v1/setup/password-requirements` endpoint to retrieve current password policy.
- **Type Hints**: Added proper type hints using Protocol types in user service.

### Documentation
- **AppArmor**: Documented AppArmor configuration and why containers run unconfined.
- **Docker Socket**: Enhanced documentation for Docker socket security and alternatives.
- **Password Policy**: Documented configurable password policy settings in deployment guide.

## [0.2.3] - 2025-11-28

### Fixed
- **Database Race Condition**: Fixed `UniqueViolation` error during startup when running with multiple workers. Added `pre_start.py` to initialize the database sequentially before spawning workers.
- **Version Check**: Fixed issue where the backend failed to detect the local version, causing it to report "0.2.0" instead of the actual version. Added `VERSION` file to backend build and production volume mounts.

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
