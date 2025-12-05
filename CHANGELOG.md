# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.11] - 2025-12-05

### Added
- **Seal/Unseal Buttons**: Added explicit seal and unseal controls for testing and operations
  - "Seal" button in System Health when Vault is unsealed
  - "Unseal" button in System Health when Vault is sealed (uses auto-unseal)
  - New `POST /config/vault/seal` endpoint to seal Vault
  - New `seal_vault()` method in VaultClient
- **Test Auto-Unseal Section**: Added a "Test Auto-Unseal" section in the Store Unseal Keys area
  - Quick access to seal the Vault for testing auto-unseal methods
  - Instructions to use priority order to control which method is tested first
- **Remove Provider from Auto-Unseal**: Added ability to remove KMS providers from auto-unseal without deleting their configuration
  - New API endpoint `DELETE /config/vault/auto-unseal-provider` to remove wrapped DEK for a provider
  - "×" button on each active provider badge to remove it from auto-unseal
  - Confirmation dialog before removal with clear explanation
  - Safety check prevents removing the last remaining provider
  - Provider configuration is preserved so it can be re-added later

### Fixed
- **Shamir Priority Display**: Shamir (Manual Unseal) now properly displays in the unseal priority list
  - Added "shamir" to the providerNames map with label "Manual Unseal (Shamir Keys)"
  - Shamir can now be reordered in the priority list like other methods

### Improved
- **Auto-Unseal UI**: Enhanced the active providers display
  - Clearer indication that clicking × removes a provider
  - Shows provider count and allows removal when more than one exists
  - Loading spinner when removal is in progress

## [0.2.10] - 2025-12-04

### Added
- **Auto-Unseal in Web UI**: Added one-click auto-unseal option when Vault is sealed
  - Detects `vault_keys.json` file in data directory
  - Shows "Auto-Unseal Available" button with clear warnings about production use
  - Includes confirmation dialog before unsealing
- **Auto-Unseal on Startup**: Backend now automatically attempts to unseal Vault on startup
  - Checks for `vault_keys.json` in data directory
  - Unseals Vault before establishing connection if keys are available
  - Logs detailed status messages during auto-unseal process
- **Local Keys File Management via Web UI**: Create `vault_keys.json` directly from the UI
  - Enter unseal keys in the Auto-Unseal Configuration section
  - Click "Enable Local Auto-Unseal" to create the file
  - View status and delete the file when no longer needed
- **Seal Configuration via Web UI**: Complete auto-unseal configuration through the UI
  - Configure Vault seal type without docker-compose or .env changes
  - Support for multiple providers: Transit, AWS KMS, GCP Cloud KMS, Azure Key Vault, OCI KMS, AliCloud KMS
  - Credentials stored securely in database with encryption
  - Per-provider configuration forms with all required settings
  - View, update, or delete seal configurations at any time
- **KMS Connection Testing**: Test connectivity to KMS providers before saving
  - Transit: Verifies Vault health and transit key accessibility
  - AWS KMS: Tests key access using boto3
  - GCP Cloud KMS: Tests key access using google-cloud-kms
  - Azure Key Vault: Tests key access using azure-identity
  - OCI KMS: Tests key access using oci SDK
- **Detailed Migration Instructions**: After saving seal config, displays step-by-step migration commands
  - Shows exact docker commands needed for seal migration
  - Includes copy-to-clipboard functionality
  - Terminal-style formatted display
- **Automated Seal Migration**: When Docker socket is available, perform migrations automatically
  - New `/api/v1/system/config/vault/seal/migrate` endpoint
  - Automatically restarts Vault container and applies unseal keys with -migrate flag
  - Can use provided keys or load from vault_keys.json
  - Real-time progress reporting with steps completed
  - Falls back to manual instructions when Docker socket unavailable
- **Vault Unseal Documentation**: New comprehensive `docs/VAULT_UNSEAL.md` with options:
  - Option 1: Local auto-unseal with `vault_keys.json`
  - Option 2: Manual unseal via Web UI
  - Option 3: Web UI Seal Configuration
  - Option 4: Self-hosted Transit auto-unseal
  - Option 5: Cloud KMS (AWS, GCP, Azure, OCI, AliCloud)
- **vault_keys.json.example**: Added example file showing the correct format for unseal keys

### Changed
- **deploy.sh**: Updated with comprehensive Vault unseal options information
- **README.md**: Improved first-run instructions and added Vault unseal options section

### Fixed
- **Port References**: Standardized documentation to use ports 443/80 instead of mixed references to 9443/8080
- **Enum Import**: Fixed missing `Enum` import in system.py that caused backend startup failure

## [0.2.9] - 2025-12-04

### Changed
- **Docker Compose Consolidation**: Simplified from 3 compose files to 2:
  - `docker-compose.yml` - Production config (pulls from Docker Hub)
  - `docker-compose.dev.yml` - Development override (builds locally with hot reload)
  - Removed `docker-compose.prod.yml` (merged into main `docker-compose.yml`)

### Fixed
- **Dashboard Last Check Field**: Fixed "Last check" timestamp not displaying in Operational Telemetry card (was using wrong field name `last_check_at` instead of `last_verified_at`)
- **Dashboard Status Logic**: Fixed monitoring status checks to match actual API response format (`up`/`down`/`pending` instead of `ACTIVE`/`SUCCESS`)
- **Dashboard Active Services Count**: Fixed "Active services" KPI card showing incorrect count (was checking for `active`/`success` instead of `up` and actual result string)
- **Dashboard Syntax Error**: Removed duplicate closing `</span>` tag that caused rendering issues

## [0.2.8] - 2025-12-04

### Fixed
- **Dashboard Monitoring Status**: Fixed case-sensitivity issue where monitoring services showed as degraded despite being healthy (database stores ACTIVE/SUCCESS uppercase, frontend was comparing lowercase)

## [0.2.7] - 2025-12-04

### Fixed
- **Validity Preset Bug**: Fixed certificate validity dropdown multiplying days by 365 incorrectly (e.g., selecting "2 years" resulted in 266,450 days instead of 730)

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
