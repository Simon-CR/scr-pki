# SCR-PKI

A secure, self-hosted Public Key Infrastructure (PKI) platform designed for home labs and home networks. Eliminate browser security warnings by managing your own Certificate Authority and certificates.

## 🎯 Project Overview

SCR-PKI provides a complete solution for managing SSL/TLS certificates in your home network environment. It includes:

- **Certificate Authority Management** - Create and manage your own root CA
- **Certificate Lifecycle Management** - Issue, renew, and revoke certificates
- **Service Monitoring** - Real-time health checks for deployed certificates
- **Expiration Alerts** - Proactive notifications before certificates expire
- **Secure Storage** - Integration with HashiCorp Vault for key material
- **User-Friendly Web Interface** - Simple, intuitive certificate management
- **Cross-Platform Root CA Installation** - Easy setup guides for all major platforms

## ✨ Key Features

### Certificate Management
- Issue certificates with custom validity periods (support for long-lived certs)
- Support for modern, secure cipher suites only
- Automatic certificate generation with sensible defaults
- Certificate revocation and renewal workflows
- Track certificate deployment locations

### Monitoring & Alerts
- Automated health checks for services using issued certificates
- Customizable monitoring intervals
- Manual on-demand health checks
- Real-time status dashboard (green/red indicators)
- Email/webhook notifications for expiration warnings
- Configurable alert thresholds

### Security
- Secure key storage using HashiCorp Vault
- Authentication and authorization
- Audit logging for all certificate operations
- Support for secure cipher suites only (TLS 1.3, strong algorithms)

### User Experience
- Clean, responsive web interface
- One-click root CA download
- Platform-specific installation instructions
- Certificate deployment tracking
- Search and filter issued certificates

## 🚀 Quick Start

### Prerequisites
- Docker
- Docker Compose

### Deployment

1. **Run the deployment script:**
   ```bash
   ./deploy.sh
   ```
   This script will:
   - Check prerequisites
   - Create a `.env` file from defaults
   - Initialize the directory structure
   - Start the services
   - **Initialize and Unseal Vault** (and save your keys to `vault_keys.json`)

2. **Access the Platform:**
   - **Frontend:** https://localhost:9443 (Accept the self-signed certificate warning)
   - **Vault UI:** https://localhost:9443/ui/

3. **Default Credentials:**
   - **Username:** `admin`
   - **Password:** (Check your `.env` file, default is `change_this_password`)

### Development

To run in development mode (with hot-reloading and exposed ports):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

## 📚 Documentation
git clone <repository-url>
cd pki

# Copy environment configuration
cp .env.example .env

# Edit .env with your settings
nano .env

# Start the platform
docker-compose up -d

# Access the web interface
open http://localhost:8080
```

See [GETTING_STARTED.md](docs/GETTING_STARTED.md) for detailed setup instructions.

## 📋 Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Minimum 2GB RAM
- 10GB available disk space

## 🏗️ Architecture

The platform consists of:

- **Frontend** - React-based web interface
- **Backend API** - Python FastAPI service
- **Database** - PostgreSQL for certificate metadata
- **Vault** - HashiCorp Vault for secure key storage
- **Monitor** - Service health check daemon
- **Nginx** - Reverse proxy and load balancer

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.

## 📖 Documentation

- [Getting Started](docs/GETTING_STARTED.md) - Initial setup and configuration
- [Architecture](docs/ARCHITECTURE.md) - System design and components
- [Certificate Management](docs/CERTIFICATE_MANAGEMENT.md) - Working with certificates
- [Monitoring](docs/MONITORING.md) - Health checks and alerts
- [Security](SECURITY.md) - Security model and best practices
- [API Documentation](docs/API.md) - REST API reference
- [Development Guide](docs/DEVELOPMENT.md) - Contributing to the project
- [Deployment](docs/DEPLOYMENT.md) - Production deployment guide

## 🛡️ Security

Please see [SECURITY.md](SECURITY.md) for details on the security model, including Docker socket usage and Vault integration.

## 🔧 Configuration

Key configuration options in `.env`:

```bash
# Web Interface
WEB_PORT=8080
WEB_DOMAIN=pki.local

# Certificate Defaults
DEFAULT_CERT_VALIDITY_DAYS=3650  # 10 years for home lab
DEFAULT_KEY_SIZE=4096

# Monitoring
HEALTH_CHECK_INTERVAL=300  # 5 minutes
ALERT_DAYS_BEFORE_EXPIRY=30

# Vault Configuration
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=your-vault-token
```

## 🛠️ Technology Stack

- **Backend**: Python 3.11, FastAPI, SQLAlchemy
- **Frontend**: React 18, TypeScript, TailwindCSS
- **Database**: PostgreSQL 15
- **Secrets Management**: HashiCorp Vault
- **Cryptography**: cryptography (Python), OpenSSL
- **Monitoring**: APScheduler, aiohttp
- **Container Orchestration**: Docker Compose

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

This platform is designed for **home lab and private network use only**. It is not intended for public-facing production environments or commercial use. Always follow security best practices when managing cryptographic material.

## 🐛 Known Issues & Roadmap

See [ROADMAP.md](docs/ROADMAP.md) for planned features and known limitations.

## 📞 Support

- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Join the GitHub Discussions for Q&A
- **Documentation**: Check the [docs](docs/) directory

## 🙏 Acknowledgments

- Built with modern security standards in mind
- Inspired by the need for simple, secure home lab certificate management
- Thanks to the open-source community for the amazing tools and libraries
