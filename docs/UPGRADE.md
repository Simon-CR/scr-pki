# Upgrade Guide

## Upgrading from v0.2.0 to v0.2.1

Version 0.2.1 introduces significant security improvements. Follow these steps to upgrade your existing installation.

### 1. Pull the Latest Code
```bash
git pull origin main
```

### 2. Update Docker Images
Pull the latest images from DockerHub.
```bash
docker-compose pull
```

### 3. Recreate Containers
Restart the stack to apply changes.
```bash
docker-compose up -d
```

### 4. Verification
- **Login**: Verify you can still login. Your existing password will work (legacy mode) and will be automatically upgraded to a secure hash on next change.
- **JWT Keys**: The backend will automatically generate `jwt_private.pem` and `jwt_public.pem` in the `./data/certs` directory.
- **Nginx**: Check that the application loads correctly. If you see CSP errors in the browser console, please report them.

## New Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Simon-CR/scr-pki.git
cd scr-pki
```

### 2. Configure Environment
Copy the example environment file and customize it.
```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Start the Stack
```bash
docker-compose up -d
```

### 4. Initialize
Access `https://localhost` (or your configured domain) to create the first admin user.
