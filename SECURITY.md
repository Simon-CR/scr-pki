# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Please report vulnerabilities by opening a GitHub Issue with the label `security`.

## Security Architecture

### Docker Socket Access

The backend service requires access to the Docker socket (`/var/run/docker.sock`) to perform specific administrative tasks:
1.  **System Reset**: To completely reset the system, the backend needs to stop and restart the Vault container to clear its memory state.
2.  **Restore**: During a restore operation involving Vault data, the Vault container must be restarted to reload the data from the database.
3.  **System Certificate Update**: When updating the system TLS certificate, nginx can be automatically restarted.

**⚠️ Security Implications:**
- Docker socket access is equivalent to root access on the host machine
- A compromised backend could potentially escape the container

**Risk Mitigation:**
- The backend container runs as the `root` user to access the socket (default Docker behavior).
- Access to the `/api/v1/system/reset` and `/api/v1/system/backups/*/restore` endpoints is strictly limited to **Superuser/Admin** accounts.
- The Docker socket is mounted only into the backend container, which is on an internal network (except for the API port exposed via Nginx).
- Rate limiting is applied to all API endpoints

**Alternative: Docker Socket Proxy**

For enhanced security, consider using a [Docker Socket Proxy](https://github.com/Tecnativa/docker-socket-proxy) which allows you to limit what Docker operations the backend can perform:

```yaml
# Example docker-compose addition
services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1  # Allow container operations only
      POST: 1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - backend-network

  backend:
    environment:
      - DOCKER_HOST=tcp://docker-proxy:2375
    # Remove docker.sock mount
```

**Disabling Docker Socket (Manual Operations)**

If you prefer not to mount the Docker socket:
1. Remove the volume mount from `docker-compose.yml`
2. System reset, backup restore, and auto-restart features will fail gracefully
3. You must manually restart containers after these operations:
   ```bash
   docker compose restart vault    # After system reset
   docker compose restart nginx    # After certificate update
   ```

### Vault Integration

- **Key Storage**: All private keys are stored in HashiCorp Vault, not in the database or filesystem.
- **Encryption**: The Vault token is encrypted at rest in the PostgreSQL database using a symmetric key (`SECRET_KEY`).
- **Access Control**: The backend authenticates with Vault using a token. In production, this should be a periodic token with limited policies, though the initial setup uses the root token for simplicity.

### Authentication

- **JWT**: Stateless authentication using JSON Web Tokens.
- **Password Hashing**: Passwords are hashed using bcrypt.
- **Role-Based Access Control (RBAC)**:
    - `viewer`: Read-only access.
    - `operator`: Can issue/revoke certificates.
    - `admin`: Full system access, including user management and system reset.

### AppArmor Configuration

SCR-PKI containers run with `apparmor:unconfined` in the Docker configuration. This is intentional for home lab environments where:

1. **Host Compatibility**: AppArmor may be disabled or not configured on the host system
2. **Simplified Setup**: Avoids profile creation and maintenance overhead for home users
3. **Functionality**: Some container operations (especially Vault IPC_LOCK capability) may conflict with default AppArmor profiles

**For Enhanced Security (Production/Enterprise):**

If your host has AppArmor enabled and you want additional container isolation:
1. Remove `security_opt: - apparmor:unconfined` from `docker-compose.yml`
2. Use default Docker AppArmor profiles, or
3. Create custom profiles for each service

Note: The default Docker AppArmor profile provides reasonable protection for most use cases without custom configuration.

## Best Practices for Deployment

1.  **Change Default Credentials**: Immediately change the default admin password and Vault keys.
2.  **Secure the Host**: Ensure the host machine running Docker is secure. Access to the Docker socket is equivalent to root access on the host.
3.  **Network Isolation**: Use the provided Docker networks to isolate the backend and database from direct external access. Only Nginx should be exposed.
4.  **HTTPS**: Always access the frontend via HTTPS (Nginx handles this).
