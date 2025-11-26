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

**Risk Mitigation:**
- The backend container runs as the `root` user to access the socket (default Docker behavior).
- Access to the `/api/v1/system/reset` and `/api/v1/system/backups/*/restore` endpoints is strictly limited to **Superuser/Admin** accounts.
- The Docker socket is mounted only into the backend container, which is on an internal network (except for the API port exposed via Nginx).

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

## Best Practices for Deployment

1.  **Change Default Credentials**: Immediately change the default admin password and Vault keys.
2.  **Secure the Host**: Ensure the host machine running Docker is secure. Access to the Docker socket is equivalent to root access on the host.
3.  **Network Isolation**: Use the provided Docker networks to isolate the backend and database from direct external access. Only Nginx should be exposed.
4.  **HTTPS**: Always access the frontend via HTTPS (Nginx handles this).
