# Secrets Management Recommendation

## Current State
Currently, secrets (DB passwords, Vault tokens, etc.) are passed as environment variables in `docker-compose.yml`. This exposes them to anyone with access to the docker daemon (`docker inspect`) or the process list.

## Recommended Approach: Docker Secrets

Since we are using Docker Compose, we can utilize Docker Secrets to securely manage sensitive information. This avoids the "Chicken/Egg" problem with Vault by providing the initial bootstrap credentials securely.

### Implementation Steps

1.  **Define Secrets in `docker-compose.yml`**:
    ```yaml
    secrets:
      db_password:
        file: ./secrets/db_password.txt
      vault_token:
        file: ./secrets/vault_token.txt
    ```

2.  **Update Services to Use Secrets**:
    ```yaml
    services:
      backend:
        ...
        secrets:
          - db_password
          - vault_token
        environment:
          - DB_PASSWORD_FILE=/run/secrets/db_password
          - VAULT_TOKEN_FILE=/run/secrets/vault_token
    ```

3.  **Update Application Config (`backend/app/core/config.py`)**:
    Modify the `Settings` class to support reading from files (often called `_FILE` suffix support).

    ```python
    # Example logic to add to config.py or a custom loader
    def load_secret(secret_name, default=None):
        env_var = os.getenv(secret_name)
        file_var = os.getenv(f"{secret_name}_FILE")
        
        if file_var and os.path.exists(file_var):
            with open(file_var, 'r') as f:
                return f.read().strip()
        return env_var or default
    ```

### Why this is better
*   **No Environment Leakage**: Secrets are mounted as files in `/run/secrets/` (in-memory tmpfs), not exposed in environment variables.
*   **Standard Practice**: This is the standard way to handle secrets in containerized environments (Swarm, Kubernetes, Compose).
*   **Vault Bootstrap**: You can use this method to provide the initial `VAULT_TOKEN` or `VAULT_ROLE_ID` needed for the application to authenticate with Vault and fetch other dynamic secrets.

## Next Steps
To implement this, we would need to:
1.  Create a local `secrets/` directory (gitignored).
2.  Update `docker-compose.yml` to define and map these secrets.
3.  Update `backend/app/core/config.py` to prefer `_FILE` env vars.
