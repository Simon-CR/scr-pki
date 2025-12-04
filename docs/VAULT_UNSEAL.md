# Vault Unsealing Options

HashiCorp Vault uses a sealing mechanism to protect its encryption keys. When Vault starts or restarts, it is in a "sealed" state and cannot access its data until it is unsealed. This document covers four options for unsealing Vault in SCR-PKI.

## Overview

| Option | Security Level | Automation | Complexity | Use Case |
|--------|---------------|------------|------------|----------|
| [Option 1: Local Auto-Unseal](#option-1-local-auto-unseal-with-vault_keysjson) | ⚠️ Low | ✅ Full | 🟢 Easy | Development, isolated home labs |
| [Option 2: Manual Unseal](#option-2-manual-unseal-via-web-ui) | ✅ High | ❌ None | 🟢 Easy | Production with operator availability |
| [Option 3: Self-Hosted Transit Auto-Unseal](#option-3-self-hosted-transit-auto-unseal) | ✅ High | ✅ Full | 🟡 Medium | Self-hosted, no cloud dependency |
| [Option 4: Cloud KMS Auto-Unseal](#option-4-cloud-kms-auto-unseal) | ✅ High | ✅ Full | 🟡 Medium | Cloud-based, high availability |

---

## Option 1: Local Auto-Unseal with vault_keys.json

This option stores Vault's unseal keys in a local JSON file, allowing automatic unsealing on container restart.

### ⚠️ Security Warning

> **This option stores sensitive cryptographic keys on disk in plain text.**
> 
> - Anyone with access to the server can unseal Vault and access all secrets
> - The keys file should be protected with strict file permissions (600)
> - **NOT recommended for production environments with sensitive data**
> - Acceptable for isolated home lab environments with physical security

### Setup

1. **During Initial Deployment**

   When you run `./deploy.sh` for the first time, Vault is automatically initialized and the keys are saved to `vault_keys.json`:

   ```bash
   ./deploy.sh
   ```

   The script will:
   - Initialize Vault with 5 key shares, requiring 3 to unseal
   - Save all keys and root token to `vault_keys.json`
   - Automatically unseal Vault
   - Update `.env` with the root token

2. **Keep the Keys File**

   By default, the deployment script warns you to backup and delete `vault_keys.json`. To enable auto-unseal:

   ```bash
   # Ensure proper permissions
   chmod 600 vault_keys.json
   
   # Optionally, move to a more secure location
   mv vault_keys.json /root/.vault_keys.json
   ```

### vault_keys.json Format

If you need to manually create or restore a `vault_keys.json` file, use this format (see `vault_keys.json.example`):

```json
{
  "unseal_keys_b64": [
    "base64-encoded-key-1",
    "base64-encoded-key-2",
    "base64-encoded-key-3",
    "base64-encoded-key-4",
    "base64-encoded-key-5"
  ],
  "unseal_keys_hex": [
    "hex-encoded-key-1",
    "hex-encoded-key-2",
    "hex-encoded-key-3",
    "hex-encoded-key-4",
    "hex-encoded-key-5"
  ],
  "unseal_shares": 5,
  "unseal_threshold": 3,
  "root_token": "hvs.your-root-token"
}
```

**Key fields:**
- `unseal_keys_b64`: Base64-encoded unseal keys (used by deploy.sh)
- `unseal_keys_hex`: Hex-encoded unseal keys (alternative format)
- `unseal_threshold`: Number of keys required to unseal (default: 3)
- `root_token`: The Vault root token for initial configuration

3. **Create an Auto-Unseal Script** (Optional)

   Create `/usr/local/bin/vault-unseal.sh`:

   ```bash
   #!/bin/bash
   KEYS_FILE="/root/.vault_keys.json"
   
   if [ ! -f "$KEYS_FILE" ]; then
       echo "Keys file not found: $KEYS_FILE"
       exit 1
   fi
   
   # Extract keys using jq or grep
   KEY1=$(jq -r '.unseal_keys_b64[0]' "$KEYS_FILE")
   KEY2=$(jq -r '.unseal_keys_b64[1]' "$KEYS_FILE")
   KEY3=$(jq -r '.unseal_keys_b64[2]' "$KEYS_FILE")
   
   docker exec pki_vault vault operator unseal "$KEY1"
   docker exec pki_vault vault operator unseal "$KEY2"
   docker exec pki_vault vault operator unseal "$KEY3"
   
   echo "Vault unsealed successfully"
   ```

4. **Auto-Unseal on Boot** (Optional)

   Add a systemd service or cron job:

   ```bash
   # /etc/systemd/system/vault-unseal.service
   [Unit]
   Description=Unseal Vault after container restart
   After=docker.service
   Requires=docker.service
   
   [Service]
   Type=oneshot
   ExecStartPre=/bin/sleep 30
   ExecStart=/usr/local/bin/vault-unseal.sh
   RemainAfterExit=yes
   
   [Install]
   WantedBy=multi-user.target
   ```

   Enable it:
   ```bash
   systemctl enable vault-unseal.service
   ```

---

## Option 2: Manual Unseal via Web UI

This is the most secure option for manual operations, requiring an operator to unseal Vault after each restart.

### Setup

1. **Save Your Unseal Keys Securely**

   During initial deployment, save the contents of `vault_keys.json` to a secure location:
   - Password manager (1Password, Bitwarden, etc.)
   - Encrypted USB drive stored in a safe
   - Distributed among trusted team members (each person gets 1-2 keys)

2. **Delete the Keys File from the Server**

   ```bash
   # After backing up securely
   rm vault_keys.json
   ```

3. **Unsealing via Web UI**

   When Vault is sealed (after container restart):

   1. Navigate to `https://your-server/ui/`
   2. You'll see the "Unseal Vault" screen
   3. Enter the first unseal key and click "Unseal"
   4. Repeat for the second and third keys
   5. After 3 valid keys, Vault is unsealed

4. **Unsealing via CLI**

   Alternatively, use the command line:

   ```bash
   # SSH to your server
   ssh user@your-server
   
   # Unseal with each key (need 3 of 5)
   docker exec pki_vault vault operator unseal <key1>
   docker exec pki_vault vault operator unseal <key2>
   docker exec pki_vault vault operator unseal <key3>
   ```

### Monitoring Seal Status

Check if Vault is sealed:

```bash
docker exec pki_vault vault status
```

Output when sealed:
```
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true        # <-- Vault is sealed
Total Shares       5
Threshold          3
Unseal Progress    0/3
```

---

## Option 3: Self-Hosted Transit Auto-Unseal

This option uses a separate Vault instance (running outside the SCR-PKI stack) to provide auto-unseal functionality. It offers the security benefits of KMS auto-unseal without requiring cloud services or internet connectivity.

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Your Infrastructure                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────────────┐         ┌──────────────────────┐         │
│   │   "KMS" Vault        │         │   SCR-PKI Vault      │         │
│   │   (Always Running)   │◄────────│   (Auto-Unseals)     │         │
│   │                      │         │                      │         │
│   │   - Transit Engine   │         │   - PKI Secrets      │         │
│   │   - Encryption Key   │         │   - Certificates     │         │
│   │   - Manually Unsealed│         │   - Private Keys     │         │
│   └──────────────────────┘         └──────────────────────┘         │
│          ▲                                                           │
│          │ Manual unseal (once)                                      │
│          │ or hardware token                                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

The "KMS Vault" only needs to be unsealed once (manually) and stays running. It provides encryption/decryption services to the SCR-PKI Vault, which can then auto-unseal on restart.

### Prerequisites

- A separate server/VM/container to run the KMS Vault
- Network connectivity between KMS Vault and SCR-PKI
- The KMS Vault should be on a separate machine for true security benefit

### Setup

#### Step 1: Deploy the KMS Vault

Create a `docker-compose.kms-vault.yml` on a **separate server**:

```yaml
# KMS Vault - Run on a separate, always-on server
# This provides Transit auto-unseal for other Vault instances

services:
  kms-vault:
    image: hashicorp/vault:1.21.1
    container_name: kms_vault
    ports:
      - "8200:8200"
    environment:
      - VAULT_ADDR=http://127.0.0.1:8200
      - VAULT_API_ADDR=http://YOUR_KMS_SERVER_IP:8200
    volumes:
      - ./kms-vault-data:/vault/data
      - ./kms-vault-config:/vault/config
    cap_add:
      - IPC_LOCK
    restart: unless-stopped
    command: server -config=/vault/config/vault.hcl

volumes:
  kms-vault-data:
```

Create the config file `kms-vault-config/vault.hcl`:

```hcl
ui = true
disable_mlock = true

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1  # Enable TLS in production!
}

api_addr = "http://YOUR_KMS_SERVER_IP:8200"
```

Start and initialize:

```bash
docker compose -f docker-compose.kms-vault.yml up -d

# Initialize (save these keys securely!)
docker exec kms_vault vault operator init

# Unseal with 3 of the 5 keys
docker exec kms_vault vault operator unseal <key1>
docker exec kms_vault vault operator unseal <key2>
docker exec kms_vault vault operator unseal <key3>
```

#### Step 2: Configure Transit Engine on KMS Vault

```bash
# Login to KMS Vault
docker exec -it kms_vault vault login

# Enable Transit secrets engine
docker exec kms_vault vault secrets enable transit

# Create an encryption key for auto-unseal
docker exec kms_vault vault write -f transit/keys/autounseal

# Create a policy for the SCR-PKI Vault
docker exec kms_vault vault policy write autounseal - <<EOF
path "transit/encrypt/autounseal" {
  capabilities = ["update"]
}

path "transit/decrypt/autounseal" {
  capabilities = ["update"]
}
EOF

# Create a token for SCR-PKI Vault (save this!)
docker exec kms_vault vault token create \
  -policy="autounseal" \
  -period=24h \
  -orphan
```

Save the token output - you'll need it for SCR-PKI configuration.

#### Step 3: Configure SCR-PKI Vault for Transit Auto-Unseal

Update your SCR-PKI `docker-compose.yml` vault service:

```yaml
vault:
  image: hashicorp/vault:1.21.1
  container_name: pki_vault
  environment:
    - VAULT_ADDR=http://127.0.0.1:8200
    - VAULT_API_ADDR=http://127.0.0.1:8200
    # Transit auto-unseal configuration
    - VAULT_SEAL_TYPE=transit
    - VAULT_TRANSIT_SEAL_ADDRESS=http://YOUR_KMS_SERVER_IP:8200
    - VAULT_TRANSIT_SEAL_TOKEN=hvs.XXXXXXXX  # Token from Step 2
    - VAULT_TRANSIT_SEAL_KEY_NAME=autounseal
    - VAULT_TRANSIT_SEAL_MOUNT_PATH=transit
```

#### Step 4: Migrate Existing Vault (if already initialized)

If your SCR-PKI Vault is already initialized with Shamir seals:

```bash
# Add migration flag
export VAULT_SEAL_MIGRATE=true

# Restart Vault
docker compose restart vault

# Unseal with old keys and -migrate flag
docker exec pki_vault vault operator unseal -migrate <old_key1>
docker exec pki_vault vault operator unseal -migrate <old_key2>
docker exec pki_vault vault operator unseal -migrate <old_key3>

# Remove migration flag and restart
# (remove VAULT_SEAL_MIGRATE from compose file)
docker compose restart vault
```

### Security Considerations

1. **Run KMS Vault on a separate machine** - If both Vaults are on the same server, an attacker with server access can unseal both.

2. **Secure the KMS Vault unseal keys** - These are now your "root of trust". Store them in a hardware security module, safe, or distributed among trusted individuals.

3. **Enable TLS** - The example disables TLS for simplicity. In production, configure TLS for the KMS Vault.

4. **Network isolation** - Use firewalls to restrict access to the KMS Vault to only the SCR-PKI server.

5. **Token renewal** - The auto-unseal token has a 24h period. Consider using a longer period or implementing token renewal.

### High Availability Setup

For critical deployments, run the KMS Vault in HA mode:

```hcl
# kms-vault-config/vault.hcl
storage "raft" {
  path = "/vault/data"
  node_id = "kms-node-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/vault/config/cert.pem"
  tls_key_file  = "/vault/config/key.pem"
}

api_addr = "https://kms-vault.example.com:8200"
cluster_addr = "https://kms-vault.example.com:8201"
```

### Comparison: Transit vs Cloud KMS

| Feature | Self-Hosted Transit | Cloud KMS |
|---------|--------------------| ----------|
| Internet required | ❌ No | ✅ Yes |
| Monthly cost | $0 (your hardware) | ~$1-5/month |
| You control the keys | ✅ Yes | ❌ No (cloud has access) |
| Setup complexity | Medium | Medium |
| Maintenance | You manage KMS Vault | Cloud provider manages |
| Latency | Low (local network) | Variable (internet) |
| Availability | Your infrastructure | Cloud SLA (99.9%+) |

---

## Option 4: Cloud KMS Auto-Unseal

This option uses a cloud Key Management Service to automatically unseal Vault. The master key is encrypted by the cloud KMS, so Vault can unseal itself without storing keys locally.

### Supported Cloud Providers

- [AWS KMS](#aws-kms)
- [Google Cloud KMS](#google-cloud-kms)
- [Azure Key Vault](#azure-key-vault)
- [Oracle OCI KMS](#oracle-oci-kms)
- [AliCloud KMS](#alicloud-kms)

---

### AWS KMS

#### Prerequisites
- AWS account with KMS access
- IAM credentials with `kms:Encrypt` and `kms:Decrypt` permissions

#### Setup

1. **Create a KMS Key in AWS Console**

   ```bash
   aws kms create-key --description "Vault Auto-Unseal Key"
   ```

   Note the `KeyId` from the output.

2. **Create IAM Policy**

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "kms:Encrypt",
           "kms:Decrypt",
           "kms:DescribeKey"
         ],
         "Resource": "arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID"
       }
     ]
   }
   ```

3. **Update docker-compose.yml**

   Add environment variables to the vault service:

   ```yaml
   vault:
     environment:
       - VAULT_SEAL_TYPE=awskms
       - VAULT_AWSKMS_SEAL_KEY_ID=arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID
       - AWS_ACCESS_KEY_ID=your-access-key
       - AWS_SECRET_ACCESS_KEY=your-secret-key
       - AWS_REGION=us-east-1
   ```

4. **Migrate from Shamir to KMS** (if already initialized)

   See [Seal Migration](#seal-migration) section below.

---

### Google Cloud KMS

#### Prerequisites
- GCP project with Cloud KMS API enabled
- Service account with `cloudkms.cryptoKeyVersions.useToEncrypt` and `cloudkms.cryptoKeyVersions.useToDecrypt` permissions

#### Setup

1. **Create a Key Ring and Key**

   ```bash
   gcloud kms keyrings create vault-keyring --location=global
   gcloud kms keys create vault-unseal-key \
     --location=global \
     --keyring=vault-keyring \
     --purpose=encryption
   ```

2. **Create Service Account**

   ```bash
   gcloud iam service-accounts create vault-unseal
   gcloud kms keys add-iam-policy-binding vault-unseal-key \
     --location=global \
     --keyring=vault-keyring \
     --member="serviceAccount:vault-unseal@PROJECT.iam.gserviceaccount.com" \
     --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
   ```

3. **Update docker-compose.yml**

   ```yaml
   vault:
     environment:
       - VAULT_SEAL_TYPE=gcpckms
       - VAULT_GCPCKMS_SEAL_KEY_RING=vault-keyring
       - VAULT_GCPCKMS_SEAL_CRYPTO_KEY=vault-unseal-key
       - VAULT_GCPCKMS_SEAL_PROJECT=your-project-id
       - VAULT_GCPCKMS_SEAL_REGION=global
       - GOOGLE_APPLICATION_CREDENTIALS=/vault/config/gcp-credentials.json
     volumes:
       - ./gcp-credentials.json:/vault/config/gcp-credentials.json:ro
   ```

---

### Azure Key Vault

#### Prerequisites
- Azure subscription with Key Vault
- Service principal with Key Vault Crypto User role

#### Setup

1. **Create a Key Vault and Key**

   ```bash
   az keyvault create --name vault-unseal-kv --resource-group mygroup --location eastus
   az keyvault key create --vault-name vault-unseal-kv --name vault-unseal-key --protection software
   ```

2. **Create Service Principal**

   ```bash
   az ad sp create-for-rbac --name vault-unseal-sp
   az keyvault set-policy --name vault-unseal-kv \
     --spn APP_ID \
     --key-permissions wrapKey unwrapKey get
   ```

3. **Update docker-compose.yml**

   ```yaml
   vault:
     environment:
       - VAULT_SEAL_TYPE=azurekeyvault
       - VAULT_AZUREKEYVAULT_VAULT_NAME=vault-unseal-kv
       - VAULT_AZUREKEYVAULT_KEY_NAME=vault-unseal-key
       - AZURE_TENANT_ID=your-tenant-id
       - AZURE_CLIENT_ID=your-client-id
       - AZURE_CLIENT_SECRET=your-client-secret
   ```

---

### Oracle OCI KMS

#### Prerequisites
- OCI tenancy with KMS access
- Either Instance Principal (for OCI compute) or API key authentication

#### Setup

1. **Create a Vault and Master Encryption Key**

   In OCI Console:
   - Go to Security > Vault
   - Create a new Vault
   - Create a Master Encryption Key (AES 256-bit recommended)
   - Note the Key OCID, Crypto Endpoint, and Management Endpoint

2. **Configure Authentication**

   **Option A: Instance Principal** (recommended for OCI compute instances)
   
   Create a Dynamic Group and Policy:
   ```
   # Dynamic Group matching rule
   instance.compartment.id = 'ocid1.compartment.oc1...'
   
   # Policy
   Allow dynamic-group vault-instances to use keys in compartment vault-compartment
   ```

   **Option B: API Key** (for non-OCI environments)
   
   Create an API key in OCI Console and download the config file.

3. **Update docker-compose.yml**

   For Instance Principal:
   ```yaml
   vault:
     environment:
       - VAULT_SEAL_TYPE=ocikms
       - VAULT_OCIKMS_SEAL_KEY_ID=ocid1.key.oc1.iad.xxxxx
       - VAULT_OCIKMS_CRYPTO_ENDPOINT=https://xxxxx-crypto.kms.us-ashburn-1.oraclecloud.com
       - VAULT_OCIKMS_MANAGEMENT_ENDPOINT=https://xxxxx-management.kms.us-ashburn-1.oraclecloud.com
   ```

   For API Key:
   ```yaml
   vault:
     environment:
       - VAULT_SEAL_TYPE=ocikms
       - VAULT_OCIKMS_SEAL_KEY_ID=ocid1.key.oc1.iad.xxxxx
       - VAULT_OCIKMS_CRYPTO_ENDPOINT=https://xxxxx-crypto.kms.us-ashburn-1.oraclecloud.com
       - VAULT_OCIKMS_MANAGEMENT_ENDPOINT=https://xxxxx-management.kms.us-ashburn-1.oraclecloud.com
       - VAULT_OCIKMS_AUTH_TYPE_API_KEY=true
       - OCI_CLI_USER=ocid1.user.oc1..xxxxx
       - OCI_CLI_TENANCY=ocid1.tenancy.oc1..xxxxx
       - OCI_CLI_FINGERPRINT=xx:xx:xx:xx
       - OCI_CLI_KEY_FILE=/vault/config/oci_api_key.pem
       - OCI_CLI_REGION=us-ashburn-1
     volumes:
       - ./oci_api_key.pem:/vault/config/oci_api_key.pem:ro
   ```

---

### AliCloud KMS

#### Prerequisites
- Alibaba Cloud account with KMS access
- Access key with AliyunKMSCryptoUserAccess permission

#### Setup

1. **Create a KMS Key**

   In AliCloud Console, create a CMK (Customer Master Key).

2. **Update docker-compose.yml**

   ```yaml
   vault:
     environment:
       - VAULT_SEAL_TYPE=alicloudkms
       - VAULT_ALICLOUDKMS_SEAL_KEY_ID=your-key-id
       - VAULT_ALICLOUDKMS_REGION=cn-hangzhou
       - ALICLOUD_ACCESS_KEY=your-access-key
       - ALICLOUD_SECRET_KEY=your-secret-key
   ```

---

## Seal Migration

If Vault is already initialized with Shamir seals and you want to migrate to Cloud KMS:

### Prerequisites
- Vault must be unsealed during migration
- You need the current unseal keys

### Migration Steps

1. **Add KMS Configuration**

   Update `docker-compose.yml` with KMS environment variables AND add:
   ```yaml
   vault:
     environment:
       # ... KMS config ...
       - VAULT_SEAL_MIGRATE=true
   ```

2. **Restart Vault**

   ```bash
   docker compose restart vault
   ```

3. **Unseal with Old Keys**

   Vault will prompt for the old Shamir keys to complete migration:
   ```bash
   docker exec pki_vault vault operator unseal -migrate <key1>
   docker exec pki_vault vault operator unseal -migrate <key2>
   docker exec pki_vault vault operator unseal -migrate <key3>
   ```

4. **Verify Migration**

   ```bash
   docker exec pki_vault vault status
   ```

   Should show the new seal type.

5. **Remove Migration Flag**

   Remove `VAULT_SEAL_MIGRATE=true` from docker-compose.yml and restart.

---

## Comparison Summary

| Feature | Local Keys | Manual Unseal | Self-Hosted Transit | Cloud KMS |
|---------|-----------|---------------|---------------------|-----------|
| Automatic unseal | ✅ | ❌ | ✅ | ✅ |
| No cloud dependency | ✅ | ✅ | ✅ | ❌ |
| No internet required | ✅ | ✅ | ✅ | ❌ |
| Keys protected at rest | ❌ | ✅ | ✅ | ✅ |
| Operator intervention | ❌ | ✅ (each restart) | ❌ (KMS unsealed once) | ❌ |
| Suitable for air-gapped | ✅ | ✅ | ✅ | ❌ |
| You control all keys | ✅ | ✅ | ✅ | ❌ |
| Monthly cost | $0 | $0 | $0 (your hardware) | ~$1-5 |
| Setup complexity | Easy | Easy | Medium | Medium |

## Recommendations

- **Home Lab (Isolated Network)**: Option 1, 2, or 3
- **Home Lab (Internet-facing)**: Option 2, 3, or 4
- **Self-Hosted Production**: Option 3 (Transit)
- **Cloud-Based Production**: Option 4 (Cloud KMS)
- **High Availability Required**: Option 3 (HA) or Option 4

## Troubleshooting

### Vault Stays Sealed After KMS/Transit Setup

1. Check connectivity:
   ```bash
   docker logs pki_vault 2>&1 | grep -i seal
   ```

2. Verify credentials:
   ```bash
   docker exec pki_vault env | grep -i "AWS\|AZURE\|GCP\|OCI"
   ```

3. Test KMS access manually (AWS example):
   ```bash
   aws kms describe-key --key-id your-key-id
   ```

### Migration Fails

1. Ensure Vault is unsealed before migration
2. Use the `-migrate` flag with unseal commands
3. Check logs for specific errors:
   ```bash
   docker logs pki_vault 2>&1 | tail -50
   ```

## References

- [HashiCorp Vault Seal Documentation](https://developer.hashicorp.com/vault/docs/configuration/seal)
- [AWS KMS Seal](https://developer.hashicorp.com/vault/docs/configuration/seal/awskms)
- [GCP Cloud KMS Seal](https://developer.hashicorp.com/vault/docs/configuration/seal/gcpckms)
- [Azure Key Vault Seal](https://developer.hashicorp.com/vault/docs/configuration/seal/azurekeyvault)
- [OCI KMS Seal](https://developer.hashicorp.com/vault/docs/configuration/seal/ocikms)
- [Seal Migration](https://developer.hashicorp.com/vault/docs/concepts/seal#seal-migration)
