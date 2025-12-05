#!/usr/bin/env python3
"""Store unseal keys securely with DEK + KMS wrapping."""

import json
from app.core.database import SessionLocal
from app.core.auto_unseal import auto_unseal_manager
from app.models.system import SystemConfig
from app.core.security import decrypt_value

db = SessionLocal()

# The unseal keys
keys = [
    "a35c2c42071b10e5647b0e238e0d0d53c3a21200b90cd1e36ffe983ae9940a8fbc",
    "fc238f9a9eed808e4c8ed4685a2a5435a1f999d57dcd651066e054e4f083b33367",
    "73139829a79bf4b45d2f264acf3608490d644132ab4883c5dc05ad5bc9f8ef58d5",
    "aaa0138ec5b0aed921e7202f8a557d37b2268755d738a2c3996c9faf6869c38e8a",
    "4315f724ded54733402342d933a1c42555cf223556e9581774c626e8694ae6d325"
]

# Generate DEK
dek = auto_unseal_manager.generate_dek()
print(f"Generated DEK: {len(dek)} bytes")

wrap_results = {}

# Try OCI KMS
config = db.query(SystemConfig).filter(SystemConfig.key == "seal_ocikms").first()
if not config:
    config = db.query(SystemConfig).filter(SystemConfig.key == "vault_seal_ocikms").first()
if config:
    try:
        decrypted = decrypt_value(config.value)
        kms_config = json.loads(decrypted)
        if kms_config.get("enabled"):
            result = auto_unseal_manager.wrap_dek(dek, "ocikms", kms_config)
            if result.get("success"):
                wrap_results["ocikms"] = result
                print("OCI KMS: DEK wrapped successfully")
            else:
                print(f"OCI KMS: Failed - {result.get('error')}")
        else:
            print("OCI KMS: Not enabled")
    except Exception as e:
        print(f"OCI KMS: Error - {e}")
else:
    print("OCI KMS: Not configured")

# Try GCP KMS
config = db.query(SystemConfig).filter(SystemConfig.key == "seal_gcpckms").first()
if not config:
    config = db.query(SystemConfig).filter(SystemConfig.key == "vault_seal_gcpckms").first()
if config:
    try:
        decrypted = decrypt_value(config.value)
        kms_config = json.loads(decrypted)
        if kms_config.get("enabled"):
            result = auto_unseal_manager.wrap_dek(dek, "gcpckms", kms_config)
            if result.get("success"):
                wrap_results["gcpckms"] = result
                print("GCP KMS: DEK wrapped successfully")
            else:
                print(f"GCP KMS: Failed - {result.get('error')}")
        else:
            print("GCP KMS: Not enabled")
    except Exception as e:
        print(f"GCP KMS: Error - {e}")
else:
    print("GCP KMS: Not configured")

# Store encrypted keys
auto_unseal_manager.store_encrypted_keys(db, keys, dek, wrap_results)
print("Encrypted keys stored in database")

# Store local DEK too (for fallback)
auto_unseal_manager.store_local_dek(db, dek)
print("Local DEK stored (Fernet encrypted)")

# Verify
available = auto_unseal_manager.get_available_providers(db)
print(f"Available providers: {available}")

db.close()
print("Done!")
