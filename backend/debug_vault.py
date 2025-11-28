import sys
import os
import logging
import structlog

# Configure logging to stdout
logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger()

# Add current directory to path so we can import app
sys.path.append(os.getcwd())

try:
    from app.core.vault import vault_client
    from app.core.config import settings
except ImportError as e:
    print(f"Error importing app modules: {e}")
    sys.exit(1)

def debug_vault():
    print("--- Vault Debug Script ---")
    print(f"Vault Address: {settings.VAULT_ADDR}")
    print(f"Vault Token (Env): {'Set' if settings.VAULT_TOKEN else 'Not Set'}")
    
    print("\n1. Checking Connection...")
    try:
        vault_client.connect()
        print(f"Connected: {vault_client.client is not None}")
        print(f"Authenticated: {vault_client.is_authenticated()}")
        
        if not vault_client.is_authenticated():
            print("ERROR: Not authenticated. Cannot proceed.")
            return
            
        status = vault_client.get_vault_status()
        print(f"Status: {status}")
        
    except Exception as e:
        print(f"Connection Error: {e}")
        return

    print("\n2. Listing Keys in 'certificates/'...")
    try:
        keys = vault_client.list_stored_keys("certificates")
        print(f"Found {len(keys)} keys.")
        print(f"Keys: {keys}")
    except Exception as e:
        print(f"List Error: {e}")

    print("\n3. Testing Specific Key Retrieval...")
    # Key ID from the user's log
    target_key_id = "certificates/490172712183857475159310435515881326353040518215"
    print(f"Attempting to retrieve: {target_key_id}")
    
    try:
        # Try raw read first to see the response
        path = f"pki/keys/{target_key_id}"
        print(f"Raw Read Path: {path}")
        
        # We need to access the client directly to bypass the try/catch in retrieve_private_key
        response = vault_client.client.secrets.kv.v2.read_secret_version(
            path=path
        )
        print("Raw Response: Success (Data hidden)")
        
        # Now try the wrapper
        key = vault_client.retrieve_private_key(target_key_id)
        if key:
            print("Wrapper Retrieval: Success")
        else:
            print("Wrapper Retrieval: Failed (returned None)")
            
    except Exception as e:
        print(f"Retrieval Error: {e}")
        import traceback
        traceback.print_exc()

    print("\n5. Checking Secrets Engines...")
    try:
        mounts = vault_client.client.sys.list_mounted_secrets_engines()
        # print(f"Mounts: {json.dumps(mounts, indent=2)}")
        
        if 'pki/' in mounts:
            print("\nPKI Engine found at 'pki/'. Checking configuration...")
                
            try:
                # Check Cluster config
                cluster_config = vault_client.client.read('pki/config/cluster')
                print(f"Cluster Config: {json.dumps(cluster_config, indent=2)}")
                
                if cluster_config and 'data' in cluster_config:
                    path = cluster_config['data'].get('path')
                    aia_path = cluster_config['data'].get('aia_path')
                    print(f"Cluster Path: {path}")
                    print(f"AIA Path: {aia_path}")
            except Exception as e:
                print(f"Failed to read Cluster config: {e}")
                

        else:
            print("\nWARNING: 'pki/' engine NOT found!")
            
    except Exception as e:
        print(f"Mounts Error: {e}")

if __name__ == "__main__":
    import json
    debug_vault()
