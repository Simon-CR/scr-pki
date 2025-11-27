#!/bin/bash

# URL of your Vault instance
VAULT_ADDR="http://localhost:8200"

# YOUR UNSEAL KEYS (Replace these with your actual keys)
KEY1="your-key-1-here"
KEY2="your-key-2-here"
KEY3="your-key-3-here"

echo "Waiting for Vault to be ready..."
until curl -s $VAULT_ADDR/v1/sys/health > /dev/null; do
    echo "Vault is not responding yet..."
    sleep 2
done

echo "Unsealing Vault..."
curl -s --request POST --data "{\"key\": \"$KEY1\"}" $VAULT_ADDR/v1/sys/unseal | grep "sealed"
curl -s --request POST --data "{\"key\": \"$KEY2\"}" $VAULT_ADDR/v1/sys/unseal | grep "sealed"
curl -s --request POST --data "{\"key\": \"$KEY3\"}" $VAULT_ADDR/v1/sys/unseal | grep "sealed"

echo "Done!"
