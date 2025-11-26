#!/bin/bash

# PKI System Restore Script
# Usage: ./scripts/restore.sh <backup_file.tar.gz>

set -e

BACKUP_FILE=$1
TEMP_DIR=$(mktemp -d)

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file.tar.gz>"
    exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "⚠️  WARNING: This will OVERWRITE the current database and Vault data."
echo "⚠️  The system will be stopped during this process."
read -p "Are you sure you want to continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Restore cancelled."
    exit 1
fi

echo "Starting restore process..."

# 1. Extract Backup
echo "Step 1: Extracting backup..."
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

# 2. Stop Containers
echo "Step 2: Stopping containers..."
docker compose down

# 3. Restore Vault Config
echo "Step 3: Restoring Vault config..."
# Restore Config
if [ -d "$TEMP_DIR/vault/config" ]; then
    mkdir -p data/vault/config
    cp -r "$TEMP_DIR/vault/config/"* data/vault/config/
fi

# 4. Restore Certificates
echo "Step 4: Restoring Certificates..."
if [ -d "$TEMP_DIR/certs" ]; then
    mkdir -p data/certs
    cp -r "$TEMP_DIR/certs/"* data/certs/
fi

# 5. Restore Database
echo "Step 5: Restoring Database..."
# We need to start Postgres ONLY to restore the dump
docker compose up -d postgres
echo "Waiting for Postgres to be ready..."
until docker exec pki_postgres pg_isready -U pki_user > /dev/null 2>&1; do
    sleep 1
done

# Drop and Re-create Schema (simplest way to ensure clean state)
# Or just feed the dump if it includes DROP commands (pg_dump usually doesn't by default unless requested)
# We'll assume the dump is a data dump.
# Let's drop the public schema and recreate it to be safe
echo "Resetting database schema..."
docker exec pki_postgres psql -U pki_user -d pki -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

echo "Importing SQL dump..."
cat "$TEMP_DIR/db_dump.sql" | docker exec -i pki_postgres psql -U pki_user -d pki

# 6. Restart All Services
echo "Step 6: Restarting all services..."
docker compose up -d

# Cleanup
rm -rf "$TEMP_DIR"

echo "✅ Restore completed successfully!"
