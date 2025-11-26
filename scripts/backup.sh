#!/bin/bash

# PKI System Backup Script
# Usage: ./scripts/backup.sh [output_dir]

set -e

# Configuration
BACKUP_DIR=${1:-"./backups"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="pki_backup_${TIMESTAMP}.tar.gz"
TEMP_DIR=$(mktemp -d)

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

echo "Starting backup process..."
echo "Temp dir: $TEMP_DIR"

# 1. Dump PostgreSQL Database
echo "Step 1: Dumping Database..."
if docker ps | grep -q pki_postgres; then
    # Use the container's environment variable POSTGRES_PASSWORD for authentication
    docker exec pki_postgres bash -c "PGPASSWORD=\$POSTGRES_PASSWORD pg_dump -U pki_user pki" > "$TEMP_DIR/db_dump.sql"
else
    echo "Error: Postgres container is not running!"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# 2. Copy Vault Config (Postgres Backend)
# Vault data is now in the database dump!
echo "Step 2: Archiving Vault Config..."
mkdir -p "$TEMP_DIR/vault"
if [ -d "data/vault/config" ]; then
    cp -r data/vault/config "$TEMP_DIR/vault/"
fi

# 3. Copy Exported Certificates
echo "Step 3: Archiving Certificates..."
mkdir -p "$TEMP_DIR/certs"
if [ -d "data/certs" ]; then
    cp -r data/certs "$TEMP_DIR/"
fi

# 5. Copy Environment Config (Optional but recommended)
echo "Step 5: Archiving Configuration..."
if [ -f ".env" ]; then
    cp .env "$TEMP_DIR/"
fi
if [ -f "docker-compose.yml" ]; then
    cp docker-compose.yml "$TEMP_DIR/"
fi

# 4. Create Archive
echo "Step 4: Creating archive..."
tar -czf "$BACKUP_DIR/$FILENAME" -C "$TEMP_DIR" .

# Cleanup
rm -rf "$TEMP_DIR"

echo "✅ Backup completed successfully!"
echo "📁 File: $BACKUP_DIR/$FILENAME"
