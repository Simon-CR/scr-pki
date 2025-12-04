#!/bin/bash

# PKI Platform Deployment Script
# This script handles the setup and deployment of the PKI platform.

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 PKI Platform Deployment${NC}"
echo "============================"

# 1. Prerequisites Check
echo -e "\n${YELLOW}[1/5] Checking prerequisites...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed.${NC}"
    exit 1
fi

# Check for docker compose (v2) or docker-compose (v1)
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    echo -e "${RED}❌ Docker Compose is not installed.${NC}"
    exit 1
fi
echo "✅ Docker and Docker Compose found."

# 2. Environment Setup
echo -e "\n${YELLOW}[2/5] Setting up environment...${NC}"
if [ ! -f .env ]; then
    echo "📝 Creating .env file from example..."
    cp .env.example .env
    # Generate random secrets
    JWT_SECRET=$(openssl rand -hex 32)
    sed -i.bak "s/JWT_SECRET_KEY=change_this_to_a_secure_random_string/JWT_SECRET_KEY=$JWT_SECRET/" .env
    rm -f .env.bak
    echo "✅ Created .env file with generated secrets."
    echo -e "${YELLOW}⚠️  Please review .env file and update passwords!${NC}"
    read -p "Press Enter to continue after reviewing .env (or Ctrl+C to stop)..."
else
    echo "✅ .env file exists."
fi

# 3. Directory Structure
echo -e "\n${YELLOW}[3/5] Creating directory structure...${NC}"
mkdir -p data/{certs,logs/{backend,frontend,nginx,monitor},postgres,vault/{data,logs}}
chmod 755 data
chmod -R 755 data/logs
chmod 700 data/vault/data
echo "✅ Directories created."

# 4. Start Services
echo -e "\n${YELLOW}[4/5] Starting services...${NC}"
$DOCKER_COMPOSE up -d --remove-orphans

# 5. Vault Initialization (The tricky part)
echo -e "\n${YELLOW}[5/5] Checking Vault status...${NC}"
echo "Waiting for Vault to start..."
sleep 5

# Check if Vault is initialized
VAULT_STATUS=$($DOCKER_COMPOSE exec vault vault status -format=json 2>/dev/null || true)

if [[ -z "$VAULT_STATUS" ]]; then
    echo -e "${RED}❌ Could not contact Vault. Check logs: $DOCKER_COMPOSE logs vault${NC}"
    exit 1
fi

INITIALIZED=$(echo "$VAULT_STATUS" | grep -o '"initialized": *true' || true)
SEALED=$(echo "$VAULT_STATUS" | grep -o '"sealed": *true' || true)

if [[ -z "$INITIALIZED" ]]; then
    echo -e "${YELLOW}⚠️  Vault is NOT initialized.${NC}"
    echo "Initializing Vault..."
    INIT_OUTPUT=$($DOCKER_COMPOSE exec vault vault operator init -format=json)
    
    # Save keys securely
    echo "$INIT_OUTPUT" > vault_keys.json
    chmod 600 vault_keys.json
    
    echo -e "${GREEN}✅ Vault initialized! Keys saved to 'vault_keys.json'.${NC}"
    echo -e "${RED}🔥 IMPORTANT: BACK UP 'vault_keys.json' AND DELETE IT FROM THIS SERVER!${NC}"
    
    # Parse keys for unsealing
    KEY1=$(echo "$INIT_OUTPUT" | grep -o '"unseal_keys_b64": *\[ *"[^"]*"' | cut -d'"' -f4)
    KEY2=$(echo "$INIT_OUTPUT" | grep -o '"unseal_keys_b64": *\[ *"[^"]*", *"[^"]*"' | cut -d'"' -f6)
    KEY3=$(echo "$INIT_OUTPUT" | grep -o '"unseal_keys_b64": *\[ *"[^"]*", *"[^"]*", *"[^"]*"' | cut -d'"' -f8)
    ROOT_TOKEN=$(echo "$INIT_OUTPUT" | grep -o '"root_token": *"[^"]*"' | cut -d'"' -f4)
    
    echo "Unsealing Vault..."
    $DOCKER_COMPOSE exec vault vault operator unseal "$KEY1" > /dev/null
    $DOCKER_COMPOSE exec vault vault operator unseal "$KEY2" > /dev/null
    $DOCKER_COMPOSE exec vault vault operator unseal "$KEY3" > /dev/null
    
    # Update .env with root token
    sed -i.bak "s/VAULT_TOKEN=.*/VAULT_TOKEN=$ROOT_TOKEN/" .env
    rm -f .env.bak
    echo "✅ Vault unsealed and root token updated in .env."
    
    # Restart backend to pick up new token
    $DOCKER_COMPOSE restart backend
    
elif [[ -n "$SEALED" ]]; then
    echo -e "${YELLOW}⚠️  Vault is SEALED.${NC}"
    if [ -f vault_keys.json ]; then
        echo "Found vault_keys.json, attempting to auto-unseal..."
        KEY1=$(grep -o '"unseal_keys_b64": *\[ *"[^"]*"' vault_keys.json | cut -d'"' -f4)
        KEY2=$(grep -o '"unseal_keys_b64": *\[ *"[^"]*", *"[^"]*"' vault_keys.json | cut -d'"' -f6)
        KEY3=$(grep -o '"unseal_keys_b64": *\[ *"[^"]*", *"[^"]*", *"[^"]*"' vault_keys.json | cut -d'"' -f8)
        
        $DOCKER_COMPOSE exec vault vault operator unseal "$KEY1" > /dev/null
        $DOCKER_COMPOSE exec vault vault operator unseal "$KEY2" > /dev/null
        $DOCKER_COMPOSE exec vault vault operator unseal "$KEY3" > /dev/null
        echo "✅ Vault unsealed."
    else
        echo -e "${RED}❌ Vault is sealed and no keys found. Please unseal manually:${NC}"
        echo "   $DOCKER_COMPOSE exec vault vault operator unseal <key>"
    fi
else
    echo "✅ Vault is already initialized and unsealed."
fi

echo -e "\n${GREEN}🎉 Deployment Complete!${NC}"
echo "------------------------------------------------"
echo "Frontend: https://localhost (Accept self-signed cert)"
echo "Vault UI: https://localhost/ui/"
echo "------------------------------------------------"
