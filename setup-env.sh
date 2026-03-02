#!/bin/bash
# Fillr Setup Script
# Initializes environment configuration files

echo ""
echo "========================================"
echo "  Fillr Environment Setup"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if env files already exist
CLIENT_ENV="client/env.js"
EXT_ENV="extension/env.js"
SERVER_ENV="server/.env"

# Function to copy if not exists
copy_if_missing() {
    local source=$1
    local dest=$2
    local name=$3
    
    if [ -f "$dest" ]; then
        echo -e "${YELLOW}[SKIP]${NC} $name already exists: $dest"
    else
        if [ -f "$source" ]; then
            cp "$source" "$dest"
            echo -e "${GREEN}[OK]${NC} Created $name: $dest"
        else
            echo -e "${RED}[ERROR]${NC} Template not found: $source"
            return 1
        fi
    fi
    return 0
}

echo "Setting up environment files..."
echo ""

# Client env
copy_if_missing "client/env.example.js" "$CLIENT_ENV" "Frontend config"

# Extension env
copy_if_missing "extension/env.example.js" "$EXT_ENV" "Extension config"

# Server env
if [ -f "$SERVER_ENV" ]; then
    echo -e "${YELLOW}[SKIP]${NC} Server config already exists: $SERVER_ENV"
else
    echo -e "${YELLOW}[MANUAL]${NC} Create $SERVER_ENV manually with:"
    echo "  PORT=5000"
    echo "  MONGO_URI=your-mongodb-connection-string"
    echo "  JWT_SECRET=your-secret-key"
    echo "  (see README.md for full configuration)"
fi

echo ""
echo "========================================"
echo -e "${GREEN}Setup Complete!${NC}"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Edit client/env.js with your API URL"
echo "  2. Edit extension/env.js with your API URL"
echo "  3. Create server/.env with database credentials"
echo "  4. Run 'cd server && npm install && npm run dev'"
echo ""
