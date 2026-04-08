#!/bin/bash
# setup.sh — First-time project setup on a Linux machine with Go installed
set -euo pipefail

echo "═══════════════════════════════════════════════"
echo "  Samba Panel — Project Setup"
echo "═══════════════════════════════════════════════"

# Check Go version
if ! command -v go &>/dev/null; then
    echo "❌ Go is not installed. Install from https://go.dev/dl/ (Go 1.21+ required)"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED="1.21"
if [[ "$(printf '%s\n' "$REQUIRED" "$GO_VERSION" | sort -V | head -1)" != "$REQUIRED" ]]; then
    echo "❌ Go $REQUIRED+ is required. Found: $GO_VERSION"
    exit 1
fi
echo "✓ Go $GO_VERSION found"

# Download dependencies
echo "▶ Downloading dependencies..."
go mod download
go mod verify
echo "✓ Dependencies OK"

# Setup .env
if [ ! -f .env ]; then
    cp .env.example .env
    JWT_SECRET=$(openssl rand -hex 32)
    CSRF_SECRET=$(openssl rand -hex 32)
    sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$JWT_SECRET/" .env
    sed -i "s/^CSRF_SECRET=.*/CSRF_SECRET=$CSRF_SECRET/" .env
    echo "✓ Created .env with generated secrets"
else
    echo "ℹ .env already exists, skipping"
fi

# Build
echo "▶ Building..."
make build
echo "✓ Binary at bin/sambaguard"

echo ""
echo "═══════════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  To run in development:"
echo "    make run"
echo ""
echo "  To deploy with Docker:"
echo "    make docker"
echo "    docker-compose up -d"
echo "    docker-compose logs -f  # check for admin password"
echo "═══════════════════════════════════════════════"
