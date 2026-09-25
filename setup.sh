#!/bin/bash

# TRON THE DLP AGENT System Setup Script

set -e

echo "🛡️ TRON THE DLP AGENT System Setup"
echo "=============================="
echo

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found"
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Setup config
echo "Setting up configuration..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠️  Created .env file - PLEASE configure it with your credentials"
fi

# Validate service account
if [ ! -f config/service-account.json ]; then
    echo "❌ Service account JSON not found"
    echo "Place your GCP service account key at config/service-account.json"
    exit 1
fi

echo
echo "✅ Setup complete!"
echo
echo "Next steps:"
echo "1. Edit .env (see README: APP_AUTH_SECRET, TELEGRAM_BOT_TOKEN, GCP_PROJECT_ID, ...)"
echo "2. Run: ./start   (API + console)   or   ./start_all.sh   (API + agents)"
echo
echo "Or use Docker:"
echo "docker compose up -d"
