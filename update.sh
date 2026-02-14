#!/bin/bash

# HTTPMR Update Tool
# This script updates HTTPMR to the latest version from GitHub

set -e  # Exit on any error

echo "=========================================="
echo "HTTPMR Update Tool"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# GitHub repository URL
GITHUB_REPO="https://github.com/KaliforniaGator/HTTPMR"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the HTTPMR directory
if [ ! -f "HTTPMR.py" ] || [ ! -d "webui" ]; then
    print_error "This script must be run from the HTTPMR root directory"
    exit 1
fi

# Check if git is available
if ! command -v git &> /dev/null; then
    print_error "Git is not installed or not in PATH"
    exit 1
fi

# Check if we have internet connectivity
if ! ping -c 1 github.com &> /dev/null; then
    print_error "No internet connectivity. Cannot update from GitHub."
    exit 1
fi

print_status "Starting update process..."

# Check current version
if [ -f "version" ]; then
    CURRENT_VERSION=$(cat version)
    print_status "Current version: $CURRENT_VERSION"
else
    print_warning "No version file found - assuming first installation"
fi

# Check remote version from GitHub
print_status "Checking remote version..."
REMOTE_VERSION_CONTENT=$(curl -s "$GITHUB_REPO/raw/HEAD/version" 2>/dev/null || echo "")

if [ -n "$REMOTE_VERSION_CONTENT" ]; then
    REMOTE_VERSION_LINE=$(echo "$REMOTE_VERSION_CONTENT" | head -n1 | tr -d '\n\r')
    print_status "Remote version: $REMOTE_VERSION_LINE"
    
    # Compare versions
    if [ -f "version" ]; then
        if [ "$CURRENT_VERSION" = "$REMOTE_VERSION_LINE" ]; then
            print_status "You already have the latest version ($REMOTE_VERSION_LINE)"
            print_status "No update needed."
            exit 0
        else
            print_status "New version available: $REMOTE_VERSION_LINE"
        fi
    else
        print_status "No local version found - will install: $REMOTE_VERSION_LINE"
    fi
else
    print_warning "No version file found in remote repository"
    print_status "Proceeding with update anyway..."
fi

# Backup current state
BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
print_warning "Creating backup in $BACKUP_DIR directory..."
mkdir -p "$BACKUP_DIR"
cp -r . "$BACKUP_DIR/" 2>/dev/null || true

# Download latest version from GitHub
print_status "Downloading latest version from GitHub..."
TEMP_DIR=$(mktemp -d)

git clone --depth 1 "$GITHUB_REPO" "$TEMP_DIR" || {
    print_error "Failed to download from GitHub"
    rm -rf "$TEMP_DIR"
    exit 1
}

# Copy files from temp directory, excluding .git and user data
print_status "Installing new files..."
rsync -av --exclude='.git' --exclude='backup_*' --exclude='reports' --exclude='.secure' --exclude='.venv' "$TEMP_DIR/" ./

# Clean up
rm -rf "$TEMP_DIR"

# Update Python dependencies
print_status "Updating Python dependencies..."

# Check if virtual environment exists
if [ -d ".venv" ]; then
    print_status "Updating dependencies in existing virtual environment..."
    source .venv/bin/activate
    pip install -r requirements.txt --upgrade
else
    print_warning "No virtual environment found. Creating new one..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
fi

# Clean up Python cache
print_status "Cleaning up Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# Make scripts executable
print_status "Making scripts executable..."
chmod +x run_webui.sh clean_pycache.sh update.sh 2>/dev/null || true

# Get final version
if [ -f "version" ]; then
    FINAL_VERSION=$(cat version)
else
    FINAL_VERSION="Unknown"
fi

print_status "Update completed successfully!"
echo ""
echo "=========================================="
echo "Update Summary:"
echo "=========================================="
echo "Repository: $GITHUB_REPO"
echo "Version: $FINAL_VERSION"
echo "Backup created: $BACKUP_DIR"
echo ""
echo "To restore backup if needed:"
echo "  rm -rf . && mv $BACKUP_DIR ."
echo ""
echo "To start the Web UI:"
echo "  ./run_webui.sh"
echo ""
echo "To run CLI tools:"
echo "  python HTTPMR.py --help"
echo "=========================================="

exit 0
