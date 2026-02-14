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

# Backup current state (optional but recommended)
BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
print_warning "Creating backup in $BACKUP_DIR directory..."
mkdir -p "$BACKUP_DIR"
cp -r . "$BACKUP_DIR/" 2>/dev/null || true

# Stash any local changes
if [ -n "$(git status --porcelain)" ]; then
    print_warning "Local changes detected. Stashing changes..."
    git stash push -m "Auto-stash before update on $(date)"
fi

# Fetch latest changes from origin
print_status "Fetching latest changes from GitHub..."
git fetch origin

# Get current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
print_status "Current branch: $CURRENT_BRANCH"

# Check if we're on main/master, switch to main if needed
if [ "$CURRENT_BRANCH" != "main" ] && [ "$CURRENT_BRANCH" != "master" ]; then
    print_warning "Not on main/master branch. Switching to main branch..."
    git checkout main 2>/dev/null || git checkout master 2>/dev/null || {
        print_error "Could not switch to main or master branch"
        exit 1
    }
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
fi

# Pull latest changes
print_status "Pulling latest changes..."
git pull origin "$CURRENT_BRANCH"

# Update submodules if any exist
if [ -f ".gitmodules" ]; then
    print_status "Updating submodules..."
    git submodule update --init --recursive
fi

# Update Python dependencies if requirements.txt changed
if git diff --name-only HEAD@{1} HEAD | grep -q "requirements.txt"; then
    print_status "Requirements.txt changed. Updating Python dependencies..."
    
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
else
    print_status "No dependency updates needed."
fi

# Clean up Python cache
print_status "Cleaning up Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# Make scripts executable
print_status "Making scripts executable..."
chmod +x run_webui.sh clean_pycache.sh update.sh 2>/dev/null || true

# Get version information
COMMIT_HASH=$(git rev-parse --short HEAD)
COMMIT_DATE=$(git log -1 --format="%ci" HEAD)
REMOTE_URL=$(git remote get-url origin)

print_status "Update completed successfully!"
echo ""
echo "=========================================="
echo "Update Summary:"
echo "=========================================="
echo "Repository: $REMOTE_URL"
echo "Latest Commit: $COMMIT_HASH"
echo "Commit Date: $COMMIT_DATE"
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

# Check if there were stashed changes
if git stash list | grep -q "Auto-stash before update"; then
    print_warning "You have stashed local changes."
    print_warning "To restore them run: git stash pop"
fi

exit 0
