#!/usr/bin/env bash
set -euo pipefail

# clean_pycache.sh
# Recursively remove Python __pycache__ directories and compiled files (*.pyc, *.pyo)
# Usage: ./clean_pycache.sh [path]

ROOT_DIR="${1:-$(pwd)}"

echo "Cleaning Python caches and compiled files under: $ROOT_DIR"

# Find and remove __pycache__ directories
find "$ROOT_DIR" -type d -name '__pycache__' -prune -print -exec rm -rf {} + || true

# Find and remove .pyc and .pyo files
find "$ROOT_DIR" -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.pyd' \) -print -exec rm -f {} + || true

# Also remove pytest cache directories if present
find "$ROOT_DIR" -type d -name '.pytest_cache' -prune -print -exec rm -rf {} + || true

echo "Cleanup complete."
