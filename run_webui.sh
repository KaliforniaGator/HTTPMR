#!/usr/bin/env bash
set -euo pipefail

# run_webui.sh
# Creates a .venv if missing, installs requirements, then runs the FastAPI WebUI

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
REQUIREMENTS="$ROOT_DIR/requirements.txt"

echo "HTTPMR WebUI helper - ensuring virtualenv and dependencies"

if [ ! -f "$REQUIREMENTS" ]; then
  echo "requirements.txt not found in $ROOT_DIR"
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

PIP="$VENV_DIR/bin/pip"
PY="$VENV_DIR/bin/python"
UVICORN="$VENV_DIR/bin/uvicorn"

if [ ! -x "$PIP" ]; then
  echo "pip not found inside venv; aborting"
  exit 1
fi

echo "Upgrading pip and installing requirements (this is idempotent)..."
"$PIP" install --upgrade pip
"$PIP" install -r "$REQUIREMENTS"

if [ ! -x "$UVICORN" ]; then
  echo "uvicorn not found in venv (installation may have failed). Trying to run via python -m uvicorn..."
  exec "$PY" -m uvicorn webui.app:app --reload --host 127.0.0.1 --port 8000
else
  echo "Starting WebUI with uvicorn..."
  exec "$UVICORN" webui.app:app --reload --host 127.0.0.1 --port 8000
fi
