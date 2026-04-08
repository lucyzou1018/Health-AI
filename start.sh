#!/usr/bin/env bash
# CodeAutrix — Backend startup script
# Usage:
#   ./start.sh          — production mode (stable, no auto-reload)
#   ./start.sh --dev    — development mode (auto-reloads on Python file changes)
#                         WARNING: --dev will interrupt in-flight scan tasks on reload!

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"

cd "$BACKEND_DIR"

if [[ "$1" == "--dev" ]]; then
  echo "⚠️  Starting in DEV mode (--reload enabled)."
  echo "   File changes will restart the server and may interrupt active scan tasks."
  source .venv/bin/activate
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
else
  echo "🚀 Starting CodeAutrix backend (stable mode, no auto-reload)..."
  source .venv/bin/activate
  uvicorn app.main:app --host 0.0.0.0 --port 8000
fi
