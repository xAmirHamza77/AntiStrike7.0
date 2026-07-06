#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3.12 -m venv .venv 2>/dev/null || python3 -m venv .venv
  source .venv/bin/activate
  pip install -e .
else
  source .venv/bin/activate
fi

echo "Starting Antistrike 7.0 server..."
echo "  API:       http://127.0.0.1:7700"
echo "  Dashboard: http://127.0.0.1:7700/dashboard"
echo "  Docs:      http://127.0.0.1:7700/api/docs"
echo ""
exec antistrike-server