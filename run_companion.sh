#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT"

# Start backend
python -m uvicorn cc.api:app --host 127.0.0.1 --port 7078 --reload >/tmp/cc_uvicorn.log 2>&1 &
UV_PID=$!

# Wait until listening
for i in {1..60}; do
  if curl -fsS "http://127.0.0.1:7078/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

# Start Electron
cd "$ROOT/electron-app"
CC_URL="http://127.0.0.1:7078/" npm start

# Cleanup
kill "$UV_PID" 2>/dev/null || true
