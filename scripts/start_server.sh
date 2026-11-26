#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -r .env ]]; then
  set -a
  # .env is locally generated (no commands or arbitrary user input).
  source .env
  set +a
elif [[ -z "${SECURENET_JWT_SECRET:-}" ]]; then
  echo 'Run python tools/setup_lab.py init first (or pass .env via Docker Compose)' >&2
  exit 1
fi
export PYTHONUNBUFFERED=1
host="${BIND_HOST:-127.0.0.1}"
http_port="${HTTP_PORT:-8080}"
https_port="${HTTPS_PORT:-8443}"
python -m server.app --host "$host" --port "$http_port" &
http_pid=$!
python -m server.app --host "$host" --port "$https_port" --tls &
https_pid=$!
trap 'kill "$http_pid" "$https_pid" 2>/dev/null || true;wait 2>/dev/null || true' EXIT INT TERM
wait -n "$http_pid" "$https_pid"
