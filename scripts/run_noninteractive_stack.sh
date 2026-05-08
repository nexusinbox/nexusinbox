#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
RUNTIME_DIR="${AGENT_INBOX_RUNTIME_DIR:-/tmp/nexusinbox-noninteractive}"
SIGNER_PID_FILE="$RUNTIME_DIR/signer.pid"
GATEWAY_PID_FILE="$RUNTIME_DIR/gateway.pid"
SIGNER_LOG="$RUNTIME_DIR/signer.log"
GATEWAY_LOG="$RUNTIME_DIR/gateway.log"

SIGNER_SOCKET="${AGENT_INBOX_SIGNER_SOCKET:-/tmp/nexusinbox-signer.sock}"
GATEWAY_SOCKET="${AGENT_INBOX_GATEWAY_SOCKET:-/tmp/nexusinbox-gateway.sock}"
API_URL="${AGENT_INBOX_API_URL:-http://localhost:8080}"
KEY_FILE="${AGENT_INBOX_KEY_FILE:-$ROOT_DIR/.local/nexusinbox-signer.key.enc}"

usage() {
  cat <<EOF
Usage:
  AGENT_INBOX_AID=aid:ai:... \\
  AGENT_INBOX_CREDENTIAL_ID=<uuid> \\
  AGENT_INBOX_KEY_FILE=/path/to/signing.key.enc \\
  $0 start

Commands:
  start   Start signer-daemon and agent-gateway in background
  stop    Stop both processes
  status  Show process/socket/log status
EOF
}

ensure_runtime_dir() {
  mkdir -p "$RUNTIME_DIR"
  mkdir -p "$(dirname "$KEY_FILE")"
}

is_running() {
  pid="$1"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

read_pid() {
  file="$1"
  if [ -f "$file" ]; then
    cat "$file"
  fi
}

start() {
  : "${AGENT_INBOX_AID:?AGENT_INBOX_AID is required}"
  : "${AGENT_INBOX_CREDENTIAL_ID:?AGENT_INBOX_CREDENTIAL_ID is required}"
  ensure_runtime_dir

  signer_pid="$(read_pid "$SIGNER_PID_FILE" || true)"
  gateway_pid="$(read_pid "$GATEWAY_PID_FILE" || true)"
  if is_running "$signer_pid" || is_running "$gateway_pid"; then
    echo "Non-interactive stack appears to be already running."
    "$0" status
    exit 1
  fi

  rm -f "$SIGNER_SOCKET" "$GATEWAY_SOCKET"

  echo "Starting signer-daemon..."
  (
    cd "$ROOT_DIR"
    cargo run --manifest-path services/signer-daemon/Cargo.toml -- \
      --socket "$SIGNER_SOCKET" \
      --key-file "$KEY_FILE" \
      --aid "$AGENT_INBOX_AID" \
      --credential-id "$AGENT_INBOX_CREDENTIAL_ID" \
      --api-url "$API_URL"
  ) >"$SIGNER_LOG" 2>&1 &
  echo $! >"$SIGNER_PID_FILE"

  sleep 1

  echo "Starting agent-gateway..."
  (
    cd "$ROOT_DIR"
    cargo run --manifest-path services/agent-gateway/Cargo.toml -- \
      --llm-socket "$GATEWAY_SOCKET" \
      --signer-socket "$SIGNER_SOCKET" \
      --api-url "$API_URL/api"
  ) >"$GATEWAY_LOG" 2>&1 &
  echo $! >"$GATEWAY_PID_FILE"

  sleep 1
  "$0" status
}

stop() {
  signer_pid="$(read_pid "$SIGNER_PID_FILE" || true)"
  gateway_pid="$(read_pid "$GATEWAY_PID_FILE" || true)"

  if is_running "$gateway_pid"; then
    echo "Stopping agent-gateway ($gateway_pid)"
    kill "$gateway_pid" || true
  fi
  if is_running "$signer_pid"; then
    echo "Stopping signer-daemon ($signer_pid)"
    kill "$signer_pid" || true
  fi

  rm -f "$SIGNER_PID_FILE" "$GATEWAY_PID_FILE" "$SIGNER_SOCKET" "$GATEWAY_SOCKET"
}

status() {
  signer_pid="$(read_pid "$SIGNER_PID_FILE" || true)"
  gateway_pid="$(read_pid "$GATEWAY_PID_FILE" || true)"

  echo "Runtime dir:  $RUNTIME_DIR"
  echo "API URL:      $API_URL"
  echo "Signer socket:$SIGNER_SOCKET"
  echo "Gateway socket:$GATEWAY_SOCKET"
  echo "Signer PID:   ${signer_pid:-<none>}"
  echo "Gateway PID:  ${gateway_pid:-<none>}"
  echo "Signer up:    $(is_running "$signer_pid" && echo yes || echo no)"
  echo "Gateway up:   $(is_running "$gateway_pid" && echo yes || echo no)"
  echo "Signer log:   $SIGNER_LOG"
  echo "Gateway log:  $GATEWAY_LOG"
}

cmd="${1:-}"
case "$cmd" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) usage; exit 1 ;;
esac
