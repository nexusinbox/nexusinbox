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
# Optional X25519 key for opening incoming messages. Required for the
# auto-reply executor (AGENT_INBOX_MODE_A_EXECUTOR=on, docs/19 §7).
ENCRYPTION_KEY_FILE="${AGENT_INBOX_ENCRYPTION_KEY_FILE:-}"

usage() {
  cat <<EOF
Usage:
  AGENT_INBOX_AID=aid:ai:... \\
  AGENT_INBOX_CREDENTIAL_ID=<uuid> \\
  AGENT_INBOX_KEY_FILE=/path/to/signing.key.enc \\
  [AGENT_INBOX_ENCRYPTION_KEY_FILE=/path/to/encryption.key.enc] \\
  [AGENT_INBOX_MODE_A_EXECUTOR=on] \\
  $0 start

Enroll the daemon once first (docs/19 §3):
  cargo run --manifest-path services/signer-daemon/Cargo.toml -- --enroll ...

Commands:
  start   Ask for the key passphrase (one stdin line when not a terminal),
          then start signer-daemon and agent-gateway in background
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

  # The daemon reads its key passphrase from stdin, which a background job
  # does not have. Read it here (no echo on a terminal, else one line from
  # stdin) and hand it over on a pipe; printf is a shell builtin, so the
  # passphrase never shows in a process list.
  if [ -t 0 ]; then
    printf 'Passphrase for %s: ' "$KEY_FILE" >&2
    trap 'stty echo; exit 130' INT TERM
    stty -echo
    IFS= read -r KEY_PASSPHRASE || KEY_PASSPHRASE=""
    stty echo
    trap - INT TERM
    printf '\n' >&2
  else
    IFS= read -r KEY_PASSPHRASE || KEY_PASSPHRASE=""
  fi
  # Key files are never encrypted with an empty passphrase; an empty read
  # means the terminal went away (tab closed, Ctrl-D), so start nothing.
  if [ -z "$KEY_PASSPHRASE" ]; then
    echo "No passphrase entered; nothing started." >&2
    exit 1
  fi

  # `exec` here and cargo's own exec into the binary keep one PID from the
  # subshell to the daemon, so the PID file names the process that `stop`
  # must kill (it used to name a subshell, and the daemons outlived `stop`).
  echo "Starting signer-daemon..."
  printf '%s\n' "$KEY_PASSPHRASE" | (
    cd "$ROOT_DIR"
    exec cargo run --manifest-path services/signer-daemon/Cargo.toml -- \
      --socket "$SIGNER_SOCKET" \
      --key-file "$KEY_FILE" \
      ${ENCRYPTION_KEY_FILE:+--encryption-key-file "$ENCRYPTION_KEY_FILE"} \
      --aid "$AGENT_INBOX_AID" \
      --credential-id "$AGENT_INBOX_CREDENTIAL_ID" \
      --api-url "$API_URL"
  ) >"$SIGNER_LOG" 2>&1 &
  echo $! >"$SIGNER_PID_FILE"
  signer_pid="$(read_pid "$SIGNER_PID_FILE")"

  # Start the gateway only once the daemon is listening: with a wrong
  # passphrase the daemon exits, and a gateway without it would just retry.
  waited=0
  while [ ! -S "$SIGNER_SOCKET" ]; do
    if ! is_running "$signer_pid" || [ "$waited" -ge 120 ]; then
      echo "signer-daemon did not start. Last lines of $SIGNER_LOG:" >&2
      tail -n 3 "$SIGNER_LOG" >&2
      kill "$signer_pid" 2>/dev/null || true
      rm -f "$SIGNER_PID_FILE"
      exit 1
    fi
    sleep 1
    waited=$((waited + 1))
  done

  echo "Starting agent-gateway..."
  (
    cd "$ROOT_DIR"
    exec cargo run --manifest-path services/agent-gateway/Cargo.toml -- \
      --llm-socket "$GATEWAY_SOCKET" \
      --signer-socket "$SIGNER_SOCKET" \
      --api-url "$API_URL"
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
