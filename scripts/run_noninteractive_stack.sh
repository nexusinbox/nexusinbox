#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# `start|stop|status <dir>`: the directory `connect` (or `nexusinbox-signer
# --enroll --dir`) wrote. Its agent.env holds this agent's settings; only
# the keys below are read, as plain KEY=VALUE lines — nothing in it is run.
# PID files, logs and sockets then live in <dir>/run, next to the keys.
case "${1:-}" in
  start | stop | status) AGENT_DIR="${2:-}" ;;
  *) AGENT_DIR="" ;;
esac
if [ -n "$AGENT_DIR" ]; then
  if [ ! -f "$AGENT_DIR/agent.env" ]; then
    echo "No $AGENT_DIR/agent.env. Enroll first: nexusinbox-signer --enroll --credential-id <id> --dir $AGENT_DIR --api-url <api>" >&2
    exit 1
  fi
  while IFS='=' read -r key value; do
    case "$key" in
      AGENT_INBOX_API_URL|AGENT_INBOX_AID|AGENT_INBOX_CREDENTIAL_ID|AGENT_INBOX_KEY_FILE|AGENT_INBOX_ENCRYPTION_KEY_FILE|AGENT_INBOX_MODE_A_EXECUTOR|AGENT_INBOX_MODE_A_EXECUTOR_INTERVAL_SECS)
        export "$key=$value"
        ;;
    esac
  done <"$AGENT_DIR/agent.env"
  : "${AGENT_INBOX_RUNTIME_DIR:=$AGENT_DIR/run}"
  : "${AGENT_INBOX_SIGNER_SOCKET:=$AGENT_DIR/run/signer.sock}"
  : "${AGENT_INBOX_GATEWAY_SOCKET:=$AGENT_DIR/run/gateway.sock}"
  export AGENT_INBOX_RUNTIME_DIR AGENT_INBOX_SIGNER_SOCKET AGENT_INBOX_GATEWAY_SOCKET
fi

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
  $0 connect <code> [api_url]
      Connect this machine to an agent with the pairing code the web UI
      shows, then start it. Asks for a new passphrase for the agent's keys.
      api_url defaults to https://api.nexusinbox.ai.

  $0 start|stop|status <dir>
      <dir> is what \`connect\` (or \`nexusinbox-signer --enroll --dir <dir>\`) wrote.

  Or with the settings spelled out:
  AGENT_INBOX_AID=aid:ai:... \\
  AGENT_INBOX_CREDENTIAL_ID=<uuid> \\
  AGENT_INBOX_KEY_FILE=/path/to/signing.key.enc \\
  [AGENT_INBOX_ENCRYPTION_KEY_FILE=/path/to/encryption.key.enc] \\
  [AGENT_INBOX_MODE_A_EXECUTOR=on] \\
  $0 start

Enroll the daemon once first (docs/19 §3):
  cargo run --manifest-path services/signer-daemon/Cargo.toml -- --enroll ...

Commands:
  connect Pair with the web UI, then start
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

# Pair this machine with an agent (docs/31): the daemon looks the code up,
# writes the keys and agent.env to a new directory under ~/.nexusinbox and
# prints it; then the stack starts from there. The passphrase is asked for
# here, once with confirmation, and handed to both steps on a pipe.
connect() {
  code="${1:-}"
  api_url="${2:-https://api.nexusinbox.ai}"
  if [ -z "$code" ]; then
    usage
    exit 1
  fi
  if [ -t 0 ]; then
    echo "Choose a passphrase. It protects this agent's keys on this machine;" >&2
    echo "you will type it each time you start the agent." >&2
    trap 'stty echo; exit 130' INT TERM
    stty -echo
    printf 'Passphrase: ' >&2
    IFS= read -r NEW_PASSPHRASE || NEW_PASSPHRASE=""
    printf '\nOnce more: ' >&2
    IFS= read -r CONFIRM_PASSPHRASE || CONFIRM_PASSPHRASE=""
    stty echo
    trap - INT TERM
    printf '\n' >&2
  else
    IFS= read -r NEW_PASSPHRASE || NEW_PASSPHRASE=""
    IFS= read -r CONFIRM_PASSPHRASE || CONFIRM_PASSPHRASE=""
  fi
  if [ -z "$NEW_PASSPHRASE" ]; then
    echo "No passphrase entered; nothing changed." >&2
    exit 1
  fi
  if [ "$NEW_PASSPHRASE" != "$CONFIRM_PASSPHRASE" ]; then
    echo "The two passphrases differ; nothing changed. Run the command again." >&2
    exit 1
  fi

  echo "Connecting. The first time, building the programs takes a few minutes..." >&2
  agent_dir="$(printf '%s\n%s\n' "$NEW_PASSPHRASE" "$NEW_PASSPHRASE" | (
    cd "$ROOT_DIR"
    exec cargo run --manifest-path services/signer-daemon/Cargo.toml -- \
      --connect "$code" \
      --api-url "$api_url"
  ))" || exit 1

  if ! printf '%s\n' "$NEW_PASSPHRASE" | "$0" start "$agent_dir"; then
    echo "Connected, but the agent did not start. Fix the cause above, then run:" >&2
    echo "  $0 start $agent_dir" >&2
    exit 1
  fi
  echo ""
  echo "Connected. Next time, start this agent with:"
  echo "  $0 start $agent_dir"
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
  connect) connect "${2:-}" "${3:-}" ;;
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) usage; exit 1 ;;
esac
