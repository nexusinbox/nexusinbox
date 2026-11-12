#!/usr/bin/env sh
set -eu

# Two ways to run (docs/32): installed, as `nexusinbox` with the signer and
# gateway binaries beside it (a release, Homebrew); or from a checkout of the
# repository, building them with cargo.
SELF_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SELF_DIR/.." && pwd)"
if [ -x "$SELF_DIR/nexusinbox-signer" ] && [ -x "$SELF_DIR/nexusinbox-gateway" ]; then
  INSTALLED=1
  SELF_NAME="$(basename -- "$0")"
else
  INSTALLED=0
  SELF_NAME="$0"
fi

# Replace the current (sub)shell with the signer or the gateway.
exec_signer() {
  if [ "$INSTALLED" = 1 ]; then
    exec "$SELF_DIR/nexusinbox-signer" "$@"
  fi
  cd "$ROOT_DIR"
  exec cargo run --manifest-path services/signer-daemon/Cargo.toml -- "$@"
}
exec_gateway() {
  if [ "$INSTALLED" = 1 ]; then
    exec "$SELF_DIR/nexusinbox-gateway" "$@"
  fi
  cd "$ROOT_DIR"
  exec cargo run --manifest-path services/agent-gateway/Cargo.toml -- "$@"
}

# `start|stop|status <dir>`: the directory `connect` (or `nexusinbox-signer
# --enroll --dir`) wrote. Its agent.env holds this agent's settings; only
# the keys below are read, as plain KEY=VALUE lines — nothing in it is run.
# PID files, logs and sockets then live in <dir>/run, next to the keys.
# The directory may be left out when ~/.nexusinbox holds exactly one agent.
only_agent_dir() {
  found=""
  count=0
  for d in "$HOME"/.nexusinbox/*/; do
    [ -f "${d}agent.env" ] || continue
    found="${d%/}"
    count=$((count + 1))
  done
  if [ "$count" = 1 ]; then
    printf '%s\n' "$found"
    return 0
  fi
  if [ "$count" = 0 ]; then
    echo "No agent on this computer yet. Connect one first: $(basename -- "$0") connect <code>" >&2
  else
    echo "More than one agent on this computer; name its directory:" >&2
    for d in "$HOME"/.nexusinbox/*/; do
      [ -f "${d}agent.env" ] && echo "  ${d%/}" >&2
    done
  fi
  return 1
}
case "${1:-}" in
  start | stop | status | run) AGENT_DIR="${2:-}"; DIR_GIVEN="${2:+1}" ;;
  autostart) AGENT_DIR="${3:-}"; DIR_GIVEN="${3:+1}" ;;
  *) AGENT_DIR=""; DIR_GIVEN="" ;;
esac
case "${1:-}" in
  start | stop | status | run | autostart)
    # Settings spelled out in the environment (docs/19) need no directory.
    if [ -z "$DIR_GIVEN" ] && [ -z "${AGENT_INBOX_AID:-}" ]; then
      AGENT_DIR="$(only_agent_dir)" || exit 1
    fi
    ;;
esac
if [ -n "$AGENT_DIR" ]; then
  AGENT_DIR="$(CDPATH= cd -- "$AGENT_DIR" 2>/dev/null && pwd || printf '%s' "$AGENT_DIR")"
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
# Cloud AIs reach the agent through this relay, but only after the person
# turns cloud access on in the app (docs/33 §12); until then the gateway
# just asks. Needs the agent's directory for the certificate. "off" opts out.
MCP_RELAY="${AGENT_INBOX_MCP_RELAY:-relay.agent-inbox.ai}"
if [ -z "$AGENT_DIR" ] || [ "$MCP_RELAY" = off ]; then
  MCP_RELAY=""
fi
# Optional X25519 key for opening incoming messages. Required for the
# auto-reply executor (AGENT_INBOX_MODE_A_EXECUTOR=on, docs/19 §7).
ENCRYPTION_KEY_FILE="${AGENT_INBOX_ENCRYPTION_KEY_FILE:-}"

usage() {
  cat <<EOF
Usage:
  $SELF_NAME connect <code> [api_url]
      Connect this machine to an agent with the pairing code the web UI
      shows, then start it. Asks for a new passphrase for the agent's keys.
      api_url defaults to https://api.nexusinbox.ai.

  $SELF_NAME start|stop|status [<dir>]
      <dir> is what \`connect\` (or \`nexusinbox-signer --enroll --dir <dir>\`) wrote.
      It may be left out when ~/.nexusinbox holds a single agent.
      Started this way, the agent can also serve cloud AIs once that is
      turned on in the app (AGENT_INBOX_MCP_RELAY=off to opt out).

  Or with the settings spelled out:
  AGENT_INBOX_AID=aid:ai:... \\
  AGENT_INBOX_CREDENTIAL_ID=<uuid> \\
  AGENT_INBOX_KEY_FILE=/path/to/signing.key.enc \\
  [AGENT_INBOX_ENCRYPTION_KEY_FILE=/path/to/encryption.key.enc] \\
  [AGENT_INBOX_MODE_A_EXECUTOR=on] \\
  $SELF_NAME start

Or enroll the daemon by hand first (docs/19 §3.1):
  nexusinbox-signer --enroll ...

  $SELF_NAME autostart on|off [<dir>]      (macOS)
      Start the agent by itself when you log in: the passphrase is saved in
      the login keychain, readable only by nexusinbox-signer (docs/39).
      \`off\` stops that and deletes the saved passphrase.

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
  # Set up to start at login: start it the same way, no passphrase asked.
  if [ "${FROM_KEYCHAIN:-0}" != 1 ] && [ -n "$AGENT_DIR" ] && [ "$(uname)" = Darwin ] && autostart_is_on; then
    launchctl bootstrap "gui/$(id -u)" "$(launch_plist)" 2>/dev/null || launchctl kickstart "gui/$(id -u)/$(launch_label)"
    echo "Started (this agent starts at login; see: $SELF_NAME status $AGENT_DIR)"
    return 0
  fi
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

  # Started at login (`run`, docs/39): the daemon reads the passphrase from
  # the keychain itself, so nothing is asked here.
  if [ "${FROM_KEYCHAIN:-0}" = 1 ]; then
    KEY_PASSPHRASE=""
  # The daemon reads its key passphrase from stdin, which a background job
  # does not have. Read it here (no echo on a terminal, else one line from
  # stdin) and hand it over on a pipe; printf is a shell builtin, so the
  # passphrase never shows in a process list.
  elif [ -t 0 ]; then
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
  if [ "${FROM_KEYCHAIN:-0}" != 1 ] && [ -z "$KEY_PASSPHRASE" ]; then
    echo "No passphrase entered; nothing started." >&2
    exit 1
  fi

  # `exec` here and cargo's own exec into the binary keep one PID from the
  # subshell to the daemon, so the PID file names the process that `stop`
  # must kill (it used to name a subshell, and the daemons outlived `stop`).
  echo "Starting signer-daemon..."
  if [ "${FROM_KEYCHAIN:-0}" = 1 ]; then
    (
      exec_signer \
        --socket "$SIGNER_SOCKET" \
        --key-file "$KEY_FILE" \
        ${ENCRYPTION_KEY_FILE:+--encryption-key-file "$ENCRYPTION_KEY_FILE"} \
        --aid "$AGENT_INBOX_AID" \
        --credential-id "$AGENT_INBOX_CREDENTIAL_ID" \
        --api-url "$API_URL" \
        --passphrase-from-keychain "$AGENT_INBOX_CREDENTIAL_ID"
    ) </dev/null >"$SIGNER_LOG" 2>&1 &
  else
    printf '%s\n' "$KEY_PASSPHRASE" | (
      exec_signer \
        --socket "$SIGNER_SOCKET" \
        --key-file "$KEY_FILE" \
        ${ENCRYPTION_KEY_FILE:+--encryption-key-file "$ENCRYPTION_KEY_FILE"} \
        --aid "$AGENT_INBOX_AID" \
        --credential-id "$AGENT_INBOX_CREDENTIAL_ID" \
        --api-url "$API_URL"
    ) >"$SIGNER_LOG" 2>&1 &
  fi
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
    exec_gateway \
      --llm-socket "$GATEWAY_SOCKET" \
      --signer-socket "$SIGNER_SOCKET" \
      --api-url "$API_URL" \
      ${MCP_RELAY:+--mcp-relay "$MCP_RELAY" --mcp-acme-cache "$AGENT_DIR/acme"}
  ) >"$GATEWAY_LOG" 2>&1 &
  echo $! >"$GATEWAY_PID_FILE"

  if [ "${FROM_KEYCHAIN:-0}" = 1 ]; then
    supervise
  fi
  sleep 1
  "$0" status
}

# `run` (docs/39): stay in the foreground while both run, for launchd. When
# either stops, stop the other and exit non-zero so launchd starts them
# again (at most every 30 s); a TERM from launchd stops both and exits 0.
supervise() {
  signer_pid="$(read_pid "$SIGNER_PID_FILE")"
  gateway_pid="$(read_pid "$GATEWAY_PID_FILE")"
  trap 'kill "$gateway_pid" "$signer_pid" 2>/dev/null; rm -f "$SIGNER_PID_FILE" "$GATEWAY_PID_FILE"; exit 0' TERM INT
  while is_running "$signer_pid" && is_running "$gateway_pid"; do
    sleep 5
  done
  echo "$(date '+%F %T') a process stopped; see $SIGNER_LOG and $GATEWAY_LOG" >&2
  kill "$gateway_pid" "$signer_pid" 2>/dev/null || true
  rm -f "$SIGNER_PID_FILE" "$GATEWAY_PID_FILE"
  exit 1
}

# Start at login on macOS (docs/39): the key passphrase goes into the login
# keychain (only nexusinbox-signer may read it without macOS asking) and a
# LaunchAgent runs `run <dir>` at login.
launch_label() {
  printf 'ai.nexusinbox.%s' "$(basename -- "$AGENT_DIR" | tr -c 'A-Za-z0-9._-\n' '-')"
}
launch_plist() {
  printf '%s/Library/LaunchAgents/%s.plist' "$HOME" "$(launch_label)"
}
autostart_is_on() {
  [ -f "$(launch_plist)" ]
}
require_macos() {
  if [ "$(uname)" != Darwin ]; then
    echo "Starting at login is macOS only for now (docs/39)." >&2
    exit 1
  fi
}

autostart_on() {
  require_macos
  : "${AGENT_INBOX_CREDENTIAL_ID:?AGENT_INBOX_CREDENTIAL_ID is required}"
  [ -n "$AGENT_DIR" ] || { echo "autostart needs the agent's directory" >&2; exit 1; }
  echo "The passphrase will be saved in your macOS login keychain, so this agent" >&2
  echo "starts when you log in. Only nexusinbox-signer can read it without macOS" >&2
  echo "asking; after 'brew upgrade', macOS asks once whether to allow it." >&2
  # The signer asks (no echo) or reads one line from a pipe, checks the
  # passphrase opens the keys, and only then saves it.
  ( exec_signer \
      --key-file "$KEY_FILE" \
      ${ENCRYPTION_KEY_FILE:+--encryption-key-file "$ENCRYPTION_KEY_FILE"} \
      --keychain-store "$AGENT_INBOX_CREDENTIAL_ID" ) || exit 1

  # Hand over to launchd: stop a copy started by hand, then load the agent.
  "$0" stop "$AGENT_DIR" >/dev/null 2>&1 || true
  ensure_runtime_dir
  plist="$(launch_plist)"
  mkdir -p "$(dirname "$plist")"
  cat >"$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$(launch_label)</string>
  <key>ProgramArguments</key>
  <array>
    <string>$SELF_DIR/$(basename -- "$0")</string>
    <string>run</string>
    <string>$AGENT_DIR</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>$RUNTIME_DIR/launchd.log</string>
  <key>StandardErrorPath</key><string>$RUNTIME_DIR/launchd.log</string>
</dict>
</plist>
PLIST
  launchctl bootout "gui/$(id -u)/$(launch_label)" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$plist"
  echo "This agent now starts when you log in. To turn that off:"
  echo "  $SELF_NAME autostart off $AGENT_DIR"
}

autostart_off() {
  require_macos
  : "${AGENT_INBOX_CREDENTIAL_ID:?AGENT_INBOX_CREDENTIAL_ID is required}"
  launchctl bootout "gui/$(id -u)/$(launch_label)" 2>/dev/null || true
  rm -f "$(launch_plist)"
  ( exec_signer --keychain-delete "$AGENT_INBOX_CREDENTIAL_ID" ) || exit 1
  echo "This agent no longer starts at login, and its passphrase is no longer saved."
  echo "Start it by hand with:"
  echo "  $SELF_NAME start $AGENT_DIR"
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
    echo "you type it when you start the agent (on a Mac it can also start by" >&2
    echo "itself at login; you will be asked at the end)." >&2
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

  if [ "$INSTALLED" = 1 ]; then
    echo "Connecting..." >&2
  else
    echo "Connecting. The first time, building the programs takes a few minutes..." >&2
  fi
  agent_dir="$(printf '%s\n%s\n' "$NEW_PASSPHRASE" "$NEW_PASSPHRASE" | (
    exec_signer \
      --connect "$code" \
      --api-url "$api_url"
  ))" || exit 1

  if ! printf '%s\n' "$NEW_PASSPHRASE" | "$0" start "$agent_dir"; then
    echo "Connected, but the agent did not start. Fix the cause above, then run:" >&2
    echo "  $SELF_NAME start $agent_dir" >&2
    exit 1
  fi
  # docs/39: offer to start at login. No unless the person says yes.
  if [ -t 0 ] && [ "$(uname)" = Darwin ]; then
    echo "" >&2
    printf 'Start this agent by itself when you log in to this Mac? The passphrase is\nsaved in your login keychain (only nexusinbox-signer can read it). [y/N] ' >&2
    IFS= read -r answer || answer=""
    case "$answer" in
      y | Y | yes | YES)
        if printf '%s\n' "$NEW_PASSPHRASE" | "$0" autostart on "$agent_dir"; then
          return 0
        fi
        echo "Could not turn on starting at login; the agent keeps running for now." >&2
        ;;
    esac
  fi
  echo ""
  echo "Connected. Next time, start this agent with:"
  echo "  $SELF_NAME start $agent_dir"
}

stop() {
  # Started at login: unload it (until the next login or `start`).
  if [ -n "$AGENT_DIR" ] && [ "$(uname)" = Darwin ] && autostart_is_on; then
    launchctl bootout "gui/$(id -u)/$(launch_label)" 2>/dev/null || true
  fi
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
  if [ -n "$AGENT_DIR" ] && [ "$(uname)" = Darwin ]; then
    echo "At login:     $(autostart_is_on && echo "starts by itself (autostart on)" || echo "start by hand")"
  fi
}

cmd="${1:-}"
case "$cmd" in
  connect) connect "${2:-}" "${3:-}" ;;
  start) start ;;
  run) FROM_KEYCHAIN=1; start ;;
  autostart)
    case "${2:-}" in
      on) autostart_on ;;
      off) autostart_off ;;
      *) usage; exit 1 ;;
    esac
    ;;
  stop) stop ;;
  status) status ;;
  *) usage; exit 1 ;;
esac
