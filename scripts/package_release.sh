#!/usr/bin/env sh
# Build the computer-side programs for one target and pack them as a
# release archive (docs/32): `nexusinbox` (scripts/run_noninteractive_stack.sh)
# with the signer and gateway binaries beside it, plus a SHA-256 file.
#
# Usage: scripts/package_release.sh <version> <rust-target>
#   e.g. scripts/package_release.sh 0.1.0 aarch64-apple-darwin
# Writes dist/nexusinbox-<version>-<target>.tar.gz and its .sha256.
set -eu

VERSION="${1:?version, e.g. 0.1.0}"
TARGET="${2:?rust target, e.g. aarch64-apple-darwin}"
case "$VERSION" in
  *[!0-9A-Za-z.-]* | "") echo "bad version: $VERSION" >&2; exit 2 ;;
esac
case "$TARGET" in
  *[!0-9A-Za-z_.-]* | "") echo "bad target: $TARGET" >&2; exit 2 ;;
esac

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
NAME="nexusinbox-$VERSION-$TARGET"
OUT="$ROOT_DIR/dist/$NAME"

for crate in signer-daemon agent-gateway; do
  cargo build --release --locked --target "$TARGET" \
    --manifest-path "$ROOT_DIR/services/$crate/Cargo.toml"
done

rm -rf "$OUT" "$OUT.tar.gz" "$OUT.tar.gz.sha256"
mkdir -p "$OUT"
install -m 0755 "$ROOT_DIR/scripts/run_noninteractive_stack.sh" "$OUT/nexusinbox"
install -m 0755 "$ROOT_DIR/services/signer-daemon/target/$TARGET/release/nexusinbox-signer" "$OUT/"
install -m 0755 "$ROOT_DIR/services/agent-gateway/target/$TARGET/release/nexusinbox-gateway" "$OUT/"
install -m 0644 "$ROOT_DIR/LICENSE" "$OUT/"
cat >"$OUT/README.txt" <<EOF
NexusInbox $VERSION ($TARGET)

Connect this computer to an agent with the pairing code the web app shows:
  nexusinbox connect <code>
Start, stop or check it later:
  nexusinbox start|stop|status <folder shown when it connected>

Keep nexusinbox, nexusinbox-signer and nexusinbox-gateway in the same folder.
https://github.com/nexusinbox/nexusinbox
EOF

(cd "$ROOT_DIR/dist" && tar -czf "$NAME.tar.gz" "$NAME")
(cd "$ROOT_DIR/dist" && if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$NAME.tar.gz"
else
  shasum -a 256 "$NAME.tar.gz"
fi >"$NAME.tar.gz.sha256")
echo "$ROOT_DIR/dist/$NAME.tar.gz"
