#!/bin/sh
# schain installer: downloads source from GitHub, builds, installs.
# Needs: curl, tar, go. No sudo.
#   curl -fsSL https://raw.githubusercontent.com/pkar/schain/main/install.sh | sh
set -eu

REPO="pkar/schain"

command -v go >/dev/null 2>&1 || {
	echo "schain install: Go is required (https://go.dev/dl)" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "downloading $REPO..."
curl -fsSL "https://github.com/$REPO/archive/refs/heads/main.tar.gz" | tar -xz -C "$tmp"

echo "building..."
cd "$tmp/schain-main"
go build -trimpath -ldflags '-s -w' -o schain .

BINDIR=""
for d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do
	if [ -w "$d" ]; then BINDIR="$d"; break; fi
done
BINDIR="${BINDIR:-$HOME/.local/bin}"
mkdir -p "$BINDIR"
install -m 0755 schain "$BINDIR/schain"

echo "installed $BINDIR/schain"
case ":$PATH:" in
*:"$BINDIR":*) ;;
*) echo "note: $BINDIR is not on your PATH" >&2 ;;
esac
