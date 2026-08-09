#!/bin/sh
# schain installer: grabs the prebuilt binary from the latest GitHub
# release, or builds from source if no binary fits (then Go is needed).
# Needs curl. No sudo.
#   curl -fsSL https://raw.githubusercontent.com/pkar/schain/main/install.sh | sh
set -eu

REPO="pkar/schain"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
x86_64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
esac

got=""
url="https://github.com/$REPO/releases/latest/download/schain-$os-$arch"
if curl -fsSL -o "$tmp/schain" "$url" 2>/dev/null; then
	echo "downloaded prebuilt schain-$os-$arch"
	got=1
elif command -v go >/dev/null 2>&1; then
	echo "no prebuilt binary for $os/$arch; building from source..."
	curl -fsSL "https://github.com/$REPO/archive/refs/heads/main.tar.gz" | tar -xz -C "$tmp"
	(cd "$tmp/schain-main" && go build -trimpath -ldflags '-s -w' -o "$tmp/schain" .)
	got=1
fi
[ -n "$got" ] || {
	echo "schain install: no prebuilt binary for $os/$arch and no Go toolchain to build with (https://go.dev/dl)" >&2
	exit 1
}

BINDIR=""
for d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do
	if [ -w "$d" ]; then BINDIR="$d"; break; fi
done
BINDIR="${BINDIR:-$HOME/.local/bin}"
mkdir -p "$BINDIR"
install -m 0755 "$tmp/schain" "$BINDIR/schain"

echo "installed $BINDIR/schain ($("$BINDIR/schain" --version 2>/dev/null || echo schain))"
case ":$PATH:" in
*:"$BINDIR":*) ;;
*) echo "note: $BINDIR is not on your PATH" >&2 ;;
esac
