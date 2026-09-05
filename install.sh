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

fail() { echo "schain install: $*" >&2; exit 1; }

# Resolve latest once, then use only that release's URLs. No JSON parser needed.
release=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") || fail "could not resolve latest release"
prefix="https://github.com/$REPO/releases/tag/"
case "$release" in "$prefix"*) tag=${release#"$prefix"} ;; *) fail "invalid release URL" ;; esac
case "$tag" in v[0-9]*) ;; *) fail "invalid release tag" ;; esac
case "$tag" in *[!a-zA-Z0-9.-]*) fail "invalid release tag" ;; esac

asset="schain-$os-$arch"
base="https://github.com/$REPO/releases/download/$tag"
got=""
if curl -fsSL -o "$tmp/schain" "$base/$asset" 2>/dev/null; then
	curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || fail "could not download release checksums"
	expected=""
	while read -r digest name extra; do
		if [ "$name" = "$asset" ]; then
			[ -z "$expected" ] && [ -z "$extra" ] || fail "ambiguous checksum entry"
			[ "${#digest}" -eq 64 ] || fail "invalid checksum"
			case "$digest" in *[!0-9a-f]*) fail "invalid checksum" ;; esac
			expected=$digest
		fi
	done < "$tmp/checksums.txt"
	[ -n "$expected" ] || fail "missing checksum for $asset"
	if command -v sha256sum >/dev/null 2>&1; then
		actual=$(sha256sum "$tmp/schain") || fail "checksum calculation failed"
	elif command -v shasum >/dev/null 2>&1; then
		actual=$(shasum -a 256 "$tmp/schain") || fail "checksum calculation failed"
	else
		fail "checksum verification requires sha256sum or shasum"
	fi
	[ "${actual%% *}" = "$expected" ] || fail "checksum mismatch for $asset"
	echo "verified prebuilt $asset ($tag)"
	got=1
elif command -v go >/dev/null 2>&1; then
	echo "no prebuilt binary for $os/$arch; building from source..."
	curl -fsSL -o "$tmp/source.tar.gz" "https://github.com/$REPO/archive/refs/tags/$tag.tar.gz" || fail "could not download release source"
	mkdir "$tmp/source"
	tar -xzf "$tmp/source.tar.gz" -C "$tmp/source" --strip-components=1
	(cd "$tmp/source" && go build -trimpath -ldflags "-s -w -X main.version=${tag#v}" -o "$tmp/schain" .)
	got=1
fi
[ -n "$got" ] || {
	echo "schain install: no prebuilt binary for $os/$arch and no Go toolchain to build with (https://go.dev/dl)" >&2
	exit 1
}

BINDIR="${SCHAIN_INSTALL_DIR:-}"
if [ -z "$BINDIR" ]; then
	for d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do
		if [ -w "$d" ]; then BINDIR="$d"; break; fi
	done
fi
BINDIR="${BINDIR:-$HOME/.local/bin}"
mkdir -p "$BINDIR"
install -m 0755 "$tmp/schain" "$BINDIR/schain"

echo "installed $BINDIR/schain ($("$BINDIR/schain" --version 2>/dev/null || echo schain))"
case ":$PATH:" in
*:"$BINDIR":*) ;;
*) echo "note: $BINDIR is not on your PATH" >&2 ;;
esac
