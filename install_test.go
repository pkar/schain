package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every external download/build/install is intercepted; PATH excludes host tools
// except explicitly allowed basic utilities and the real checksum implementation.
func runInstaller(t *testing.T, mode, system, machine string) (string, string, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX installer")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sh", "mktemp", "rm", "tr", "mkdir", "tar", "gzip", "cp", "chmod"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	hash := "sha256sum"
	if system == "Darwin" {
		hash = "shasum"
	}
	p, err := exec.LookPath(hash)
	if err != nil && hash == "sha256sum" {
		hash = "shasum"
		p, err = exec.LookPath(hash)
	}
	if err != nil {
		t.Fatal(err)
	}
	if mode != "no-hash" {
		if err := os.Symlink(p, filepath.Join(bin, hash)); err != nil {
			t.Fatal(err)
		}
	}
	payload := "#!/bin/sh\necho fixture-version\n"
	write("payload", payload)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
	asset := "schain-linux-amd64"
	if system == "Darwin" {
		asset = "schain-darwin-arm64"
	}
	if mode == "mismatch" {
		digest = strings.Repeat("0", 64)
	}
	manifest := digest + "  " + asset + "\n"
	if mode == "missing-entry" {
		manifest = digest + "  unrelated\n"
	}
	if mode == "duplicate-entry" {
		manifest += manifest
	}
	write("checksums", manifest)
	write("bin/uname", "#!/bin/sh\ncase \"$1\" in -s) echo \"$SYSTEM\";; -m) echo \"$MACHINE\";; esac\n")
	write("bin/curl", `#!/bin/sh
printf '%s\n' "$*" >> "$ROOT/requests"
out=''
while [ "$#" -gt 0 ]; do
 case "$1" in -o) out=$2; shift 2;; -w) shift 2;; -*) shift;; *) url=$1; shift;; esac
done
case "$url" in
 */releases/latest)
  [ "$MODE" != resolve-failure ] || exit 22
  if [ "$MODE" = invalid-tag ]; then printf 'https://github.com/pkar/schain/releases/tag/main'; else printf 'https://github.com/pkar/schain/releases/tag/v1.2.3'; fi;;
 */checksums.txt)
  [ "$MODE" != missing-manifest ] || exit 22
  cp "$ROOT/checksums" "$out";;
 */archive/refs/tags/v1.2.3.tar.gz) cp "$ROOT/source.tar.gz" "$out";;
 */schain-*)
  [ "$MODE" != fallback ] || exit 22
  cp "$ROOT/payload" "$out";;
 *) exit 22;;
esac
`)
	write("bin/install", "#!/bin/sh\n[ \"$4\" = \"$SCHAIN_INSTALL_DIR/schain\" ] || exit 90\nprintf '%s\\n' \"$*\" >> \"$ROOT/installed\"\ncp \"$3\" \"$ROOT/result\"\n")
	write("bin/go", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$ROOT/built\"\nwhile [ \"$#\" -gt 0 ]; do if [ \"$1\" = -o ]; then cp \"$ROOT/payload\" \"$2\"; exit; fi; shift; done\nexit 1\n")
	if err := os.Mkdir(filepath.Join(root, "source"), 0755); err != nil {
		t.Fatal(err)
	}
	write("source/go.mod", "module fixture\n")
	tar := exec.Command("tar", "-czf", filepath.Join(root, "source.tar.gz"), "-C", root, "source")
	if out, err := tar.CombinedOutput(); err != nil {
		t.Fatalf("fixture tar: %s: %v", out, err)
	}
	cmd := exec.Command(filepath.Join(bin, "sh"), "install.sh")
	cmd.Env = []string{"PATH=" + bin, "HOME=" + root, "TMPDIR=" + root, "ROOT=" + root, "MODE=" + mode, "SYSTEM=" + system, "MACHINE=" + machine, "SCHAIN_INSTALL_DIR=" + filepath.Join(root, "dest")}
	out, runErr := cmd.CombinedOutput()
	requests, _ := os.ReadFile(filepath.Join(root, "requests"))
	_, installedErr := os.Stat(filepath.Join(root, "installed"))
	if runErr != nil && installedErr == nil {
		t.Fatalf("installed despite failure: %s", out)
	}
	if runErr == nil && installedErr != nil {
		t.Fatalf("success without installation: %s", out)
	}
	if runErr == nil {
		result, err := os.ReadFile(filepath.Join(root, "result"))
		if err != nil || string(result) != payload {
			t.Fatalf("installed unexpected bytes: %q: %v", result, err)
		}
	}
	built, _ := os.ReadFile(filepath.Join(root, "built"))
	return string(out), string(requests) + string(built), runErr
}

func TestInstallerReleaseVerification(t *testing.T) {
	for _, tc := range []struct {
		mode, system, machine string
		success               bool
	}{
		{"ok", "Linux", "x86_64", true}, {"ok", "Darwin", "arm64", true},
		{"missing-entry", "Linux", "x86_64", false}, {"missing-manifest", "Linux", "x86_64", false},
		{"duplicate-entry", "Linux", "x86_64", false}, {"invalid-tag", "Linux", "x86_64", false},
		{"resolve-failure", "Linux", "x86_64", false}, {"no-hash", "Linux", "x86_64", false},
	} {
		t.Run(tc.mode+tc.system, func(t *testing.T) {
			out, requests, err := runInstaller(t, tc.mode, tc.system, tc.machine)
			if (err == nil) != tc.success {
				t.Fatalf("success=%v: %v: %s\n%s", tc.success, err, out, requests)
			}
			if strings.Count(requests, "https://github.com/pkar/schain/releases/latest\n") != 1 {
				t.Fatalf("latest not resolved exactly once: %s", requests)
			}
			if strings.Contains(requests, "latest/download") || strings.Contains(requests, "refs/heads") {
				t.Fatalf("mutable download: %s", requests)
			}
			if !tc.success && strings.Contains(requests, "archive/") {
				t.Fatalf("verification failure fell back to source: %s", requests)
			}
			if tc.success && !strings.Contains(requests, "releases/download/v1.2.3/checksums.txt") {
				t.Fatalf("missing pinned checksums: %s", requests)
			}
		})
	}
}

func TestInstallerPinnedSourceFallback(t *testing.T) {
	out, requests, err := runInstaller(t, "fallback", "Linux", "riscv64")
	if err != nil {
		t.Fatalf("fallback failed: %v: %s\n%s", err, out, requests)
	}
	if !strings.Contains(requests, "archive/refs/tags/v1.2.3.tar.gz") || strings.Contains(requests, "main.tar.gz") {
		t.Fatalf("source not pinned: %s", requests)
	}
	if !strings.Contains(requests, "-X main.version=1.2.3") {
		t.Fatalf("missing version: %s", requests)
	}
}

func TestInstallerRejectsChecksumMismatch(t *testing.T) {
	out, requests, err := runInstaller(t, "mismatch", "Linux", "x86_64")
	if err == nil {
		t.Fatalf("accepted corrupt prebuilt: %s\n%s", out, requests)
	}
	if !strings.Contains(out, "checksum") {
		t.Fatalf("wrong failure: %s", out)
	}
}
