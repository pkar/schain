# schain

Encrypted per-directory environment variables. Each project keeps its secrets in an encrypted `.schain` file in its own directory. No shell hooks, no daemon, no dependencies. Go stdlib only. macOS and Linux.

## Install

One-liner (uses the prebuilt binary from the latest [release](https://github.com/pkar/schain/releases); needs Go only if none fits your platform):

```sh
curl -fsSL https://raw.githubusercontent.com/pkar/schain/main/install.sh | sh
```

Prebuilt targets: linux amd64/arm64, macOS arm64. Anything else builds from source.

Or with the Go toolchain directly:

```sh
go install github.com/pkar/schain@latest
```

Or from a clone:

```sh
make install
```

No sudo needed anywhere: the installer and `make install` pick the first user-writable of `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin` (created if missing); `go install` uses `$GOBIN` or `~/go/bin`. Force a location with `make install PREFIX=$HOME/.local` or `BINDIR=/some/bin`. Warns if the target dir is not on PATH.

## Usage

In your project directory, store secrets (values prompted with echo off). First `set` creates the vault and asks for a passphrase:

```sh
$ cd ~/work/infra
$ schain set AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
new passphrase for ~/work/infra:
repeat:
creating /Users/you/work/infra/.schain
AWS_ACCESS_KEY_ID:
AWS_SECRET_ACCESS_KEY:
saved 2 key(s)
```

`KEY=value` also works (`schain set AWS_REGION=us-east-1`) and mixes with prompted keys. Careful: inline values land in shell history, use the prompt form for real secrets.

Then run bare `schain` to get a subshell with the vars set:

```sh
$ schain
passphrase for ~/work/infra:
schain: entering shell with env from ~/work/infra (3 keys), exit to leave
$ aws s3 ls
$ exit          # secrets gone
```

Changing secrets from inside the subshell just works: after `schain set` or `schain unset`, the shell swaps itself for a fresh one with the updated vault (no nesting, one `exit` still leaves). A shell's environment is fixed at start, so schain defines a `schain` wrapper function inside its own subshells that runs `exec schain reload` after env-changing commands. Bare `schain` and `schain reload` inside a subshell also refresh. In shells other than bash/zsh/fish, refresh manually with `exec schain reload`.

Or wrap a single command:

```sh
$ schain exec terraform plan
```

The `.schain` vault is found in the current directory or any parent (like `.git`), so everything works from subdirectories too. It is encrypted; whether to commit it is your call (see below).

Other commands:

```sh
schain ls           # list key names (-v adds the vault each came from)
schain ls --local   # only the nearest vault's keys
schain unset KEY    # removes from the nearest vault
schain passwd       # change passphrase (rotates salt)
schain reload       # refresh a schain shell's env (automatic in bash/zsh/fish)
schain help
```

## Nested vaults

Every `.schain` from the current directory up to the root is merged, root-most first, nearest wins. A child vault holds only its overrides, so shared credentials live in one place and rotating them is one edit.

```
~/work/.schain              AWS_PROFILE=sso  NOMAD_TOKEN=prod-tok  DD_API_KEY=abc
~/work/proj/dev/.schain     NOMAD_TOKEN=dev-tok
```

In `~/work/proj/dev`: `AWS_PROFILE=sso` and `DD_API_KEY=abc` are inherited, `NOMAD_TOKEN=dev-tok` wins.

`set` writes to the nearest vault, which may be an ancestor; it says so on stderr. `--here` creates a vault in the current directory instead:

```sh
schain set --here NOMAD_TOKEN     # creates ./.schain even with a parent vault
```

Each vault keeps its own passphrase and salt. schain unlocks the chain bottom-up and reuses a passphrase that works, so vaults created with the same passphrase prompt once; `schain remember` caches the whole chain (`--local` for the nearest vault only), and so does `schain forget`.

Scope of the other commands: `unset` and `passwd` act on the nearest vault only; `ls`, `exec`, the subshell, and `reload` see the merged chain. `$SCHAIN_ACTIVE` holds the chain, `:`-separated, nearest last.

Stopping the walk:

- `SCHAIN_ROOT=1` stored in a vault (`schain set SCHAIN_ROOT=1`) makes it the top of the chain: nothing above it is read. The key itself is never exported.
- `SCHAIN_NO_INHERIT=1` in the environment turns inheritance off entirely, nearest vault only.

A child can override an inherited key but cannot remove one; an empty value means an empty value, not "unset". Unset it in the vault that defines it (`schain ls -v` names that vault).

Upgrading from 0.0.1: a nested vault used to hide its ancestors. Now they contribute keys, so variables you did not see before can appear. `SCHAIN_NO_INHERIT=1`, or `SCHAIN_ROOT=1` inside the vault, restores the old scope.

There is no delete command: a vault is just the file, so `rm .schain` (plus `schain forget` if you cached its key).

Running schain commands in the "wrong" place is caught: with no vault in reach it says so, adding where the current shell's env came from if you are inside a schain shell; and operating on a different project's vault than the one your shell came from prints a warning first.

## Skipping the passphrase prompt

Opt in per vault:

```sh
schain remember     # unlock once, cache the key in the OS
schain forget       # drop the cached key
```

`remember` covers every vault in the chain (`--local` restricts it to the nearest); `forget` drops them all (`--local` likewise). After `remember`, every schain command on that vault runs without prompting. The cache holds the derived key, never the passphrase, in:

- macOS: the login keychain, via the system `security` tool. Unlocked at login, lives until `forget`.
- Linux: the kernel keyring (`add_key(2)`). Never touches disk, gone on reboot.

`schain remember 30m` expires the cache after 30 minutes; durations take Go syntax (`30m`, `8h`, `1h30m`, `90s`), a bare number means minutes, and omitting it means no expiry. On Linux the kernel enforces the timeout. On macOS, which has no keychain TTL, schain embeds the expiry in the cached entry (an expired entry is never honored and is deleted on next use) and also spawns a detached sleeper that deletes the item on schedule; if the sleeper dies first (reboot), the embedded expiry still holds.

The cached key is bound to the vault's salt, so `schain passwd` invalidates any cached copy. Tradeoff: while a key is cached, anything running as your user can decrypt that vault. `forget` when that bothers you.

## Why no shell hook

A child process cannot modify its parent shell's environment. Tools that appear to do that install a hook into your shell rc. schain instead either `exec`s your command directly, or `exec`s a fresh shell with the secrets in its environment. Exit the shell and the secrets are gone.

The subshell is the same shell you invoked schain from (detected from the parent process, `$SHELL` as fallback) and starts as a login shell on macOS, matching terminal behavior, so your usual config loads. Its prompt is prefixed with `(schain ~/path/to/project) ` so it is obvious which shell holds which vault's secrets, wherever you cd. That works without touching your rc files: schain writes a throwaway init file that sources your normal startup files, prepends the marker, and deletes itself (bash, zsh, and fish; other shells get no marker). `$SCHAIN_ACTIVE` holds the vault path inside the subshell and guards against nesting.

## Security design

Built entirely on the Go standard library's crypto:

- Key derivation: PBKDF2-SHA256, 600,000 iterations (OWASP recommendation), 16-byte random salt per vault. PBKDF2 is not memory-hard (the stdlib has no scrypt or Argon2), so GPU-assisted guessing is cheaper than against memory-hard KDFs: pick a long passphrase.
- Encryption: AES-256-GCM with a fresh random 12-byte nonce per write. One shot per file, far below GCM nonce-collision bounds.
- Integrity: the header (magic, iteration count, salt) is bound as AEAD additional data, so KDF parameter tampering fails decryption. Any bit flip anywhere in the file is rejected.
- Files written 0600 via temp file + rename (no partial writes).
- `schain exec` and the subshell use `execve`, replacing the schain process. No parent process holds decrypted secrets.
- Iteration count below 100,000 in a vault file is refused (downgrade guard).
- Key material is zeroed after use, best effort (Go's GC can copy memory).

Committing `.schain` to git: it is ciphertext, so it only exposes what any encrypted blob exposes (size, and it invites offline passphrase guessing). With a strong passphrase that is fine; with a weak one, add it to `.gitignore`.

What it does not protect against: anything running as your user while secrets are in a live process environment (`/proc/<pid>/environ` on Linux is readable by the owner), swap without encryption, or a compromised machine.

## Tests

```sh
make test
```

Covers roundtrip, wrong passphrase, per-byte tamper rejection, rekey, truncation, cache payload parsing, file permissions, and chain composition (inherit, override, depth, prompt counts, caching, `set --here`, inherited `unset`, walk stops).

## License

MIT, see [LICENSE](LICENSE).
