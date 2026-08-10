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
$ schain set API_TOKEN DB_PASSWORD
new passphrase for ~/work/infra:
repeat:
creating /Users/you/work/infra/.schain
API_TOKEN:
DB_PASSWORD:
saved 2 key(s)
```

`KEY=value` also works (`schain set DEPLOY_ENV=staging`) and mixes with prompted keys. Careful: inline values land in shell history, use the prompt form for real secrets.

Then run bare `schain` to get a subshell with the vars set:

```sh
$ schain
passphrase for ~/work/infra:
schain: entering shell with env from ~/work/infra (3 keys), exit to leave
$ ./deploy.sh
$ exit          # secrets gone
```

Changing secrets from inside the subshell just works: after `schain set` or `schain unset`, the shell swaps itself for a fresh one with the updated vault (no nesting, one `exit` still leaves). A shell's environment is fixed at start, so schain defines a `schain` wrapper function inside its own subshells that runs `exec schain reload` after env-changing commands. Bare `schain` and `schain reload` inside a subshell also refresh. In shells other than bash/zsh/fish, refresh manually with `exec schain reload`.

Or wrap a single command:

```sh
$ schain exec make migrate
```

The `.schain` vault is found in the current directory or any parent (like `.git`), so everything works from subdirectories too. It is encrypted; whether to commit it is your call (see below).

Other commands:

```sh
schain ls           # list key names
schain ls --local   # only the nearest vault's keys
schain unset KEY    # removes from the nearest vault
schain passwd       # change passphrase (rotates salt)
schain reload       # refresh a schain shell's env (automatic in bash/zsh/fish)
schain worktree     # which vaults a git worktree uses, and from where
schain history      # what changed in this vault, and when
schain help
```

## Nested vaults

Every `.schain` from the current directory up to the root is merged, root-most first, nearest wins. A child vault holds only its overrides, so shared credentials live in one place and rotating them is one edit.

```
~/work/.schain              DB_PASSWORD=hunter2  API_TOKEN=prod-tok  SIGNING_KEY=abc
~/work/proj/dev/.schain     API_TOKEN=dev-tok
```

In `~/work/proj/dev`: `DB_PASSWORD=hunter2` and `SIGNING_KEY=abc` are inherited, `API_TOKEN=dev-tok` wins.

With more than one vault in the chain, `schain ls` on a terminal tags each key with the vault it comes from, since that is what you need before rotating one:

```sh
$ schain ls
API_TOKEN     ~/work/proj/dev
DB_PASSWORD   ~/work
SIGNING_KEY   ~/work
```

Piped or redirected output stays bare key names, so `schain ls | ...` keeps working. `-v` forces the tags on, `--plain` forces them off, `--local` lists the nearest vault alone.

`set` writes to the nearest vault, which may be an ancestor; it says so on stderr. `--here` creates a vault in the current directory instead:

```sh
schain set --here API_TOKEN     # creates ./.schain even with a parent vault
```

Each vault keeps its own passphrase and salt. schain unlocks the chain bottom-up and reuses a passphrase that works, so vaults created with the same passphrase prompt once; `schain remember` caches the whole chain (`--local` for the nearest vault only, `--all` for every vault below this directory too), and so does `schain forget`.

Scope of the other commands: `unset` and `passwd` act on the nearest vault only; `ls`, `exec`, the subshell, and `reload` see the merged chain. `$SCHAIN_ACTIVE` holds the chain, `:`-separated, nearest last.

Stopping the walk:

- `SCHAIN_ROOT=1` stored in a vault (`schain set SCHAIN_ROOT=1`) makes it the top of the chain: nothing above it is read. The key itself is never exported.
- `SCHAIN_NO_INHERIT=1` in the environment turns inheritance off entirely, nearest vault only.

A child can override an inherited key but cannot remove one; an empty value means an empty value, not "unset". Unset it in the vault that defines it (`schain ls -v` names that vault).

## History

Every `set` and `unset` keeps the value it replaced, three per key, inside the vault. A rotation that breaks something is one command to undo:

```sh
$ schain history
KEY          KEPT  LAST CHANGE          BY
API_TOKEN    3     2026-08-09 17:10:38  you@laptop
DB_PASSWORD  1     2026-08-09 17:10:35  you@laptop

$ schain history API_TOKEN
current  since 2026-08-09 17:10:38  you@laptop
1 back   until 2026-08-09 17:10:38  you@laptop
2 back   until 2026-08-09 17:10:37  you@laptop
3 back   until 2026-08-09 17:10:35  you@laptop  absent: reverting removes the key

$ schain history revert API_TOKEN      # or: revert API_TOKEN 2
schain: API_TOKEN restored to the value from 2026-08-09 17:10:38
schain: undo with: schain history revert API_TOKEN
```

**Old values are never printed.** `history` shows what changed and when, never a value; `revert` puts one back without displaying it. That keeps the property that no schain command writes a secret to your terminal.

Reverting is an ordinary change, so it is kept too and can be reverted in turn. That also means the step count shifts after a revert: read `schain history KEY` again before stepping back further. Creating a key is recorded as well, so `revert` on a freshly added key removes it, and a key you `unset` by mistake comes back.

```sh
schain history off             # stop recording in this vault
schain history on [N]          # record again, keeping N (default 3)
schain history purge [KEY...]  # drop what is stored
```

Two things worth knowing before you rely on it:

- **History weakens deletion.** After `unset`, the old value is still in the file until it ages out or you `purge`. If you put a real secret somewhere by mistake, `schain unset KEY` then `schain history purge KEY`. (If you commit your vault, git already keeps every old ciphertext, so this changes nothing there.)
- **A vault holding history is written in a newer on-disk format** (`schain2`), which schain older than 0.0.6 reports as "not a schain vault". A vault switched off with `history off` and purged goes back to the original format, so it stays readable by older builds. Nothing else about the format changed: same crypto, same header, same per-vault salt.

History belongs to one vault file, so these commands act on the nearest vault, never the merged chain.

## Git worktrees

A linked worktree is a second checkout at another path. Vault files are untracked, so a fresh worktree has none of the repo's per-directory vaults, and every key that a child vault existed to override would quietly resolve to whatever an ancestor holds. schain closes that gap at lookup time: inside a linked worktree, a directory with no vault of its own uses the **main checkout's** vault at the same repo-relative path.

```sh
$ cd ~/work/repo/.claude/worktrees/feature/prod
$ schain ls -v
API_TOKEN    ~/work/repo/prod (main checkout)
DB_PASSWORD  ~/work
```

Nothing is copied, so there is nothing to re-sync after rotating a key and nothing to prune after deleting a vault. The main checkout's file is used at its own path, which also means `schain remember` run there covers every worktree, with no second prompt.

```sh
schain worktree     # which vaults this worktree uses, and from where (alias: wt)
```

The rest of the rules:

- **A vault in the worktree wins.** `schain set --here KEY` creates one, for a worktree that should deliberately differ.
- **Writes go to the main checkout.** `set`, `unset`, and `passwd` acting on a borrowed vault change that one file, so a rotation from a worktree is visible everywhere at once. schain names the file on stderr when it does this.
- **A worktree outside the vault root gets a warning**, naming the vaults the main checkout composes with that this worktree cannot reach.
- Detection reads git's own files (`.git` → `commondir`), so no `git` binary is needed. Submodules use the same `.git` indirection but have no `commondir`, so they never borrow. `SCHAIN_NO_WORKTREE=1` turns the whole thing off.

Upgrading from 0.0.1: a nested vault used to hide its ancestors. Now they contribute keys, so variables you did not see before can appear. `SCHAIN_NO_INHERIT=1`, or `SCHAIN_ROOT=1` inside the vault, restores the old scope.

There is no delete command: a vault is just the file, so `rm .schain` (plus `schain forget` if you cached its key). That also takes its history with it.

Running schain commands in the "wrong" place is caught: with no vault in reach it says so, adding where the current shell's env came from if you are inside a schain shell; and operating on a different project's vault than the one your shell came from prints a warning first.

## Skipping the passphrase prompt

Opt in per vault:

```sh
schain remember           # unlock once, cache the key in the OS
schain remember --all     # same for every vault above and below here
schain forget             # drop the cached key
schain forget --all       # drop them for the same set
```

`remember` covers every vault in the chain (`--local` restricts it to the nearest); `forget` drops them all (`--local` likewise). After `remember`, every schain command on that vault runs without prompting.

`--all` adds a walk downward: every `.schain` under the current directory, plus the chain above it. Run it once at the top of a monorepo and every project underneath is prompt-free. A passphrase that opens one vault is tried on the rest before asking again, so a tree sharing one passphrase costs one prompt and a tree with three costs three. Vaults that will not open (wrong passphrase, unreadable, not a vault) are named on stderr and skipped, so one bad file does not abandon the run. The walk does not follow symlinks and does not descend into `.git`. The cache holds the derived key, never the passphrase, in:

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
- Replaced values are kept in the vault (see [History](#history)), so a value survives `unset` until it ages out or you `purge`. Everything stays inside the same encrypted file.

Committing `.schain` to git: it is ciphertext, so it only exposes what any encrypted blob exposes (size, and it invites offline passphrase guessing). With a strong passphrase that is fine; with a weak one, add it to `.gitignore`.

What it does not protect against: anything running as your user while secrets are in a live process environment (`/proc/<pid>/environ` on Linux is readable by the owner), swap without encryption, or a compromised machine.

## Tests

```sh
make test
```

Covers roundtrip, wrong passphrase, per-byte tamper rejection, rekey, truncation, cache payload parsing, file permissions, chain composition (inherit, override, depth, prompt counts, caching, `set --here`, inherited `unset`, walk stops), bulk `--all` (recursive discovery, passphrase reuse, skipping vaults that will not open), and git worktrees (borrowing, local override, writes reaching the main checkout, submodules excluded, unreachable-ancestor warning, plus one test against a real `git worktree add`), and history (format round trip, cap and ordering, creation and deletion, revert including to-absent and undo-the-undo, off/purge returning the file to the old format, and that no value reaches stdout).

## License

MIT, see [LICENSE](LICENSE).
