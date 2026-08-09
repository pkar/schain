package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

const vaultName = ".schain"

// version is stamped by the release build via -ldflags.
var version = "dev"

const usageText = `schain - encrypted per-directory environment variables

The encrypted vault is a ` + vaultName + ` file in your project directory.
Every ` + vaultName + ` from the current directory up to the root is merged,
nearest wins, so a child vault holds only its overrides.

usage:
  schain                   spawn subshell with the chain's env
  schain exec <cmd> ...    run one command with the chain's env
  schain set KEY...        store secrets (values prompted, hidden)
  schain set KEY=value     store secret inline (lands in shell history!)
  schain set --here KEY    store in a vault in this directory, creating
                           it even when a parent vault exists
  schain unset KEY...      remove keys from the nearest vault
  schain ls [--local] [-v] list key names; on a terminal each key is
                           tagged with the vault it comes from (-v forces
                           that, --plain never, --local nearest only)
  schain passwd            change the nearest vault's passphrase
  schain remember [dur]    cache keys for the chain in an OS store; skip
                           passphrase prompts (--local: nearest vault)
                           (macOS: login keychain; linux: kernel keyring)
                           dur: 30m, 8h, 1h30m; bare number = minutes;
                           omitted = no expiry
  schain forget            drop cached keys (--local: nearest vault)
  schain reload            refresh a schain shell's env (automatic after
                           set/unset in bash/zsh/fish; elsewhere run as:
                           exec schain reload)

first "schain set" creates ` + vaultName + ` in the current directory.
` + rootKey + ` set in a vault stops the walk there; SCHAIN_NO_INHERIT=1
disables inheritance entirely.
inside a schain subshell, $SCHAIN_ACTIVE holds the chain, nearest last.`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "schain:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return cmdSubshell()
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Println(usageText)
		return nil
	case "-v", "--version", "version":
		fmt.Println("schain " + version)
		return nil
	case "exec":
		if len(args) < 2 {
			return fmt.Errorf("usage: schain exec <cmd> [args...]")
		}
		return cmdExec(args[1:])
	case "set":
		return cmdSet(args[1:])
	case "unset":
		return cmdUnset(args[1:])
	case "ls", "list":
		return cmdLs(args[1:])
	case "passwd":
		return cmdPasswd()
	case "remember":
		return cmdRemember(args[1:])
	case "forget":
		return cmdForget(args[1:])
	case "reload":
		return cmdReload()
	default:
		return fmt.Errorf("unknown command %q (see schain --help)", args[0])
	}
}

// mustFindVault resolves the nearest vault, for commands that write to
// exactly one vault (set, unset, passwd).
func mustFindVault() (string, error) {
	path, err := findVault()
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", noVaultErr()
	}
	warnForeign(path)
	return path, nil
}

func noVaultErr() error {
	if active := activeChain(); len(active) > 0 {
		return fmt.Errorf("no %s here or in any parent\n(this shell's env came from %s; cd there to manage it)",
			vaultName, display(active[len(active)-1]))
	}
	return fmt.Errorf("no %s here or in any parent (create with: schain set KEY)", vaultName)
}

// warnForeign notes when the vault in reach is not part of the chain this
// shell's env came from.
func warnForeign(path string) {
	active := activeChain()
	if len(active) == 0 {
		return
	}
	for _, p := range active {
		if p == path {
			return
		}
	}
	fmt.Fprintf(os.Stderr, "schain: warning: operating on %s, but this shell's env came from %s\n",
		display(path), display(active[len(active)-1]))
}

// display shortens a path for prompts: /Users/x/work/app/.schain -> ~/work/app
func display(path string) string {
	dir := filepath.Dir(path)
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(home, dir); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.Join("~", rel)
		}
	}
	return dir
}

// unlock opens one vault, trying the OS key cache before prompting.
func unlock(path string) (*vault, error) {
	if v := openCached(path); v != nil {
		return v, nil
	}
	pass, err := promptSecret(fmt.Sprintf("passphrase for %s: ", display(path)))
	if err != nil {
		return nil, err
	}
	defer wipe(pass)
	return openVault(path, pass)
}

func newPassphrase(path string) ([]byte, error) {
	p1, err := promptSecret(fmt.Sprintf("new passphrase for %s: ", display(path)))
	if err != nil {
		return nil, err
	}
	if len(p1) == 0 {
		return nil, fmt.Errorf("empty passphrase not allowed")
	}
	p2, err := promptSecret("repeat: ")
	if err != nil {
		return nil, err
	}
	defer wipe(p2)
	if !bytes.Equal(p1, p2) {
		wipe(p1)
		return nil, fmt.Errorf("passphrases do not match")
	}
	return p1, nil
}

func cmdSet(args []string) error {
	here := false
	if len(args) > 0 && (args[0] == "--here" || args[0] == "--local") {
		here, args = true, args[1:]
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: schain set [--here] KEY... | KEY=value...")
	}
	// Vet every key before unlocking anything, so a typo cannot come to
	// light halfway through a run of prompts.
	for _, arg := range args {
		k, _, _ := strings.Cut(arg, "=")
		if k == "" || strings.ContainsAny(k, "\x00") {
			return fmt.Errorf("invalid key %q", arg)
		}
		if strings.HasPrefix(k, "-") {
			return fmt.Errorf("invalid key %q (flags must come before keys)", k)
		}
	}
	path, err := findVault()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	local := filepath.Join(cwd, vaultName)
	if here && path != local {
		path = "" // ignore ancestors, create one here
	}
	var v *vault
	if path == "" {
		path = local
		pass, err := newPassphrase(path)
		if err != nil {
			return err
		}
		v, err = newVault(pass)
		wipe(pass)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "creating %s\n", path)
		// A running schain shell keeps the chain it started with.
		if len(activeChain()) > 0 {
			fmt.Fprintf(os.Stderr, "schain: this shell's env predates %s; exit and re-enter to pick it up\n", path)
		}
	} else {
		// Writing to an ancestor changes a broader scope than the
		// directory the user is standing in; say so.
		if filepath.Dir(path) != cwd {
			fmt.Fprintf(os.Stderr, "schain: writing to %s (no vault here; use --here to create one)\n", path)
		}
		v, err = unlock(path)
		if err != nil {
			return err
		}
	}
	defer v.close()
	for _, arg := range args {
		k, inline, hasInline := strings.Cut(arg, "=")
		if hasInline {
			v.Secrets[k] = inline
			continue
		}
		val, err := promptSecret(k + ": ")
		if err != nil {
			return err
		}
		v.Secrets[k] = string(val)
		wipe(val)
	}
	if err := v.save(path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "saved %d key(s)\n", len(args))
	return nil
}

func cmdUnset(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: schain unset KEY...")
	}
	path, err := mustFindVault()
	if err != nil {
		return err
	}
	v, err := unlock(path)
	if err != nil {
		return err
	}
	defer v.close()
	for _, k := range args {
		if _, ok := v.Secrets[k]; !ok {
			if owner := inheritedFrom(k); owner != "" {
				return fmt.Errorf("%q is inherited from %s; unset it there", k, owner)
			}
			if paths, _ := findVaults(); len(paths) > 1 {
				return fmt.Errorf("no key %q in %s\n(inherited keys must be unset in the vault that defines them; see: schain ls -v)", k, path)
			}
			return fmt.Errorf("no key %q", k)
		}
		delete(v.Secrets, k)
	}
	return v.save(path)
}

func cmdLs(args []string) error {
	local, verbose, plain := false, false, false
	for _, a := range args {
		switch a {
		case "--local":
			local = true
		case "-v", "--verbose":
			verbose = true
		case "--plain":
			plain = true
		default:
			return fmt.Errorf("usage: schain ls [--local] [-v] [--plain]")
		}
	}
	if local {
		path, err := mustFindVault()
		if err != nil {
			return err
		}
		v, err := unlock(path)
		if err != nil {
			return err
		}
		defer v.close()
		src := func(string) string { return path }
		return printKeys(v.keys(), src, verbose, plain)
	}
	c, err := openChain()
	if err != nil {
		return err
	}
	defer c.close()
	secrets := c.secrets()
	defer wipeMap(secrets)
	// With more than one vault in play, which vault owns a key is the
	// thing you need before rotating it: show it unless the output is
	// being piped somewhere that expects bare key names.
	if len(c.vaults) > 1 && !plain {
		verbose = verbose || isTerminal(os.Stdout)
	}
	return printKeys(sortedKeys(secrets), c.sourceOf, verbose, plain)
}

func printKeys(keys []string, source func(string) string, verbose, plain bool) error {
	if plain || !verbose {
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%s\n", k, display(source(k)))
	}
	return w.Flush()
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func cmdPasswd() error {
	path, err := mustFindVault()
	if err != nil {
		return err
	}
	v, err := unlock(path)
	if err != nil {
		return err
	}
	defer v.close()
	pass, err := newPassphrase(path)
	if err != nil {
		return err
	}
	defer wipe(pass)
	if err := v.rekey(pass); err != nil {
		return err
	}
	cacheForget(path) // stale after rekey; best effort
	return v.save(path)
}

func cmdRemember(args []string) error {
	local := false
	if len(args) > 0 && args[0] == "--local" {
		local, args = true, args[1:]
	}
	if len(args) > 1 {
		return fmt.Errorf("usage: schain remember [--local] [duration]")
	}
	ttl := 0
	if len(args) == 1 {
		d, err := parseTTL(args[0])
		if err != nil {
			return err
		}
		ttl = d
	}
	if local {
		path, err := mustFindVault()
		if err != nil {
			return err
		}
		v, err := unlock(path)
		if err != nil {
			return err
		}
		defer v.close()
		return rememberVault(path, v, ttl)
	}
	c, err := openChain()
	if err != nil {
		return err
	}
	defer c.close()
	for i, v := range c.vaults {
		if err := rememberVault(c.paths[i], v, ttl); err != nil {
			return err
		}
	}
	return nil
}

func rememberVault(path string, v *vault, ttl int) error {
	payload := cachePayload(v.salt, v.key)
	defer wipe(payload)
	if err := cacheStore(path, payload, ttl); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "schain: key for %s cached; no passphrase until forget\n", display(path))
	return nil
}

// parseTTL accepts Go durations ("30m", "8h", "1h30m", "90s"); a bare
// number means minutes.
func parseTTL(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return n * 60, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < time.Second {
		return 0, fmt.Errorf("bad duration %q (use 30m, 8h, 1h30m, or minutes as a bare number)", s)
	}
	return int(d / time.Second), nil
}

func cmdForget(args []string) error {
	local := false
	if len(args) > 0 && args[0] == "--local" {
		local, args = true, args[1:]
	}
	if len(args) > 0 {
		return fmt.Errorf("usage: schain forget [--local]")
	}
	paths, err := findVaults()
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return noVaultErr()
	}
	warnForeign(paths[0])
	if local {
		paths = paths[:1]
	}
	n := 0
	for _, p := range paths {
		if cacheForget(p) != nil {
			continue
		}
		n++
		fmt.Fprintf(os.Stderr, "schain: forgot cached key for %s\n", display(p))
	}
	if n == 0 {
		return fmt.Errorf("nothing cached for %s", display(paths[0]))
	}
	return nil
}

// secretEnviron builds the child environment: current env minus any keys
// being (re)set, plus the merged secrets and schain markers. Stripping
// first matters on reload: getenv returns the first match, so a stale
// duplicate would shadow the fresh value. SCHAIN_ACTIVE holds the whole
// chain, nearest last.
func secretEnviron(secrets map[string]string, paths []string, shell string) []string {
	skip := map[string]bool{"SCHAIN_ACTIVE": true, "SCHAIN_SHELL": true}
	for k := range secrets {
		skip[k] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if !skip[k] {
			env = append(env, kv)
		}
	}
	for k, val := range secrets {
		env = append(env, k+"="+val)
	}
	env = append(env, "SCHAIN_ACTIVE="+strings.Join(paths, string(os.PathListSeparator)))
	if shell != "" {
		env = append(env, "SCHAIN_SHELL="+shell)
	}
	return env
}

// chainLabel describes where the env came from, e.g. "~/work/app +1 inherited".
func chainLabel(c *chain) string {
	_, near := c.nearest()
	label := display(near)
	if n := len(c.vaults) - 1; n > 0 {
		label += fmt.Sprintf(" +%d inherited", n)
	}
	return label
}

func enterShell(c *chain) error {
	// Prefer the shell recorded at first entry: on `exec schain reload`
	// the parent process is the terminal, not the shell, so parent
	// detection would misfire.
	shell := os.Getenv("SCHAIN_SHELL")
	if shell == "" {
		shell = currentShell()
	}
	_, near := c.nearest()
	setMarker(display(near))
	secrets := c.secrets()
	argv, env := subshellLaunch(shell, secretEnviron(secrets, c.paths, shell))
	fmt.Fprintf(os.Stderr, "schain: entering shell with env from %s (%d keys), exit to leave\n",
		chainLabel(c), len(secrets))
	wipeMap(secrets)
	c.close()
	return execReplace(shell, argv, env)
}

func cmdSubshell() error {
	if active := activeChain(); len(active) > 0 {
		return fmt.Errorf("already inside a schain shell for %s\n(exit first, or refresh env with: exec schain reload)", display(active[len(active)-1]))
	}
	c, err := openChain()
	if err != nil {
		return err
	}
	return enterShell(c)
}

// cmdReload re-enters the subshell for the vault this shell came from,
// picking up changes made since. Run as `exec schain reload` so the new
// shell replaces the current one instead of nesting inside it.
func cmdReload() error {
	active := activeChain() // root-most first
	if len(active) == 0 {
		return fmt.Errorf("not inside a schain shell (enter one with: schain)")
	}
	for _, p := range active {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("vault %s no longer exists", display(p))
		}
	}
	c, err := loadChain(reversed(active))
	if err != nil {
		return err
	}
	return enterShell(c)
}

// currentShell returns the shell schain was invoked from (its parent
// process), so the subshell matches what the user is actually typing in,
// even when $SHELL disagrees. Falls back to $SHELL, then /bin/sh.
func currentShell() string {
	if p := parentShellPath(); p != "" {
		return p
	}
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	return "/bin/sh"
}

var shellNames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "fish": true,
	"ksh": true, "tcsh": true, "csh": true, "dash": true,
}

func parentShellPath() string {
	ppid := strconv.Itoa(os.Getppid())
	name := ""
	if p, err := os.Readlink("/proc/" + ppid + "/exe"); err == nil {
		name = p // linux
	} else if out, err := exec.Command("ps", "-p", ppid, "-o", "comm=").Output(); err == nil {
		name = strings.TrimSpace(string(out))
	}
	name = strings.TrimPrefix(name, "-") // login shells have a leading dash
	if name == "" || !shellNames[filepath.Base(name)] {
		return "" // parent is not a shell (script, editor, ...)
	}
	if strings.Contains(name, "/") {
		return name
	}
	if lp, err := exec.LookPath(name); err == nil {
		return lp
	}
	return ""
}

func cmdExec(cmdline []string) error {
	c, err := openChain()
	if err != nil {
		return err
	}
	bin, err := exec.LookPath(cmdline[0])
	if err != nil {
		return err
	}
	secrets := c.secrets()
	env := secretEnviron(secrets, c.paths, "")
	wipeMap(secrets)
	c.close()
	return execReplace(bin, cmdline, env)
}

// execReplace replaces the schain process, so secrets never sit in a
// lingering parent process.
func execReplace(bin string, argv []string, env []string) error {
	return syscall.Exec(bin, argv, env)
}
