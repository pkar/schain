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
	"time"
)

const vaultName = ".schain"

// version is stamped by the release build via -ldflags.
var version = "dev"

const usageText = `schain - encrypted per-directory environment variables

The encrypted vault is a ` + vaultName + ` file in your project directory,
found from the current directory or any parent (like .git).

usage:
  schain                   spawn subshell with the vault's env
  schain exec <cmd> ...    run one command with the vault's env
  schain set KEY...        store secrets (values prompted, hidden)
  schain set KEY=value     store secret inline (lands in shell history!)
  schain unset KEY...      remove keys
  schain ls                list key names
  schain passwd            change the vault passphrase
  schain remember [dur]    cache key in OS store; skip passphrase prompts
                           (macOS: login keychain; linux: kernel keyring)
                           dur: 30m, 8h, 1h30m; bare number = minutes;
                           omitted = no expiry
  schain forget            drop the cached key
  schain reload            refresh a schain shell's env (automatic after
                           set/unset in bash/zsh/fish; elsewhere run as:
                           exec schain reload)

first "schain set" creates ` + vaultName + ` in the current directory.
inside a schain subshell, $SCHAIN_ACTIVE holds the vault path.`

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
		return cmdLs()
	case "passwd":
		return cmdPasswd()
	case "remember":
		return cmdRemember(args[1:])
	case "forget":
		return cmdForget()
	case "reload":
		return cmdReload()
	default:
		return fmt.Errorf("unknown command %q (see schain --help)", args[0])
	}
}

// findVault walks from cwd toward the root looking for a vault file.
// Returns "" if none exists.
func findVault() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		path := filepath.Join(dir, vaultName)
		if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
			return path, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

func mustFindVault() (string, error) {
	path, err := findVault()
	if err != nil {
		return "", err
	}
	active := os.Getenv("SCHAIN_ACTIVE")
	if path == "" {
		if active != "" {
			return "", fmt.Errorf("no %s here or in any parent\n(this shell's env came from %s; cd there to manage it)",
				vaultName, display(active))
		}
		return "", fmt.Errorf("no %s here or in any parent (create with: schain set KEY)", vaultName)
	}
	if active != "" && active != path {
		fmt.Fprintf(os.Stderr, "schain: warning: operating on %s, but this shell's env came from %s\n",
			display(path), display(active))
	}
	return path, nil
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

// unlock opens the vault, trying the OS key cache before prompting.
func unlock(path string) (*vault, error) {
	if v := tryCache(path); v != nil {
		return v, nil
	}
	pass, err := readSecret(fmt.Sprintf("passphrase for %s: ", display(path)))
	if err != nil {
		return nil, err
	}
	defer wipe(pass)
	return openVault(path, pass)
}

func newPassphrase(path string) ([]byte, error) {
	p1, err := readSecret(fmt.Sprintf("new passphrase for %s: ", display(path)))
	if err != nil {
		return nil, err
	}
	if len(p1) == 0 {
		return nil, fmt.Errorf("empty passphrase not allowed")
	}
	p2, err := readSecret("repeat: ")
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
	if len(args) == 0 {
		return fmt.Errorf("usage: schain set KEY... | KEY=value...")
	}
	path, err := findVault()
	if err != nil {
		return err
	}
	var v *vault
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		path = filepath.Join(cwd, vaultName)
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
	} else {
		v, err = unlock(path)
		if err != nil {
			return err
		}
	}
	defer v.close()
	for _, arg := range args {
		k, inline, hasInline := strings.Cut(arg, "=")
		if k == "" || strings.ContainsAny(k, "\x00") {
			return fmt.Errorf("invalid key %q", arg)
		}
		if hasInline {
			v.Secrets[k] = inline
			continue
		}
		val, err := readSecret(k + ": ")
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
			return fmt.Errorf("no key %q", k)
		}
		delete(v.Secrets, k)
	}
	return v.save(path)
}

func cmdLs() error {
	path, err := mustFindVault()
	if err != nil {
		return err
	}
	v, err := unlock(path)
	if err != nil {
		return err
	}
	defer v.close()
	for _, k := range v.keys() {
		fmt.Println(k)
	}
	return nil
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
	if len(args) > 1 {
		return fmt.Errorf("usage: schain remember [duration]")
	}
	ttl := 0
	if len(args) == 1 {
		d, err := parseTTL(args[0])
		if err != nil {
			return err
		}
		ttl = d
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

func cmdForget() error {
	path, err := mustFindVault()
	if err != nil {
		return err
	}
	if err := cacheForget(path); err != nil {
		return fmt.Errorf("nothing cached for %s", display(path))
	}
	fmt.Fprintf(os.Stderr, "schain: forgot cached key for %s\n", display(path))
	return nil
}

// secretEnviron builds the child environment: current env minus any keys
// being (re)set, plus the vault's secrets and schain markers. Stripping
// first matters on reload: getenv returns the first match, so a stale
// duplicate would shadow the fresh value.
func secretEnviron(v *vault, path, shell string) []string {
	skip := map[string]bool{"SCHAIN_ACTIVE": true, "SCHAIN_SHELL": true}
	for k := range v.Secrets {
		skip[k] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if !skip[k] {
			env = append(env, kv)
		}
	}
	for k, val := range v.Secrets {
		env = append(env, k+"="+val)
	}
	env = append(env, "SCHAIN_ACTIVE="+path)
	if shell != "" {
		env = append(env, "SCHAIN_SHELL="+shell)
	}
	return env
}

func enterShell(v *vault, path string) error {
	// Prefer the shell recorded at first entry: on `exec schain reload`
	// the parent process is the terminal, not the shell, so parent
	// detection would misfire.
	shell := os.Getenv("SCHAIN_SHELL")
	if shell == "" {
		shell = currentShell()
	}
	setMarker(display(path))
	argv, env := subshellLaunch(shell, secretEnviron(v, path, shell))
	fmt.Fprintf(os.Stderr, "schain: entering shell with env from %s (%d keys), exit to leave\n",
		display(path), len(v.Secrets))
	return execReplace(shell, argv, env)
}

func cmdSubshell() error {
	if active := os.Getenv("SCHAIN_ACTIVE"); active != "" {
		return fmt.Errorf("already inside a schain shell for %s\n(exit first, or refresh env with: exec schain reload)", display(active))
	}
	path, err := mustFindVault()
	if err != nil {
		return err
	}
	v, err := unlock(path)
	if err != nil {
		return err
	}
	return enterShell(v, path)
}

// cmdReload re-enters the subshell for the vault this shell came from,
// picking up changes made since. Run as `exec schain reload` so the new
// shell replaces the current one instead of nesting inside it.
func cmdReload() error {
	active := os.Getenv("SCHAIN_ACTIVE")
	if active == "" {
		return fmt.Errorf("not inside a schain shell (enter one with: schain)")
	}
	if _, err := os.Stat(active); err != nil {
		return fmt.Errorf("vault %s no longer exists", display(active))
	}
	v, err := unlock(active)
	if err != nil {
		return err
	}
	return enterShell(v, active)
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
	path, err := mustFindVault()
	if err != nil {
		return err
	}
	v, err := unlock(path)
	if err != nil {
		return err
	}
	bin, err := exec.LookPath(cmdline[0])
	if err != nil {
		return err
	}
	return execReplace(bin, cmdline, secretEnviron(v, path, ""))
}

// execReplace replaces the schain process, so secrets never sit in a
// lingering parent process.
func execReplace(bin string, argv []string, env []string) error {
	return syscall.Exec(bin, argv, env)
}
