package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// A chain is every vault from cwd up to the root, merged nearest-wins, so
// a child vault holds only its overrides. Each vault keeps its own file,
// salt and passphrase; composition happens in memory after decryption.

// rootKey, present and non-empty in a vault, stops the upward walk there.
const rootKey = "SCHAIN_ROOT"

// reserved keys configure a vault instead of being part of its
// environment: they are never exported and never get a history entry.
var reserved = map[string]bool{rootKey: true, historyKey: true, expandKey: true}

// Indirection points for tests.
var (
	promptSecret = readSecret
	openCached   = tryCache
)

type chain struct {
	vaults []*vault // root-most first
	paths  []string // parallel to vaults
	dirs   []string // parallel to vaults: what ${SCHAIN_DIR} means in each
}

// workDir is the current directory with symlinks resolved. Vault paths
// (and the cache entries keyed by them) must not depend on which spelling
// of a path the shell got there through: /tmp/x and /private/tmp/x are one
// vault, and git reports the resolved form.
func workDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved, nil
	}
	return dir, nil
}

// isVaultFile reports whether path is a vault file (not a directory).
func isVaultFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// vaultsFrom lists vault files from dir toward the root, nearest first.
func vaultsFrom(dir string) []string {
	var paths []string
	for {
		p := filepath.Join(dir, vaultName)
		if isVaultFile(p) {
			paths = append(paths, p)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return paths
		}
		dir = parent
	}
}

// findVaults lists the vaults for cwd, nearest first.
func findVaults() ([]string, error) {
	paths, _, err := resolveVaults()
	return paths, err
}

// resolveVaults walks from cwd toward the root, taking one vault per
// directory level. Inside a linked git worktree, a level with no vault of
// its own falls back to the main checkout's vault at the same
// repo-relative path: a worktree is a fresh checkout, so its per-directory
// vaults are simply not there, and without this every one of them would
// silently resolve to whatever an ancestor holds. Borrowed paths are
// returned as they live in the main checkout, so a `remember` there covers
// every worktree, mapped to the directory in this tree they stand in for,
// which is the directory ${SCHAIN_DIR} means for their keys.
// SCHAIN_NO_WORKTREE=1 turns the fallback off.
func resolveVaults() (paths []string, borrowed map[string]string, err error) {
	cwd, err := workDir()
	if err != nil {
		return nil, nil, err
	}
	var levels []string
	var wt *worktree
	wtLevel := -1
	noWT := os.Getenv("SCHAIN_NO_WORKTREE") != ""
	for dir := cwd; ; {
		if wt == nil && !noWT {
			if w := findWorktree(dir); w != nil {
				wt, wtLevel = w, len(levels)
			}
		}
		levels = append(levels, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	borrowed = map[string]string{}
	seen := map[string]bool{}
	for i, dir := range levels {
		p := filepath.Join(dir, vaultName)
		if !isVaultFile(p) {
			if wt == nil || i > wtLevel {
				continue // outside the worktree: nothing to borrow
			}
			rel, err := filepath.Rel(wt.root, dir)
			if err != nil {
				continue
			}
			p = filepath.Join(wt.main, rel, vaultName)
			if !isVaultFile(p) {
				continue
			}
			borrowed[p] = dir
		}
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	if wt != nil {
		warnUnreachable(wt, seen)
	}
	return paths, borrowed, nil
}

// isBorrowed reports whether a resolved vault lives in the main checkout
// of a linked worktree rather than in the tree being walked.
func isBorrowed(path string) bool {
	_, borrowed, err := resolveVaults()
	return err == nil && borrowed[path] != ""
}

// vaultDirs is the directory each vault applies to, which ${SCHAIN_DIR}
// resolves to for the keys it defines. That is the vault's own directory,
// except for one borrowed from a worktree's main checkout: it stands in
// for a directory in this tree, and a path built from it should land in
// the checkout being worked in, not in the one the file happens to live
// in. A path schain cannot place falls back to the file's own directory.
func vaultDirs(paths []string) []string {
	_, borrowed, err := resolveVaults()
	dirs := make([]string, len(paths))
	for i, p := range paths {
		dirs[i] = filepath.Dir(p)
		if err == nil && borrowed[p] != "" {
			dirs[i] = borrowed[p]
		}
	}
	return dirs
}

// warnedUnreachable keeps the warning to once per run.
var warnedUnreachable bool

// warnUnreachable reports vaults the main checkout composes with that this
// worktree cannot reach, which happens when the worktree was created
// outside the vault root. The borrowed children then resolve against
// nothing, which is the case most likely to confuse later.
func warnUnreachable(wt *worktree, have map[string]bool) {
	if warnedUnreachable {
		return
	}
	var missing []string
	for _, p := range vaultsFrom(filepath.Dir(wt.main)) {
		if !have[p] {
			missing = append(missing, display(p))
		}
	}
	if len(missing) == 0 {
		return
	}
	warnedUnreachable = true
	fmt.Fprintf(os.Stderr, "schain: warning: this worktree is outside %s, so %d vault(s) the main checkout composes with are not in reach: %s\n",
		displayDir(wt.main), len(missing), strings.Join(missing, ", "))
}

// findVaultsUnder walks dir downward for vault files, in lexical order.
// Unreadable directories are skipped rather than fatal, and directory
// symlinks are not followed, so the walk cannot loop.
func findVaultsUnder(dir string) ([]string, error) {
	return walkVaults(dir, false)
}

// walkVaults is findVaultsUnder with a choice about nested checkouts:
// skipNested stops at any directory below root that is itself a git
// checkout (another worktree, a submodule), whose vaults belong to that
// checkout rather than this one.
func walkVaults(root string, skipNested bool) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable: skip it, keep walking
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			if skipNested && p != root {
				if _, err := os.Lstat(filepath.Join(p, ".git")); err == nil {
					return fs.SkipDir
				}
			}
			return nil
		}
		if d.Name() != vaultName {
			return nil
		}
		if isVaultFile(p) {
			paths = append(paths, p)
		}
		return nil
	})
	return paths, err
}

// mergePaths concatenates path lists, first occurrence wins.
func mergePaths(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, p := range l {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// allVaults is every vault this directory inherits from plus every one
// underneath it: what --all operates on.
func allVaults() ([]string, error) {
	up, err := findVaults()
	if err != nil {
		return nil, err
	}
	cwd, err := workDir()
	if err != nil {
		return nil, err
	}
	down, err := findVaultsUnder(cwd)
	if err != nil {
		return nil, err
	}
	paths := mergePaths(reversed(up), down)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no %s here, above, or below", vaultName)
	}
	return paths, nil
}

// findVault returns the nearest vault, "" if none.
func findVault() (string, error) {
	paths, err := findVaults()
	if err != nil || len(paths) == 0 {
		return "", err
	}
	return paths[0], nil
}

// openChain unlocks the whole chain for cwd. SCHAIN_NO_INHERIT=1 keeps
// the old behaviour: nearest vault only.
func openChain() (*chain, error) {
	paths, err := findVaults()
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, noVaultErr()
	}
	warnForeign(paths[0])
	if os.Getenv("SCHAIN_NO_INHERIT") != "" {
		paths = paths[:1]
	}
	return loadChain(paths)
}

// loadChain opens the given vaults nearest first (so prompts read
// bottom-up) and returns them root-most first for merging. A passphrase
// that opens one vault is tried on the next, so a chain created with one
// passphrase asks once.
func loadChain(paths []string) (*chain, error) {
	c := &chain{}
	dirs := vaultDirs(paths)
	var known [][]byte
	defer func() { wipeAll(known) }()
	for i, p := range paths {
		v, err := unlockKnown(p, &known)
		if err != nil {
			c.close()
			if i > 0 {
				// A vault the user did not ask for by standing in it;
				// point at the way out.
				return nil, fmt.Errorf("%w\n(from inherited vault %s; SCHAIN_NO_INHERIT=1 skips it)", err, p)
			}
			return nil, err
		}
		c.vaults = append([]*vault{v}, c.vaults...)
		c.paths = append([]string{p}, c.paths...)
		c.dirs = append([]string{dirs[i]}, c.dirs...)
		if v.Secrets[rootKey] != "" {
			break
		}
	}
	return c, nil
}

// abortErr marks a failure that should stop a batch of vaults (no input
// on the terminal) instead of skipping one of them.
type abortErr struct{ err error }

func (e abortErr) Error() string { return e.err.Error() }
func (e abortErr) Unwrap() error { return e.err }

// unlockKnown opens one vault: cached key, then any passphrase already
// accepted in this run, then a prompt. A passphrase that works moves to
// the front of the list, since neighbouring vaults tend to share one.
func unlockKnown(path string, known *[][]byte) (*vault, error) {
	if v := openCached(path); v != nil {
		return v, nil
	}
	// A configured passphrase source answers per vault, so there is
	// nothing to reuse from other vaults and nothing to fall back to:
	// what it says for this vault is the answer for this vault. That also
	// keeps a run over vaults with distinct passphrases from re-deriving
	// every earlier one before asking, which is quadratic in PBKDF2.
	if passphraseSource() != "" {
		p, err := askPassphrase(path, askOpen)
		if err != nil {
			return nil, err
		}
		defer wipe(p)
		return openVault(path, p)
	}
	for i, p := range *known {
		v, err := openVault(path, p)
		if err == nil {
			k := *known
			copy(k[1:i+1], k[:i])
			k[0] = p
			return v, nil
		}
		if err != errBadPassphrase {
			return nil, err
		}
	}
	p, err := promptSecret(fmt.Sprintf("passphrase for %s: ", display(path)))
	if err != nil {
		return nil, abortErr{err}
	}
	v, err := openVault(path, p)
	if err != nil {
		wipe(p)
		return nil, err
	}
	*known = append([][]byte{p}, *known...)
	return v, nil
}

// eachVault opens the given vaults, hands each to fn, and closes it
// again. Vaults have nothing to do with one another, so this works on
// several at once and fn must be safe to call from several goroutines.
// Deriving one key is 600k rounds of PBKDF2, and on macOS every cache
// write is a separate `security` process, so a run over a few dozen
// vaults spends nearly all its time in work that parallelises.
//
// Each pass tries one thing against every vault still shut: first the
// keys already in the OS store, then each passphrase as it is learned. A
// pass only has to try the newest passphrase, since the ones before it
// have already failed on everything still shut. The prompt is the serial
// part, and it asks about the first vault still shut, which is the order
// schain has always asked in.
//
// A vault that will not open is counted as skipped, so one bad
// passphrase does not abandon the rest; only a dead prompt stops the run.
func eachVault(paths []string, fn func(string, *vault) error) (done int, skipped []string, err error) {
	r := &vaultRun{fn: fn}

	// Whatever `remember` already cached: no passphrase, no derivation,
	// and on a re-run it is the whole job.
	left := r.pass(paths, func(p string) (*vault, error) {
		if v := openCached(p); v != nil {
			return v, nil
		}
		return nil, errBadPassphrase
	})

	// A configured source answers per vault, so there is nothing to carry
	// from one vault to the next. One pass asks about all of them, and
	// asking twice would only get the same answer.
	if passphraseSource() != "" {
		left = r.pass(left, func(p string) (*vault, error) {
			pass, err := askPassphrase(p, askOpen)
			if err != nil {
				return nil, err
			}
			defer wipe(pass)
			return openVault(p, pass)
		})
		if r.err == nil {
			for _, p := range left {
				r.skip(p, errBadPassphrase)
			}
		}
		return r.done, r.skipped, r.err
	}

	// Typed: ask about the first vault still shut, then try that answer
	// against every one of them at once. Neighbouring vaults tend to
	// share a passphrase, so one answer usually opens the rest in a
	// single pass.
	var known [][]byte
	defer func() { wipeAll(known) }()
	for len(left) > 0 && r.err == nil {
		asked := left[0]
		pass, err := promptSecret(fmt.Sprintf("passphrase for %s: ", display(asked)))
		if err != nil {
			return r.done, r.skipped, abortErr{err}
		}
		known = append(known, pass)
		left = r.pass(left, func(p string) (*vault, error) {
			return openVault(p, pass)
		})
		if r.err != nil {
			break
		}
		if len(left) > 0 && left[0] == asked {
			// It did not fit the vault it was asked about, and asking
			// again would be the same question.
			r.skip(asked, errBadPassphrase)
			left = left[1:]
		}
	}
	return r.done, r.skipped, r.err
}

// vaultRun is what a sequence of passes over the vaults added up to.
// Nothing here is touched from a worker: the passes hand back their
// results in path order and this is filled in from that, so what schain
// counts and prints does not depend on which vault finished first.
type vaultRun struct {
	fn      func(string, *vault) error
	done    int
	skipped []string
	err     error
}

// vaultResult is one worker's outcome: why the vault stayed shut, or
// what fn made of it once it opened.
type vaultResult struct {
	openErr error
	fnErr   error
}

// pass opens every path with open, on every core, and hands what opens to
// fn. It returns the paths whose passphrase open did not have, in their
// original order, for the next pass to try.
func (r *vaultRun) pass(paths []string, open func(string) (*vault, error)) []string {
	if r.err != nil || len(paths) == 0 {
		return paths
	}
	res := forEach(paths, func(p string) vaultResult {
		v, err := open(p)
		if err != nil {
			return vaultResult{openErr: err}
		}
		err = r.fn(p, v)
		v.close()
		return vaultResult{fnErr: err}
	})
	var left []string
	for i, p := range paths {
		switch {
		case res[i].openErr == errBadPassphrase:
			left = append(left, p)
		case res[i].openErr != nil:
			r.skip(p, res[i].openErr)
		case res[i].fnErr != nil:
			if r.err == nil {
				r.err = res[i].fnErr
			}
		default:
			r.done++
		}
	}
	return left
}

// skip records a vault that would not open. A failure no vault could get
// past (no terminal, an unrunnable helper) ends the run instead, since
// every other vault would fail the same way.
func (r *vaultRun) skip(path string, err error) {
	var ae abortErr
	if errors.As(err, &ae) {
		if r.err == nil {
			r.err = err
		}
		return
	}
	r.skipped = append(r.skipped, path)
	fmt.Fprintf(os.Stderr, "schain: skipping %s: %v\n", path, err)
}

// forEach runs fn over items on several goroutines and returns the
// results in the order the items came in.
func forEach[T, R any](items []T, fn func(T) R) []R {
	out := make([]R, len(items))
	sem := make(chan struct{}, vaultWorkers())
	var wg sync.WaitGroup
	for i, it := range items {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = fn(it)
		}()
	}
	wg.Wait()
	return out
}

// vaultWorkers bounds how many vaults are worked on at once. PBKDF2 is
// CPU bound, so one per core is the whole win there; the process spawns
// macOS needs for its keychain overlap happily at the same width.
func vaultWorkers() int {
	if n := runtime.GOMAXPROCS(0); n > 1 {
		return n
	}
	return 1
}

func wipeAll(bs [][]byte) {
	for _, b := range bs {
		wipe(b)
	}
}

// secrets merges the chain as stored: root-most first, nearest
// overwrites. This is what "ls" reports.
func (c *chain) secrets() map[string]string {
	out, _ := c.merge(false)
	return out
}

// env is the same merge with every opted-in value expanded against the
// vault that defines it: what a child process actually gets. It differs
// from secrets only for keys in a vault's SCHAIN_EXPAND, and "ls -v"
// marks those, because a stored value that is not the injected value is
// something you want to find out about once rather than debug twice.
func (c *chain) env() (map[string]string, error) {
	return c.merge(true)
}

func (c *chain) merge(expand bool) (map[string]string, error) {
	out := make(map[string]string)
	for i, v := range c.vaults {
		for k, val := range v.Secrets {
			if expand && v.expands(k) {
				got, err := expandValue(val, c.dirs[i])
				if err != nil {
					wipeMap(out)
					return nil, fmt.Errorf("%s from %s: %w", k, display(c.paths[i]), err)
				}
				val = got
			}
			out[k] = val
		}
	}
	for k := range reserved {
		delete(out, k)
	}
	return out, nil
}

// nearest is the vault for cwd itself, the one writes go to.
func (c *chain) nearest() (*vault, string) {
	i := len(c.vaults) - 1
	return c.vaults[i], c.paths[i]
}

// sourceOf names the vault a merged key ends up coming from.
func (c *chain) sourceOf(k string) string {
	_, src := c.definerOf(k)
	return src
}

// definerOf is the vault a merged key ends up coming from, and its path.
// The vault itself is what says whether the key is expanded.
func (c *chain) definerOf(k string) (*vault, string) {
	var def *vault
	src := ""
	for i, v := range c.vaults {
		if _, ok := v.Secrets[k]; ok {
			def, src = v, c.paths[i]
		}
	}
	return def, src
}

func (c *chain) close() {
	for _, v := range c.vaults {
		v.close()
	}
}

// wipeMap clears merged plaintext that no vault.close reaches.
func wipeMap(m map[string]string) {
	for k := range m {
		m[k] = ""
	}
}

// inheritedFrom names the ancestor vault defining k. Best effort: it only
// looks at vaults whose key is already cached, so it never prompts.
func inheritedFrom(k string) string {
	paths, err := findVaults()
	if err != nil || len(paths) < 2 {
		return ""
	}
	for _, p := range paths[1:] {
		v := openCached(p)
		if v == nil {
			continue
		}
		_, ok := v.Secrets[k]
		v.close()
		if ok {
			return p
		}
	}
	return ""
}

// activeChain is $SCHAIN_ACTIVE split into vault paths, nearest last.
func activeChain() []string {
	if a := os.Getenv("SCHAIN_ACTIVE"); a != "" {
		return filepath.SplitList(a)
	}
	return nil
}

func reversed(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}
