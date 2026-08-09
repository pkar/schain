package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// A chain is every vault from cwd up to the root, merged nearest-wins, so
// a child vault holds only its overrides. Each vault keeps its own file,
// salt and passphrase; composition happens in memory after decryption.

// rootKey, present and non-empty in a vault, stops the upward walk there.
// It is never exported to the environment.
const rootKey = "SCHAIN_ROOT"

// Indirection points for tests.
var (
	promptSecret = readSecret
	openCached   = tryCache
)

type chain struct {
	vaults []*vault // root-most first
	paths  []string // parallel to vaults
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
// every worktree. SCHAIN_NO_WORKTREE=1 turns the fallback off.
func resolveVaults() (paths []string, borrowed map[string]bool, err error) {
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

	borrowed = map[string]bool{}
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
			borrowed[p] = true
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
	return err == nil && borrowed[path]
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

// eachVault opens the given vaults one at a time, hands each to fn, and
// closes it again. A vault that will not open is counted as skipped, so
// one bad passphrase does not abandon the rest; only a dead prompt stops
// the run.
func eachVault(paths []string, fn func(string, *vault) error) (done int, skipped []string, err error) {
	var known [][]byte
	defer func() { wipeAll(known) }()
	for _, p := range paths {
		v, err := unlockKnown(p, &known)
		if err != nil {
			var ae abortErr
			if errors.As(err, &ae) {
				return done, skipped, err
			}
			skipped = append(skipped, p)
			fmt.Fprintf(os.Stderr, "schain: skipping %s: %v\n", p, err)
			continue
		}
		err = fn(p, v)
		v.close()
		if err != nil {
			return done, skipped, err
		}
		done++
	}
	return done, skipped, nil
}

func wipeAll(bs [][]byte) {
	for _, b := range bs {
		wipe(b)
	}
}

// secrets merges the chain: root-most first, nearest overwrites.
func (c *chain) secrets() map[string]string {
	out := make(map[string]string)
	for _, v := range c.vaults {
		for k, val := range v.Secrets {
			out[k] = val
		}
	}
	delete(out, rootKey)
	return out
}

// nearest is the vault for cwd itself, the one writes go to.
func (c *chain) nearest() (*vault, string) {
	i := len(c.vaults) - 1
	return c.vaults[i], c.paths[i]
}

// sourceOf names the vault a merged key ends up coming from.
func (c *chain) sourceOf(k string) string {
	src := ""
	for i, v := range c.vaults {
		if _, ok := v.Secrets[k]; ok {
			src = c.paths[i]
		}
	}
	return src
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
