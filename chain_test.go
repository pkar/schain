package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tree makes a temp directory hierarchy and returns the resolved paths of
// each level. Resolving matters on macOS, where /var is a symlink and
// os.Getwd would disagree with t.TempDir.
func tree(t *testing.T, levels ...string) []string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dirs := []string{root}
	cur := root
	for _, l := range levels {
		cur = filepath.Join(cur, l)
		if err := os.MkdirAll(cur, 0o700); err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, cur)
	}
	return dirs
}

func mkVault(t *testing.T, dir, pass string, kv map[string]string) string {
	t.Helper()
	v, err := newVault([]byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	for k, val := range kv {
		v.Secrets[k] = val
	}
	path := filepath.Join(dir, vaultName)
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}
	return path
}

// stubPrompt answers passphrase prompts in order and counts them; an
// unexpected prompt fails the test.
func stubPrompt(t *testing.T, answers ...string) *int {
	t.Helper()
	n := 0
	old := promptSecret
	promptSecret = func(prompt string) ([]byte, error) {
		if n >= len(answers) {
			return nil, fmt.Errorf("unexpected prompt %q", prompt)
		}
		n++
		return []byte(answers[n-1]), nil
	}
	t.Cleanup(func() { promptSecret = old })
	return &n
}

// stubCache pretends the given vaults (path -> passphrase) have cached
// keys, and every other vault has none. Keeps tests off the OS store.
func stubCache(t *testing.T, hits map[string]string) {
	t.Helper()
	old := openCached
	openCached = func(path string) *vault {
		pass, ok := hits[path]
		if !ok {
			return nil
		}
		v, err := openVault(path, []byte(pass))
		if err != nil {
			return nil
		}
		return v
	}
	t.Cleanup(func() { openCached = old })
}

func captureStderr(t *testing.T) func() string {
	t.Helper()
	f, err := os.CreateTemp("", "schain-err")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = f
	t.Cleanup(func() { os.Stderr = old; f.Close(); os.Remove(f.Name()) })
	return func() string {
		b, _ := os.ReadFile(f.Name())
		return string(b)
	}
}

func captureStdout(t *testing.T) func() string {
	t.Helper()
	f, err := os.CreateTemp("", "schain-out")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = f
	t.Cleanup(func() { os.Stdout = old; f.Close(); os.Remove(f.Name()) })
	return func() string {
		b, _ := os.ReadFile(f.Name())
		return string(b)
	}
}

func TestPrintKeys(t *testing.T) {
	src := func(k string) string {
		if k == "A" {
			return "/tmp/parent/.schain"
		}
		return "/tmp/parent/child/.schain"
	}
	keys := []string{"A", "LONGER"}

	out := captureStdout(t)
	printKeys(keys, src, true, false)
	if got, want := out(), "A       /tmp/parent\nLONGER  /tmp/parent/child\n"; got != want {
		t.Errorf("annotated output = %q, want %q", got, want)
	}

	out = captureStdout(t)
	printKeys(keys, src, true, true) // --plain wins over -v
	if got, want := out(), "A\nLONGER\n"; got != want {
		t.Errorf("plain output = %q, want %q", got, want)
	}
}

func mustChain(t *testing.T) *chain {
	t.Helper()
	c, err := openChain()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func wantSecrets(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("keys = %v, want %v", sortedKeys(got), sortedKeys(want))
	}
}

func TestChainInherit(t *testing.T) {
	d := tree(t, "a")
	mkVault(t, d[0], "p", map[string]string{"A": "parent"})
	mkVault(t, d[1], "p", map[string]string{"B": "child"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	t.Chdir(d[1])

	c := mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"A": "parent", "B": "child"})
}

func TestChainOverride(t *testing.T) {
	d := tree(t, "a")
	mkVault(t, d[0], "p", map[string]string{"S": "parent_val", "P": "p"})
	mkVault(t, d[1], "p", map[string]string{"S": "child_val"})
	stubCache(t, nil)
	stubPrompt(t, "p", "p")

	t.Chdir(d[1])
	c := mustChain(t)
	wantSecrets(t, c.secrets(), map[string]string{"S": "child_val", "P": "p"})
	c.close()

	t.Chdir(d[0])
	c = mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"S": "parent_val", "P": "p"})
}

func TestChainThreeLevels(t *testing.T) {
	d := tree(t, "mid", "leaf")
	mkVault(t, d[0], "p", map[string]string{"ROOT_ONLY": "r", "S": "root"})
	mkVault(t, d[1], "p", map[string]string{"S": "mid", "M": "m"})
	mkVault(t, d[2], "p", map[string]string{"S": "leaf"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	t.Chdir(d[2])

	c := mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"ROOT_ONLY": "r", "M": "m", "S": "leaf"})
	if got := c.sourceOf("S"); got != c.paths[2] {
		t.Errorf("sourceOf(S) = %s, want %s", got, c.paths[2])
	}
	if got := c.sourceOf("ROOT_ONLY"); got != c.paths[0] {
		t.Errorf("sourceOf(ROOT_ONLY) = %s, want %s", got, c.paths[0])
	}
}

func TestChainDistinctPassphrases(t *testing.T) {
	d := tree(t, "a")
	mkVault(t, d[0], "parentpass", map[string]string{"A": "parent"})
	mkVault(t, d[1], "childpass", map[string]string{"B": "child"})
	stubCache(t, nil)
	// nearest first: child, then parent
	n := stubPrompt(t, "childpass", "parentpass")
	t.Chdir(d[1])

	c := mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"A": "parent", "B": "child"})
	if *n != 2 {
		t.Errorf("prompts = %d, want 2", *n)
	}
}

func TestChainSharedPassphraseOnePrompt(t *testing.T) {
	d := tree(t, "a", "b")
	mkVault(t, d[0], "same", map[string]string{"A": "1"})
	mkVault(t, d[1], "same", map[string]string{"B": "2"})
	mkVault(t, d[2], "same", map[string]string{"C": "3"})
	stubCache(t, nil)
	n := stubPrompt(t, "same")
	t.Chdir(d[2])

	c := mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"A": "1", "B": "2", "C": "3"})
	if *n != 1 {
		t.Errorf("prompts = %d, want 1", *n)
	}
}

func TestChainAllCachedNoPrompt(t *testing.T) {
	d := tree(t, "a")
	pp := mkVault(t, d[0], "p1", map[string]string{"A": "parent"})
	cp := mkVault(t, d[1], "p2", map[string]string{"B": "child"})
	stubCache(t, map[string]string{pp: "p1", cp: "p2"})
	n := stubPrompt(t) // any prompt is an error
	t.Chdir(d[1])

	c := mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"A": "parent", "B": "child"})
	if *n != 0 {
		t.Errorf("prompts = %d, want 0", *n)
	}
}

// A rekeyed child invalidates only its own cache entry, so exactly one
// prompt remains.
func TestChainOnePromptAfterRekey(t *testing.T) {
	d := tree(t, "a")
	pp := mkVault(t, d[0], "p1", map[string]string{"A": "parent"})
	cp := mkVault(t, d[1], "old", map[string]string{"B": "child"})
	v, err := openVault(cp, []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.rekey([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := v.save(cp); err != nil {
		t.Fatal(err)
	}
	stubCache(t, map[string]string{pp: "p1", cp: "old"}) // stale salt -> miss
	n := stubPrompt(t, "new")
	t.Chdir(d[1])

	c := mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"A": "parent", "B": "child"})
	if *n != 1 {
		t.Errorf("prompts = %d, want 1", *n)
	}
}

func TestChainNoInherit(t *testing.T) {
	d := tree(t, "a")
	mkVault(t, d[0], "p", map[string]string{"A": "parent"})
	mkVault(t, d[1], "p", map[string]string{"B": "child"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	t.Setenv("SCHAIN_NO_INHERIT", "1")
	t.Chdir(d[1])

	c := mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"B": "child"})
}

func TestChainRootKeyStopsWalk(t *testing.T) {
	d := tree(t, "a", "b")
	mkVault(t, d[0], "p", map[string]string{"TOP": "top"})
	mkVault(t, d[1], "p", map[string]string{rootKey: "1", "MID": "mid"})
	mkVault(t, d[2], "p", map[string]string{"LEAF": "leaf"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	t.Chdir(d[2])

	c := mustChain(t)
	defer c.close()
	// TOP is above the root marker; the marker itself is not exported.
	wantSecrets(t, c.secrets(), map[string]string{"MID": "mid", "LEAF": "leaf"})
}

func TestChainCloseWipes(t *testing.T) {
	d := tree(t, "a")
	mkVault(t, d[0], "p", map[string]string{"A": "parent"})
	mkVault(t, d[1], "p", map[string]string{"B": "child"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	t.Chdir(d[1])

	c := mustChain(t)
	secrets := c.secrets()
	c.close()
	wipeMap(secrets)
	for _, v := range c.vaults {
		for k, val := range v.Secrets {
			if val != "" {
				t.Errorf("vault kept %s = %q", k, val)
			}
		}
	}
	for k, val := range secrets {
		if val != "" {
			t.Errorf("merged map kept %s = %q", k, val)
		}
	}
}

// reload rebuilds the chain from $SCHAIN_ACTIVE (root-most first), so the
// precedence must survive the round trip.
func TestReloadChainOrder(t *testing.T) {
	d := tree(t, "a")
	pp := mkVault(t, d[0], "p", map[string]string{"S": "parent", "A": "1"})
	cp := mkVault(t, d[1], "p", map[string]string{"S": "child"})
	stubCache(t, map[string]string{pp: "p", cp: "p"})
	stubPrompt(t)
	t.Setenv("SCHAIN_ACTIVE", pp+string(os.PathListSeparator)+cp)

	c, err := loadChain(reversed(activeChain()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"S": "child", "A": "1"})
}

func TestSecretEnvironChain(t *testing.T) {
	t.Setenv("A", "stale")
	env := secretEnviron(map[string]string{"A": "fresh"}, []string{"/p/.schain", "/p/c/.schain"}, "")
	var seenA int
	active := ""
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "A":
			seenA++
			if v != "fresh" {
				t.Errorf("A = %q, want fresh", v)
			}
		case "SCHAIN_ACTIVE":
			active = v
		}
	}
	if seenA != 1 {
		t.Errorf("A appears %d times, want 1", seenA)
	}
	if want := "/p/.schain" + string(os.PathListSeparator) + "/p/c/.schain"; active != want {
		t.Errorf("SCHAIN_ACTIVE = %q, want %q", active, want)
	}
}

func TestSetHereCreatesChildVault(t *testing.T) {
	d := tree(t, "a")
	mkVault(t, d[0], "p", map[string]string{"A": "parent"})
	stubCache(t, nil)
	stubPrompt(t, "childpass", "childpass") // new passphrase + repeat
	captureStderr(t)
	t.Chdir(d[1])

	if err := cmdSet([]string{"--here", "B=child"}); err != nil {
		t.Fatal(err)
	}
	v, err := openVault(filepath.Join(d[1], vaultName), []byte("childpass"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if v.Secrets["B"] != "child" || len(v.Secrets) != 1 {
		t.Errorf("child vault = %v, want only B=child", v.Secrets)
	}
}

func TestSetWithoutHereWarnsAndWritesAncestor(t *testing.T) {
	d := tree(t, "a")
	pp := mkVault(t, d[0], "p", map[string]string{"A": "parent"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	stderr := captureStderr(t)
	t.Chdir(d[1])

	if err := cmdSet([]string{"B=child"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d[1], vaultName)); err == nil {
		t.Error("created a vault without --here")
	}
	if out := stderr(); !strings.Contains(out, "writing to "+pp) || !strings.Contains(out, "--here") {
		t.Errorf("missing warning, stderr = %q", out)
	}
	v, err := openVault(pp, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if v.Secrets["B"] != "child" {
		t.Error("ancestor vault not written")
	}
}

func TestUnsetInheritedKey(t *testing.T) {
	d := tree(t, "a")
	pp := mkVault(t, d[0], "p", map[string]string{"A": "parent"})
	cp := mkVault(t, d[1], "p", map[string]string{"B": "child"})
	stubCache(t, map[string]string{pp: "p", cp: "p"})
	stubPrompt(t)
	captureStderr(t)
	t.Chdir(d[1])

	err := cmdUnset([]string{"A"})
	if err == nil || !strings.Contains(err.Error(), pp) {
		t.Fatalf("err = %v, want one naming %s", err, pp)
	}
	v, err := openVault(pp, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if v.Secrets["A"] != "parent" {
		t.Error("ancestor modified")
	}
}
