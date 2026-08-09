package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// layout makes a temp root holding the given relative directories, and
// returns a resolver from relative path to absolute.
func layout(t *testing.T, dirs ...string) func(string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	warnedUnreachable = false
	return func(rel string) string { return filepath.Join(root, rel) }
}

// fakeWorktree builds git's linked-worktree layout by hand: the .git file
// in the worktree, and the commondir that points back at the main
// checkout. Kept honest by TestWorktreeRealGit below.
func fakeWorktree(t *testing.T, main, wt, name string) {
	t.Helper()
	gitDir := filepath.Join(main, ".git", "worktrees", name)
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "commondir"), []byte("../..\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func chainKeys(t *testing.T) map[string]string {
	t.Helper()
	c := mustChain(t)
	defer c.close()
	return c.secrets()
}

// A worktree resolves the main checkout's per-directory override instead
// of falling through to the ancestor value.
func TestWorktreeBorrowsChild(t *testing.T) {
	at := layout(t, "repo/prod", "wt/prod")
	mkVault(t, at(""), "p", map[string]string{"TOKEN": "root-value"})
	mkVault(t, at("repo/prod"), "p", map[string]string{"TOKEN": "prod-value"})
	fakeWorktree(t, at("repo"), at("wt"), "wt")
	stubCache(t, nil)
	stubPrompt(t, "p", "p")
	captureStderr(t)

	t.Chdir(at("wt/prod"))
	if got := chainKeys(t)["TOKEN"]; got != "prod-value" {
		t.Errorf("TOKEN = %q, want prod-value (borrowed from the main checkout)", got)
	}
}

// Vaults above the repo are reached by the ordinary walk, not copied, and
// a worktree inside the vault root needs no warning.
func TestWorktreeKeepsAncestors(t *testing.T) {
	at := layout(t, "repo/prod", "repo/wt/prod")
	mkVault(t, at(""), "p", map[string]string{"SHARED": "root", "TOKEN": "root-value"})
	mkVault(t, at("repo"), "p", map[string]string{"REPO": "repo"})
	mkVault(t, at("repo/prod"), "p", map[string]string{"TOKEN": "prod-value"})
	fakeWorktree(t, at("repo"), at("repo/wt"), "nested")
	stubCache(t, nil)
	stubPrompt(t, "p")
	stderr := captureStderr(t)

	t.Chdir(at("repo/wt/prod"))
	c := mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{
		"SHARED": "root", "REPO": "repo", "TOKEN": "prod-value",
	})
	// The repo vault is both an ancestor of the worktree and borrowable at
	// the worktree root: it must appear once, not twice.
	if len(c.paths) != 3 {
		t.Errorf("chain = %v, want 3 distinct vaults", c.paths)
	}
	if _, err := os.Stat(filepath.Join(at("repo/wt/prod"), vaultName)); err == nil {
		t.Error("a vault was materialised in the worktree")
	}
	if out := stderr(); strings.Contains(out, "not in reach") {
		t.Errorf("unexpected warning: %q", out)
	}
}

// A vault the worktree does have wins over the borrowed one.
func TestWorktreeLocalWins(t *testing.T) {
	at := layout(t, "repo/prod", "wt/prod")
	mkVault(t, at("repo"), "p", map[string]string{"A": "1"})
	mkVault(t, at("repo/prod"), "p", map[string]string{"TOKEN": "main-prod"})
	fakeWorktree(t, at("repo"), at("wt"), "wt")
	mkVault(t, at("wt/prod"), "p", map[string]string{"TOKEN": "worktree-prod"})
	stubCache(t, nil)
	stubPrompt(t, "p", "p")
	captureStderr(t)

	t.Chdir(at("wt/prod"))
	if got := chainKeys(t)["TOKEN"]; got != "worktree-prod" {
		t.Errorf("TOKEN = %q, want worktree-prod", got)
	}
}

// A worktree outside the vault root cannot reach the ancestors the main
// checkout composes with: say so.
func TestWorktreeUnreachableAncestorWarns(t *testing.T) {
	at := layout(t, "work/repo/prod", "elsewhere/wt/prod")
	rootVault := mkVault(t, at("work"), "p", map[string]string{"SHARED": "root"})
	mkVault(t, at("work/repo/prod"), "p", map[string]string{"TOKEN": "prod-value"})
	fakeWorktree(t, at("work/repo"), at("elsewhere/wt"), "wt")
	stubCache(t, nil)
	stubPrompt(t, "p")
	stderr := captureStderr(t)

	t.Chdir(at("elsewhere/wt/prod"))
	got := chainKeys(t)
	if got["TOKEN"] != "prod-value" {
		t.Errorf("TOKEN = %q, want prod-value", got["TOKEN"])
	}
	if _, ok := got["SHARED"]; ok {
		t.Error("reached a vault outside the worktree's tree")
	}
	out := stderr()
	if !strings.Contains(out, "not in reach") || !strings.Contains(out, display(rootVault)) {
		t.Errorf("want a warning naming %s, stderr = %q", display(rootVault), out)
	}
}

// A submodule uses the same .git-file indirection but has no commondir.
func TestSubmoduleIsNotAWorktree(t *testing.T) {
	at := layout(t, "repo/prod", "repo/sub/prod", "repo/.git/modules/sub")
	mkVault(t, at(""), "p", map[string]string{"TOKEN": "root-value"})
	mkVault(t, at("repo/prod"), "p", map[string]string{"TOKEN": "prod-value"})
	if err := os.WriteFile(filepath.Join(at("repo/sub"), ".git"),
		[]byte("gitdir: ../.git/modules/sub\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)

	t.Chdir(at("repo/sub/prod"))
	if got := chainKeys(t)["TOKEN"]; got != "root-value" {
		t.Errorf("TOKEN = %q, want root-value (a submodule must not borrow)", got)
	}
}

func TestWorktreeOptOut(t *testing.T) {
	at := layout(t, "repo/prod", "wt/prod")
	mkVault(t, at(""), "p", map[string]string{"TOKEN": "root-value"})
	mkVault(t, at("repo/prod"), "p", map[string]string{"TOKEN": "prod-value"})
	fakeWorktree(t, at("repo"), at("wt"), "wt")
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	t.Setenv("SCHAIN_NO_WORKTREE", "1")

	t.Chdir(at("wt/prod"))
	if got := chainKeys(t)["TOKEN"]; got != "root-value" {
		t.Errorf("TOKEN = %q, want root-value with borrowing off", got)
	}
}

// Writes land in the main checkout's file, and say so.
func TestWorktreeSetWritesMainCheckout(t *testing.T) {
	at := layout(t, "repo/prod", "wt/prod")
	mainVault := mkVault(t, at("repo/prod"), "p", map[string]string{"TOKEN": "prod-value"})
	fakeWorktree(t, at("repo"), at("wt"), "wt")
	stubCache(t, nil)
	stubPrompt(t, "p")
	stderr := captureStderr(t)

	t.Chdir(at("wt/prod"))
	if err := cmdSet([]string{"TOKEN=rotated"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(at("wt/prod"), vaultName)); err == nil {
		t.Error("set materialised a vault in the worktree")
	}
	v, err := openVault(mainVault, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if v.Secrets["TOKEN"] != "rotated" {
		t.Errorf("main checkout vault = %q, want rotated", v.Secrets["TOKEN"])
	}
	if out := stderr(); !strings.Contains(out, "main checkout") {
		t.Errorf("no notice about writing to the main checkout: %q", out)
	}
}

// --here still carves out a worktree-local vault.
func TestWorktreeSetHereStaysLocal(t *testing.T) {
	at := layout(t, "repo/prod", "wt/prod")
	mainVault := mkVault(t, at("repo/prod"), "p", map[string]string{"TOKEN": "prod-value"})
	fakeWorktree(t, at("repo"), at("wt"), "wt")
	stubCache(t, nil)
	stubPrompt(t, "local", "local")
	captureStderr(t)

	t.Chdir(at("wt/prod"))
	if err := cmdSet([]string{"--here", "TOKEN=local"}); err != nil {
		t.Fatal(err)
	}
	local, err := openVault(filepath.Join(at("wt/prod"), vaultName), []byte("local"))
	if err != nil {
		t.Fatal(err)
	}
	defer local.close()
	if local.Secrets["TOKEN"] != "local" {
		t.Errorf("worktree vault = %q, want local", local.Secrets["TOKEN"])
	}
	v, err := openVault(mainVault, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if v.Secrets["TOKEN"] != "prod-value" {
		t.Error("main checkout vault was modified")
	}
}

func TestCmdWorktreeReport(t *testing.T) {
	at := layout(t, "repo/prod", "repo/api", "wt/api", "wt/db")
	mkVault(t, at("repo"), "p", nil)
	mkVault(t, at("repo/prod"), "p", nil) // main only
	mkVault(t, at("repo/api"), "p", nil)  // both
	fakeWorktree(t, at("repo"), at("wt"), "wt")
	mkVault(t, at("wt/api"), "p", nil)
	mkVault(t, at("wt/db"), "p", nil) // worktree only
	out := captureStdout(t)

	t.Chdir(at("wt"))
	if err := cmdWorktree(nil); err != nil {
		t.Fatal(err)
	}
	got := out()
	for _, want := range []string{
		"main checkout: " + at("repo"),
		filepath.Join("prod", vaultName),
		"from the main checkout",
		filepath.Join("api", vaultName),
		"local, shadows the main checkout",
		filepath.Join("db", vaultName),
		"local to this worktree",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report missing %q:\n%s", want, got)
		}
	}

	t.Chdir(at("repo"))
	if err := cmdWorktree(nil); err == nil {
		t.Error("want an error outside a linked worktree")
	}
}

// A worktree nested inside the main checkout (how Claude Code creates
// them) must not report its own vaults as the main checkout's.
func TestCmdWorktreeReportNested(t *testing.T) {
	at := layout(t, "repo/prod", "repo/.claude/worktrees/foo/db")
	wt := at("repo/.claude/worktrees/foo")
	mkVault(t, at("repo/prod"), "p", nil)
	fakeWorktree(t, at("repo"), wt, "foo")
	mkVault(t, filepath.Join(wt, "db"), "p", nil)
	out := captureStdout(t)

	t.Chdir(wt)
	if err := cmdWorktree(nil); err != nil {
		t.Fatal(err)
	}
	got := out()
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "  ") && strings.Contains(line, ".claude") {
			t.Errorf("report lists the worktree's own vault as the main checkout's: %q", line)
		}
	}
	for _, want := range []string{"prod/", "from the main checkout", "db/", "local to this worktree"} {
		if !strings.Contains(got, want) {
			t.Errorf("report missing %q:\n%s", want, got)
		}
	}
}

// The hand-built layout above must match what git actually writes.
func TestWorktreeRealGit(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	at := layout(t, "repo/prod") // git creates the worktree directory itself
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(git, args...)
		cmd.Dir = at("repo")
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q", ".")
	run("commit", "-q", "--allow-empty", "-m", "init")
	run("worktree", "add", "--detach", "-q", at("wt"), "HEAD")
	if err := os.MkdirAll(at("wt/prod"), 0o700); err != nil {
		t.Fatal(err)
	}
	mkVault(t, at(""), "p", map[string]string{"TOKEN": "root-value"})
	mkVault(t, at("repo/prod"), "p", map[string]string{"TOKEN": "prod-value"})
	stubCache(t, nil)
	stubPrompt(t, "p", "p")
	captureStderr(t)

	t.Chdir(at("wt/prod"))
	if got := chainKeys(t)["TOKEN"]; got != "prod-value" {
		t.Errorf("TOKEN = %q, want prod-value", got)
	}
}
