package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func mustEnv(t *testing.T, c *chain) map[string]string {
	t.Helper()
	env, err := c.env()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// Every name the docs promise has to be one expandValue actually
// substitutes, or the error message points at nothing.
func TestExpandNamesResolve(t *testing.T) {
	for _, name := range expandNames {
		if _, ok := expandOne(name, "/d"); !ok {
			t.Errorf("%s is documented but not substituted", name)
		}
	}
}

// The reason expansion is opt-in and braced: values that look like
// variables to a shell, and are not.
func TestExpandLeavesBareDollarsAlone(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	for _, val := range []string{
		"$2y$05$eiui4LnB2lsnslwDKvjhFu7vXJw7SD",
		"$HOME/not/expanded",
		"pa$$word",
		"${NOPE}/x",
		"${}",
		"${unterminated",
	} {
		got, err := expandValue(val, "/vault/dir")
		if err != nil {
			t.Errorf("expandValue(%q) = error %v, want it left alone", val, err)
			continue
		}
		if got != val {
			t.Errorf("expandValue(%q) = %q, want it unchanged", val, got)
		}
	}
}

func TestExpandSubstitutes(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	t.Setenv("USER", "u")
	cases := []struct{ in, want string }{
		{"${SCHAIN_DIR}/kube.yaml", "/vault/dir/kube.yaml"},
		{"${HOME}/.aws/config", "/home/u/.aws/config"},
		{"${USER}@host", "u@host"},
		{"${SCHAIN_DIR}:${SCHAIN_DIR}", "/vault/dir:/vault/dir"},
		{"${HOME}/x/${NOPE}", "/home/u/x/${NOPE}"},
		{"plain", "plain"},
	}
	for _, c := range cases {
		got, err := expandValue(c.in, "/vault/dir")
		if err != nil {
			t.Errorf("expandValue(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("expandValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A name schain does substitute, with nothing to substitute, is an error
// rather than an empty string: the caller asked for a path and "/x" is
// not the same wrong answer as a visible ${HOME}.
func TestExpandEmptyIsAnError(t *testing.T) {
	t.Setenv("HOME", "")
	if _, err := expandValue("${HOME}/x", "/d"); err == nil {
		t.Fatal("empty ${HOME} expanded silently")
	}
}

// The flag is what makes the difference; a vault written before schain
// understood any of this keeps its values exactly as they are.
func TestExpandIsOptIn(t *testing.T) {
	d := tree(t, "app")
	mkVault(t, d[1], "p", map[string]string{"P": "${SCHAIN_DIR}/kube.yaml"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	t.Chdir(d[1])

	c := mustChain(t)
	defer c.close()
	if got := mustEnv(t, c)["P"]; got != "${SCHAIN_DIR}/kube.yaml" {
		t.Errorf("P = %q, want the stored value untouched", got)
	}
}

// ${SCHAIN_DIR} is the directory of the vault the key is defined in, not
// the nearest vault and not the current directory. A key defined three
// levels up expands to three levels up, wherever you run from.
func TestExpandUsesDefiningVaultDir(t *testing.T) {
	d := tree(t, "repo", "repo/svc")
	mkVault(t, d[0], "p", map[string]string{
		"ROOT_PATH": "${SCHAIN_DIR}/root.yaml",
		expandKey:   "ROOT_PATH",
	})
	mkVault(t, d[1], "p", map[string]string{
		"REPO_PATH": "${SCHAIN_DIR}/repo.yaml",
		expandKey:   "REPO_PATH",
	})
	mkVault(t, d[2], "p", map[string]string{"PLAIN": "v"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	t.Chdir(d[2])

	c := mustChain(t)
	defer c.close()
	env := mustEnv(t, c)
	if got, want := env["ROOT_PATH"], filepath.Join(d[0], "root.yaml"); got != want {
		t.Errorf("ROOT_PATH = %q, want %q", got, want)
	}
	if got, want := env["REPO_PATH"], filepath.Join(d[1], "repo.yaml"); got != want {
		t.Errorf("REPO_PATH = %q, want %q", got, want)
	}
	// What is stored is still the literal, which is what ls reports.
	if got := c.secrets()["ROOT_PATH"]; got != "${SCHAIN_DIR}/root.yaml" {
		t.Errorf("stored ROOT_PATH = %q, want the literal", got)
	}
	// The list of expanded keys configures the vault; it is not env.
	if _, ok := env[expandKey]; ok {
		t.Errorf("%s was exported", expandKey)
	}
}

// A key overridden further down expands against the vault that won, so
// each checkout's override gets its own directory.
func TestExpandFollowsTheOverride(t *testing.T) {
	d := tree(t, "repo", "repo/svc")
	mkVault(t, d[1], "p", map[string]string{"KUBECONFIG": "${SCHAIN_DIR}/kube.yaml", expandKey: "KUBECONFIG"})
	mkVault(t, d[2], "p", map[string]string{"KUBECONFIG": "${SCHAIN_DIR}/kube.yaml", expandKey: "KUBECONFIG"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	t.Chdir(d[2])

	c := mustChain(t)
	defer c.close()
	if got, want := mustEnv(t, c)["KUBECONFIG"], filepath.Join(d[2], "kube.yaml"); got != want {
		t.Errorf("KUBECONFIG = %q, want %q", got, want)
	}
}

// In a linked worktree the borrowed vault lives in the main checkout, but
// the directory it stands in for is here, so a path built from
// ${SCHAIN_DIR} lands in the checkout being worked in. That is the whole
// difference between it and a path with ${HOME} in it.
func TestExpandInWorktreeUsesThisCheckout(t *testing.T) {
	at := layout(t, "repo/svc", "wt/svc")
	mkVault(t, at("repo/svc"), "p", map[string]string{
		"KUBECONFIG": "${SCHAIN_DIR}/kube.yaml",
		expandKey:    "KUBECONFIG",
	})
	fakeWorktree(t, at("repo"), at("wt"), "wt")
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	t.Chdir(at("wt/svc"))

	c := mustChain(t)
	defer c.close()
	if got, want := mustEnv(t, c)["KUBECONFIG"], filepath.Join(at("wt/svc"), "kube.yaml"); got != want {
		t.Errorf("KUBECONFIG = %q, want %q", got, want)
	}
}

// set --expand stores the literal and marks the key.
func TestSetExpandStoresLiteral(t *testing.T) {
	d := tree(t, "app")
	mkVault(t, d[1], "p", map[string]string{"OTHER": "x"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	t.Chdir(d[1])

	if err := cmdSet([]string{"--expand", "KUBECONFIG=${SCHAIN_DIR}/kube.yaml"}); err != nil {
		t.Fatal(err)
	}
	v, err := openVault(filepath.Join(d[1], vaultName), []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if got := v.Secrets["KUBECONFIG"]; got != "${SCHAIN_DIR}/kube.yaml" {
		t.Errorf("stored value = %q, want the literal", got)
	}
	if !v.expands("KUBECONFIG") {
		t.Error("KUBECONFIG was not marked for expansion")
	}
	if v.expands("OTHER") {
		t.Error("OTHER was marked for expansion")
	}
}

// A name schain does not substitute is a complaint at the keyboard, not a
// ${...} discovered in a child's environment months later. Nothing is
// written when it fires.
func TestSetExpandRejectsUnknownNames(t *testing.T) {
	d := tree(t, "app")
	path := mkVault(t, d[1], "p", map[string]string{"A": "1"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	t.Chdir(d[1])

	for _, arg := range []string{"K=${PWD}/x", "K=${2y}", "K=no-reference-at-all"} {
		err := cmdSet([]string{"--expand", arg})
		if err == nil {
			t.Errorf("cmdSet --expand %s was accepted", arg)
			continue
		}
		if !strings.Contains(err.Error(), "K") {
			t.Errorf("error for %s does not name the key: %v", arg, err)
		}
	}
	v, err := openVault(path, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if _, ok := v.Secrets["K"]; ok {
		t.Error("a rejected key was written anyway")
	}
}

// Expansion belongs to the key, not to the one command that turned it on:
// a later plain set would otherwise make the path literal without saying
// so. --no-expand is how you take it back.
func TestSetExpandIsSticky(t *testing.T) {
	d := tree(t, "app")
	path := mkVault(t, d[1], "p", map[string]string{})
	stubCache(t, nil)
	stubPrompt(t, "p", "p", "p")
	captureStderr(t)
	t.Chdir(d[1])

	if err := cmdSet([]string{"--expand", "P=${SCHAIN_DIR}/a"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSet([]string{"P=${SCHAIN_DIR}/b"}); err != nil {
		t.Fatal(err)
	}
	v, err := openVault(path, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if !v.expands("P") {
		t.Error("a plain set turned expansion off")
	}
	v.close()

	if err := cmdSet([]string{"--no-expand", "P=${SCHAIN_DIR}/c"}); err != nil {
		t.Fatal(err)
	}
	v, err = openVault(path, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if v.expands("P") {
		t.Error("--no-expand left the key expanded")
	}
	if _, ok := v.Secrets[expandKey]; ok {
		t.Errorf("%s survived with nothing in it", expandKey)
	}
}

// Removing a key removes the decision about it, so setting it again
// starts from a literal value.
func TestUnsetClearsExpand(t *testing.T) {
	d := tree(t, "app")
	path := mkVault(t, d[1], "p", map[string]string{
		"P":       "${SCHAIN_DIR}/a",
		"Q":       "${HOME}/b",
		expandKey: "P,Q",
	})
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	t.Chdir(d[1])

	if err := cmdUnset([]string{"P"}); err != nil {
		t.Fatal(err)
	}
	v, err := openVault(path, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if v.expands("P") {
		t.Error("P is gone but still listed as expanded")
	}
	if !v.expands("Q") {
		t.Error("unsetting P dropped Q from the list")
	}
}

// ls -v is where the difference between the stored value and the injected
// one is visible, since neither of them is ever printed.
func TestLsMarksExpandedKeys(t *testing.T) {
	d := tree(t, "app")
	mkVault(t, d[1], "p", map[string]string{
		"KUBECONFIG": "${SCHAIN_DIR}/kube.yaml",
		"PLAIN":      "v",
		expandKey:    "KUBECONFIG",
	})
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	out := captureStdout(t)
	t.Chdir(d[1])

	if err := cmdLs([]string{"-v"}); err != nil {
		t.Fatal(err)
	}
	got := out()
	if !strings.Contains(got, "expands ${SCHAIN_DIR}") {
		t.Errorf("ls -v = %q, want the expanded key marked", got)
	}
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.HasPrefix(line, "PLAIN") && strings.Contains(line, "expands") {
			t.Errorf("PLAIN was marked: %q", line)
		}
	}
}

// A reference schain cannot resolve stops the command with the key and
// the vault named, rather than handing a child a path with a hole in it.
func TestExpandErrorNamesKeyAndVault(t *testing.T) {
	d := tree(t, "app")
	mkVault(t, d[1], "p", map[string]string{"P": "${HOME}/x", expandKey: "P"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	captureStderr(t)
	t.Setenv("HOME", "")
	t.Chdir(d[1])

	c := mustChain(t)
	defer c.close()
	_, err := c.env()
	if err == nil {
		t.Fatal("unresolvable ${HOME} was accepted")
	}
	if !strings.Contains(err.Error(), "P") || !strings.Contains(err.Error(), "HOME") {
		t.Errorf("error = %v, want it to name the key and the variable", err)
	}
}
