package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// askpassScript writes a helper that answers from a vault path ->
// passphrase map, exits 1 for anything else, and records every call as
// prompt|path|action so the contract can be asserted on.
func askpassScript(t *testing.T, answers map[string]string) (prog, log string) {
	t.Helper()
	dir := t.TempDir()
	prog = filepath.Join(dir, "askpass")
	log = filepath.Join(dir, "calls")
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&b, "printf '%%s|%%s|%%s\\n' \"$1\" \"$2\" \"$3\" >> '%s'\n", log)
	b.WriteString("case \"$2\" in\n")
	for path, pass := range answers {
		fmt.Fprintf(&b, "'%s') printf '%%s\\n' '%s';;\n", path, pass)
	}
	b.WriteString("*) echo 'no passphrase for that vault' >&2; exit 1;;\nesac\n")
	if err := os.WriteFile(prog, []byte(b.String()), 0o700); err != nil {
		t.Fatal(err)
	}
	return prog, log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// useAskpass points schain at a helper. stubPrompt goes first: it clears
// both variables, and it makes any prompt that slips through fail.
func useAskpass(t *testing.T, answers map[string]string) (*int, string) {
	t.Helper()
	prompts := stubPrompt(t)
	prog, log := askpassScript(t, answers)
	t.Setenv(envAskpass, prog)
	return prompts, log
}

// The case the whole feature exists for: several vaults, none of them
// sharing a passphrase, cached without a terminal.
func TestAskpassRememberAllDistinctPassphrases(t *testing.T) {
	d := tree(t, "app", "app/dev")
	top := mkVault(t, d[0], "one", map[string]string{"A": "1"})
	mid := mkVault(t, d[1], "two", map[string]string{"B": "2"})
	leaf := mkVault(t, d[2], "three", map[string]string{"C": "3"})
	stubCache(t, nil)
	stored := stubStore(t)
	prompts, log := useAskpass(t, map[string]string{top: "one", mid: "two", leaf: "three"})
	captureStderr(t)
	t.Chdir(d[0])

	if err := cmdRemember([]string{"--all"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{top, mid, leaf} {
		if _, ok := stored[p]; !ok {
			t.Errorf("%s not cached", p)
		}
	}
	if *prompts != 0 {
		t.Errorf("prompted %d time(s); the terminal must not be touched", *prompts)
	}
	got := calls(t, log)
	if len(got) != 3 {
		t.Fatalf("helper called %d time(s), want 3: %v", len(got), got)
	}
	// Vaults are worked on at the same time, so which call landed first
	// is not part of the contract. Which vault each one is about is.
	asked := map[string]bool{}
	for i, call := range got {
		fields := strings.Split(call, "|")
		if len(fields) != 3 {
			t.Fatalf("call %d = %q, want prompt|path|action", i, call)
		}
		asked[fields[1]] = true
		if fields[2] != askOpen {
			t.Errorf("call %d action = %q, want %q", i, fields[2], askOpen)
		}
		if !strings.HasPrefix(fields[0], "passphrase for ") {
			t.Errorf("call %d prompt = %q", i, fields[0])
		}
		for _, pass := range []string{"one", "two", "three"} {
			if strings.Contains(call, "|"+pass) || strings.HasSuffix(call, pass) {
				t.Errorf("call %d argv leaked a passphrase: %q", i, call)
			}
		}
	}
	for _, want := range []string{top, mid, leaf} {
		if !asked[want] {
			t.Errorf("helper was never asked about %s: %v", want, got)
		}
	}
}

// A helper that gives up on one vault gives up on that vault only: the
// rest of the batch still gets cached.
func TestAskpassRefusalSkipsOneVault(t *testing.T) {
	d := tree(t, "app")
	top := mkVault(t, d[0], "one", map[string]string{"A": "1"})
	child := mkVault(t, d[1], "two", map[string]string{"B": "2"})
	stubCache(t, nil)
	stored := stubStore(t)
	_, _ = useAskpass(t, map[string]string{top: "one"}) // nothing for child
	errs := captureStderr(t)
	t.Chdir(d[0])

	if err := cmdRemember([]string{"--all"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := stored[top]; !ok {
		t.Errorf("%s not cached", top)
	}
	if _, ok := stored[child]; ok {
		t.Errorf("%s cached, but the helper refused it", child)
	}
	if !strings.Contains(errs(), "skipping "+child) {
		t.Errorf("stderr did not report the skip: %q", errs())
	}
}

// A helper that cannot be started is a broken setup, not an answer about
// one vault, so it stops the run instead of skipping 66 times.
func TestAskpassUnrunnableAborts(t *testing.T) {
	d := tree(t, "app")
	mkVault(t, d[0], "one", nil)
	mkVault(t, d[1], "two", nil)
	stubCache(t, nil)
	stubStore(t)
	stubPrompt(t)
	t.Setenv(envAskpass, filepath.Join(t.TempDir(), "nope"))
	captureStderr(t)
	t.Chdir(d[0])

	err := cmdRemember([]string{"--all"})
	if err == nil {
		t.Fatal("remember --all succeeded with a helper that does not exist")
	}
	if !strings.Contains(err.Error(), "cannot run") {
		t.Errorf("error = %v, want it to name the unrunnable helper", err)
	}
}

// Creating a vault: one call, action "new", and no repeat prompt.
func TestAskpassCreatesVault(t *testing.T) {
	d := tree(t)
	path := filepath.Join(d[0], vaultName)
	prompts, log := useAskpass(t, map[string]string{path: "fresh"})
	captureStderr(t)
	t.Chdir(d[0])

	if err := run([]string{"set", "--here", "K=v"}); err != nil {
		t.Fatal(err)
	}
	if *prompts != 0 {
		t.Errorf("prompted %d time(s); nothing may be typed here", *prompts)
	}
	got := calls(t, log)
	if len(got) != 1 {
		t.Fatalf("helper called %d time(s), want 1 (no confirmation): %v", len(got), got)
	}
	if fields := strings.Split(got[0], "|"); fields[2] != askNew {
		t.Errorf("action = %q, want %q", fields[2], askNew)
	}
	v, err := openVault(path, []byte("fresh"))
	if err != nil {
		t.Fatalf("vault does not open with the helper's passphrase: %v", err)
	}
	defer v.close()
	if v.Secrets["K"] != "v" {
		t.Errorf("K = %q, want %q", v.Secrets["K"], "v")
	}
}

// The helper's answer is the answer: a wrong one fails the way a wrong
// typed passphrase does, without falling back to the terminal.
func TestAskpassWrongPassphraseDoesNotPrompt(t *testing.T) {
	d := tree(t)
	path := mkVault(t, d[0], "right", map[string]string{"A": "1"})
	stubCache(t, nil)
	prompts, _ := useAskpass(t, map[string]string{path: "wrong"})
	captureStderr(t)
	t.Chdir(d[0])

	if err := cmdLs([]string{"--local"}); err == nil {
		t.Fatal("ls succeeded with the wrong passphrase")
	}
	if *prompts != 0 {
		t.Errorf("fell back to the terminal after the helper answered")
	}
}

func TestAskpassOutputHandling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, vaultName)
	write := func(body string) string {
		prog := filepath.Join(t.TempDir(), "askpass")
		if err := os.WriteFile(prog, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return prog
	}
	cases := []struct {
		name, body, want string
		wantErr          string
	}{
		{name: "trailing newline", body: `printf 'p a s s\n'`, want: "p a s s"},
		{name: "no trailing newline", body: `printf 'pass'`, want: "pass"},
		{name: "crlf", body: `printf 'pass\r\n'`, want: "pass"},
		{name: "first line only", body: `printf 'pass\nnoise\n'`, want: "pass"},
		{name: "silent success", body: `exit 0`, wantErr: "printed no passphrase"},
		{name: "refusal", body: `exit 3`, wantErr: "gave up"},
		{name: "runaway", body: `while :; do printf 'aaaaaaaaaaaaaaaa'; done`, wantErr: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubPrompt(t)
			t.Setenv(envAskpass, write(c.body))
			got, err := askPassphrase(path, askOpen)
			if c.want == "" {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}
				if c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("error = %v, want it to mention %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Errorf("passphrase = %q, want %q", got, c.want)
			}
		})
	}
}

func TestPassphraseFile(t *testing.T) {
	d := tree(t)
	mkVault(t, d[0], "filed", map[string]string{"A": "1"})
	stubCache(t, nil)
	prompts := stubPrompt(t)
	file := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(file, []byte("filed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envPassFile, file)
	captureStderr(t)
	t.Chdir(d[0])

	err := cmdLs([]string{"--local"})
	if err == nil || !strings.Contains(err.Error(), "readable by group or others") {
		t.Fatalf("error = %v, want a refusal over the file's mode", err)
	}
	if !strings.Contains(err.Error(), "0644") {
		t.Errorf("error = %v, want it to name the mode", err)
	}

	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	captureStdout(t)
	if err := cmdLs([]string{"--local"}); err != nil {
		t.Fatal(err)
	}
	if *prompts != 0 {
		t.Errorf("prompted %d time(s)", *prompts)
	}
}

func TestPassphraseFileRejectsDirectory(t *testing.T) {
	stubPrompt(t)
	t.Setenv(envPassFile, t.TempDir())
	if _, err := askPassphrase("/x/"+vaultName, askOpen); err == nil ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

// SCHAIN_ASKPASS wins when both are set: it is the one that can tell
// vaults apart.
func TestAskpassBeatsPassphraseFile(t *testing.T) {
	d := tree(t)
	path := filepath.Join(d[0], vaultName)
	_, log := useAskpass(t, map[string]string{path: "from-helper"})
	file := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(file, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envPassFile, file)
	if passphraseSource() != envAskpass {
		t.Errorf("source = %q, want %q", passphraseSource(), envAskpass)
	}
	got, err := askPassphrase(path, askOpen)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-helper" {
		t.Errorf("passphrase = %q, want the helper's", got)
	}
	if len(calls(t, log)) != 1 {
		t.Errorf("helper not called")
	}
}

// Criterion the reporter cared about as much as the feature: configure
// neither and nothing changes, including the prompt wording.
func TestNoSourceKeepsPrompting(t *testing.T) {
	stubPrompt(t)
	if got := passphraseSource(); got != "" {
		t.Fatalf("source = %q with neither variable set", got)
	}
	var seen []string
	old := promptSecret
	promptSecret = func(prompt string) ([]byte, error) {
		seen = append(seen, prompt)
		return []byte("typed"), nil
	}
	t.Cleanup(func() { promptSecret = old })

	if _, err := askPassphrase("/work/app/"+vaultName, askOpen); err != nil {
		t.Fatal(err)
	}
	if _, err := askPassphrase("/work/app/"+vaultName, askNew); err != nil {
		t.Fatal(err)
	}
	want := []string{"passphrase for /work/app: ", "new passphrase for /work/app: "}
	if strings.Join(seen, ";") != strings.Join(want, ";") {
		t.Errorf("prompts = %v, want %v", seen, want)
	}
}

// A new passphrase typed at a terminal is still confirmed.
func TestNewPassphraseStillRepeatsWhenTyped(t *testing.T) {
	n := stubPrompt(t, "one", "two")
	if _, err := newPassphrase("/work/app/" + vaultName); err == nil {
		t.Fatal("mismatched passphrases accepted")
	}
	if *n != 2 {
		t.Errorf("prompts = %d, want 2", *n)
	}
}

func TestFirstLine(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"pass\n", "pass"},
		{"pass", "pass"},
		{"pass\r\n", "pass"},
		{"pass\nmore\n", "pass"},
		{"\n", ""},
		{"", ""},
		{" lead and trail \n", " lead and trail "},
	} {
		if got := string(firstLine([]byte(c.in))); got != c.want {
			t.Errorf("firstLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
