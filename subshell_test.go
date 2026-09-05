package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func subshellTestRun(t *testing.T, shell, script, dir string) string {
	t.Helper()
	bin, err := exec.LookPath(shell)
	if err != nil {
		t.Skipf("%s unavailable: %v", shell, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{"-c", script}
	if shell == "bash" {
		args = append([]string{"--noprofile", "--norc"}, args...)
	}
	if shell == "zsh" {
		args = append([]string{"-f"}, args...)
	}
	if shell == "fish" {
		args = append([]string{"--no-config"}, args...)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+dir, "ZDOTDIR="+dir, "BASH_ENV=", "ENV=", "TERM=dumb")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", shell, err, out)
	}
	return string(out)
}

func subshellTestMarker(t *testing.T, value string) {
	t.Helper()
	old := marker
	t.Cleanup(func() { marker = old })
	setMarker(value)
}

func TestSubshellZshLiteralMarker(t *testing.T) {
	if _, err := exec.LookPath("zsh"); err != nil {
		t.Skip("zsh unavailable")
	}
	for _, subst := range []string{"setopt", "unsetopt", "setopt PROMPT_BANG; setopt"} {
		t.Run(subst, func(t *testing.T) {
			home := t.TempDir()
			attack := "$(touch dollar)`touch backtick`%n%F{red}%{! !!\\u\\n\\\\'\"$HOME"
			subshellTestMarker(t, attack)
			rc := subst + " PROMPT_SUBST\nPROMPT='$(printf USER)%%END'\n"
			if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte(rc), 0600); err != nil {
				t.Fatal(err)
			}
			dir, err := zshDotDir()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			script, err := os.ReadFile(filepath.Join(dir, ".zshrc"))
			if err != nil {
				t.Fatal(err)
			}
			got := subshellTestRun(t, "zsh", string(script)+"\nprint -rnP -- \"$PROMPT\"", home)
			suffix := "USER%END"
			if subst == "unsetopt" {
				suffix = "$(printf USER)%END"
			}
			want := "(schain " + attack + ") " + suffix
			if got != want {
				t.Errorf("prompt = %q, want %q", got, want)
			}
			for _, name := range []string{"dollar", "backtick"} {
				if _, err := os.Stat(filepath.Join(home, name)); !os.IsNotExist(err) {
					t.Errorf("marker executed %s: %v", name, err)
				}
			}
		})
	}
}

func TestSubshellTempCleanupLiteralPath(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			if _, err := exec.LookPath(shell); err != nil {
				t.Skipf("%s unavailable", shell)
			}
			home := t.TempDir()
			parent := filepath.Join(home, "tmp $(touch tmp-dollar) `touch tmp-backtick` '$HOME\\\"\n")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(parent, "keep")
			if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TMPDIR", parent)
			subshellTestMarker(t, "safe")
			var target, init string
			if shell == "bash" {
				path, err := writeTemp("bashrc", "")
				if err != nil {
					t.Fatal(err)
				}
				target, init = filepath.Dir(path), path
			} else {
				dir, err := zshDotDir()
				if err != nil {
					t.Fatal(err)
				}
				target, init = dir, filepath.Join(dir, ".zshrc")
			}
			content, err := os.ReadFile(init)
			if err != nil {
				t.Fatal(err)
			}
			subshellTestRun(t, shell, string(content), home)
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Errorf("temporary directory not removed literally: %v", err)
			}
			if _, err := os.Stat(sentinel); err != nil {
				t.Errorf("cleanup removed sibling: %v", err)
			}
			for _, name := range []string{"tmp-dollar", "tmp-backtick"} {
				if _, err := os.Stat(filepath.Join(home, name)); !os.IsNotExist(err) {
					t.Errorf("cleanup executed %s: %v", name, err)
				}
			}
		})
	}
}

func TestSubshellFishLiteralMarker(t *testing.T) {
	attack := "(touch fish-executed)$(touch dollar)`touch backtick`\\n\\\\'\"$HOME"
	subshellTestMarker(t, attack)
	script := "function fish_prompt; printf '%s' USER; end\n" + fishInit() + "\nfish_prompt"
	dir := t.TempDir()
	got := subshellTestRun(t, "fish", script, dir)
	if want := "(schain " + attack + ") USER"; got != want {
		t.Errorf("prompt = %q, want %q", got, want)
	}
	for _, name := range []string{"fish-executed", "dollar", "backtick"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("marker executed %s: %v", name, err)
		}
	}
}

func TestSubshellAutoReloadExecutesBinary(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			if _, err := exec.LookPath(shell); err != nil {
				t.Skipf("%s unavailable", shell)
			}
			home := t.TempDir()
			bin := filepath.Join(home, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			stub := "#!/bin/sh\nprintf '<%s>' \"$@\"\nprintf '\\n'\n"
			if err := os.WriteFile(filepath.Join(bin, "schain"), []byte(stub), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			subshellTestMarker(t, "safe")
			init := autoReloadFn
			if shell == "fish" {
				init = fishInit()
			}
			for _, tc := range []struct{ args, want string }{
				{"", "<reload>\n"},
				{"reload", "<reload>\n"},
				{"set 'KEY=value with spaces'", "<set><KEY=value with spaces>\n<reload>\n"},
				{"unset KEY", "<unset><KEY>\n<reload>\n"},
			} {
				t.Run(tc.args, func(t *testing.T) {
					got := subshellTestRun(t, shell, init+"\nschain "+tc.args+"\nprintf AFTER", home)
					if got != tc.want {
						t.Errorf("wrapper output = %q, want %q (must exec, not return)", got, tc.want)
					}
				})
			}
		})
	}
}

func TestSubshellBashLiteralMarker(t *testing.T) {
	// @P invokes Bash's real prompt decoder without requiring a terminal.
	if subshellTestRun(t, "bash", `if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then printf supported; fi`, t.TempDir()) != "supported" {
		t.Skip("prompt expansion test requires Bash 4.4 or newer")
	}
	for _, promptvars := range []string{"-s", "-u"} {
		t.Run(promptvars, func(t *testing.T) {
			dir := t.TempDir()
			attack := "$(touch dollar)`touch backtick`\\u\\n\\[\\]\\\\'\"$HOME"
			subshellTestMarker(t, attack)
			// Keep the user's command substitution and prompt escape functional.
			rc := "shopt " + promptvars + " promptvars\nPS1='$(printf USER)\\nEND'\n"
			for _, name := range []string{".bashrc", ".bash_profile"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(rc), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got := subshellTestRun(t, "bash", bashInit()+"\nprintf '%s' \"${PS1@P}\"", dir)
			suffix := "USER\nEND"
			if promptvars == "-u" {
				suffix = "$(printf USER)\nEND"
			}
			want := "(schain " + attack + ") " + suffix
			if got != want {
				t.Errorf("prompt = %q, want %q", got, want)
			}
			for _, name := range []string{"dollar", "backtick"} {
				if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
					t.Errorf("marker executed %s: %v", name, err)
				}
			}
		})
	}
}
