package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The subshell prompt gets a "(schain ~/path) " prefix naming the vault
// directory, so it is obvious which shell holds which secrets even after
// cd-ing elsewhere. No permanent rc edits: schain writes a throwaway
// init file that sources the user's normal startup files, then patches
// the prompt, then deletes itself.

// marker is the prompt prefix, single-quoted for safe embedding in
// shell init code.
var marker string

func setMarker(vaultDir string) {
	m := "(schain " + vaultDir + ") "
	marker = "'" + strings.ReplaceAll(m, "'", `'\''`) + "'"
}

// subshellLaunch returns argv and env for spawning the subshell with a
// prompt marker where the shell supports it. Falls back to a plain
// spawn (env marker only) on error or unknown shells.
func subshellLaunch(shell string, env []string) ([]string, []string) {
	plain := []string{shell}
	if runtime.GOOS == "darwin" {
		// macOS terminals start login shells; match that.
		plain = append(plain, "-l")
	}
	switch filepath.Base(shell) {
	case "bash":
		rc, err := writeTemp("bashrc", bashInit())
		if err != nil {
			return plain, env
		}
		// --rcfile needs a non-login shell; the init file sources the
		// login chain itself on macOS.
		return []string{shell, "--rcfile", rc}, env
	case "zsh":
		dir, err := zshDotDir()
		if err != nil {
			return plain, env
		}
		return plain, append(env, "ZDOTDIR="+dir)
	case "fish":
		return append(plain, "-C", fishInit()), env
	default:
		return plain, env
	}
}

func writeTemp(name, content string) (string, error) {
	dir, err := os.MkdirTemp("", "schain-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	// The init file removes its own directory once it has run.
	content += fmt.Sprintf("\nrm -rf -- %q\n", dir)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return path, nil
}

// autoReloadFn wraps the schain binary in a shell function (defined only
// inside schain subshells) so env-changing commands refresh the shell
// automatically: the function can run `exec`, the child binary cannot.
const autoReloadFn = `
schain() {
  case "${1-}" in
    ""|reload) exec command schain reload ;;
    set|unset) command schain "$@" && exec command schain reload ;;
    *) command schain "$@" ;;
  esac
}`

func bashInit() string {
	if runtime.GOOS == "darwin" {
		return `[ -f /etc/profile ] && . /etc/profile
if [ -f "$HOME/.bash_profile" ]; then . "$HOME/.bash_profile"
elif [ -f "$HOME/.bash_login" ]; then . "$HOME/.bash_login"
elif [ -f "$HOME/.profile" ]; then . "$HOME/.profile"
fi
PS1=` + marker + `"$PS1"` + autoReloadFn
	}
	return `[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"
PS1=` + marker + `"$PS1"` + autoReloadFn
}

// zshDotDir builds a ZDOTDIR whose startup files chain to the user's
// real ones, then prefix the prompt. The .zshrc restores ZDOTDIR and
// removes the temp dir so nested shells behave normally.
func zshDotDir() (string, error) {
	dir, err := os.MkdirTemp("", "schain-zsh-")
	if err != nil {
		return "", err
	}
	files := map[string]string{
		".zshenv":   `[ -f "$HOME/.zshenv" ] && . "$HOME/.zshenv"`,
		".zprofile": `[ -f "$HOME/.zprofile" ] && . "$HOME/.zprofile"`,
		".zlogin":   `[ -f "$HOME/.zlogin" ] && . "$HOME/.zlogin"`,
		".zshrc": `[ -f "$HOME/.zshrc" ] && . "$HOME/.zshrc"
PROMPT=` + marker + `"$PROMPT"
ZDOTDIR="$HOME"
` + autoReloadFn + "\n" + fmt.Sprintf("rm -rf -- %q", dir),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0o600); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

func fishInit() string {
	return `functions -q fish_prompt; and functions -c fish_prompt __schain_prompt
function fish_prompt; echo -n ` + marker + `; __schain_prompt; end
function schain
  if test (count $argv) -eq 0; or test "$argv[1]" = reload
    exec command schain reload
  else if contains -- $argv[1] set unset
    command schain $argv; and exec command schain reload
  else
    command schain $argv
  end
end`
}
