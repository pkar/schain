package main

import (
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

// marker is raw data; each shell quotes it for its own parsing rules.
var marker string

func setMarker(vaultDir string) {
	marker = "(schain " + vaultDir + ") "
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fishQuote(s string) string {
	// Unlike POSIX shells, fish interprets \\ and \' inside single quotes.
	s = strings.ReplaceAll(s, `\`, `\\`)
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
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
	content += "\nrm -rf -- " + shellQuote(dir) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return path, nil
}

// autoReloadFn wraps the schain binary in a shell function (defined only
// inside schain subshells) so env-changing commands refresh the shell
// automatically: the function can run `exec`, the child binary cannot.
// env resolves the external binary consistently: Bash/fish cannot exec the
// command builtin, while zsh's bare exec can recurse into the schain function.
const autoReloadFn = `
schain() {
  case "${1-}" in
    ""|reload) exec env schain reload ;;
    set|unset) command schain "$@" && exec env schain reload ;;
    *) command schain "$@" ;;
  esac
}`

// bashPrompt inserts data through parameter expansion, after Bash has decoded
// prompt escapes. Neither command substitutions nor backslashes in the marker
// are interpreted again. With promptvars off, only prompt escapes need quoting.
func bashPrompt() string {
	return `__schain_marker=` + shellQuote(marker) + `
if shopt -q promptvars; then
  PS1='${__schain_marker}'"$PS1"
else
  PS1="${__schain_marker//\\/\\\\}$PS1"
fi`
}

func bashInit() string {
	if runtime.GOOS == "darwin" {
		return `[ -f /etc/profile ] && . /etc/profile
if [ -f "$HOME/.bash_profile" ]; then . "$HOME/.bash_profile"
elif [ -f "$HOME/.bash_login" ]; then . "$HOME/.bash_login"
elif [ -f "$HOME/.profile" ]; then . "$HOME/.profile"
fi
` + bashPrompt() + autoReloadFn
	}
	return `[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"
` + bashPrompt() + autoReloadFn
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
__schain_marker=` + shellQuote(marker) + `
# Parameter expansion is not recursively evaluated by PROMPT_SUBST, but
# percent escapes are processed afterwards and must be quoted separately.
if [[ -o promptpercent ]]; then
  __schain_marker=${__schain_marker//\%/%%}
fi
if [[ -o promptbang ]]; then
  __schain_marker=${__schain_marker//!/!!}
fi
if [[ -o promptsubst ]]; then
  PROMPT='${__schain_marker}'"$PROMPT"
else
  PROMPT="$__schain_marker$PROMPT"
fi
ZDOTDIR="$HOME"
` + autoReloadFn + "\nrm -rf -- " + shellQuote(dir),
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
function fish_prompt; printf '%s' ` + fishQuote(marker) + `; __schain_prompt; end
function schain
  if test (count $argv) -eq 0; or test "$argv[1]" = reload
    exec env schain reload
  else if contains -- $argv[1] set unset
    command schain $argv; and exec env schain reload
  else
    command schain $argv
  end
end`
}
