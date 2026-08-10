package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Non-interactive passphrase input, for containers, CI and services with
// no terminal to type at. Both mechanisms are opt-in: with neither set
// nothing here runs, the passphrase is read from /dev/tty as before, and
// a run with no terminal still fails with the same EOF.
//
//	SCHAIN_ASKPASS=prog     run prog, take the first line of its stdout
//	SCHAIN_PASSPHRASE_FILE  read the first line of a 0600 file
//
// Passphrases are per vault, so the helper is told which vault it is
// being asked about: argv is <prompt> <vault path> <open|new>. Without
// that, `remember --all` over vaults that do not share one passphrase
// has no way to answer. The prompt alone would not do, since it carries
// the shortened form of the path, not the path.
//
// There is deliberately no SCHAIN_PASSPHRASE. Every child of `schain
// exec` would inherit it, and on Linux anything able to read
// /proc/<pid>/environ would see it.

const (
	envAskpass  = "SCHAIN_ASKPASS"
	envPassFile = "SCHAIN_PASSPHRASE_FILE"

	// Why the passphrase is wanted; the helper's third argument.
	askOpen = "open" // unlock an existing vault
	askNew  = "new"  // one is being created or changed

	// A passphrase is a line, not a stream. Room for any real one, and a
	// bound on what a helper that streams can hand back.
	maxPassphrase = 4096
)

// passphraseSource names the configured non-interactive source, "" when
// there is none. SCHAIN_ASKPASS wins when both are set: it is the one
// that can tell vaults apart.
func passphraseSource() string {
	if os.Getenv(envAskpass) != "" {
		return envAskpass
	}
	if os.Getenv(envPassFile) != "" {
		return envPassFile
	}
	return ""
}

func passphrasePrompt(path, action string) string {
	if action == askNew {
		return fmt.Sprintf("new passphrase for %s: ", display(path))
	}
	return fmt.Sprintf("passphrase for %s: ", display(path))
}

// askPassphrase gets one vault's passphrase from the configured source,
// or from the terminal when there is none.
func askPassphrase(path, action string) ([]byte, error) {
	prompt := passphrasePrompt(path, action)
	switch passphraseSource() {
	case envAskpass:
		return runAskpass(os.Getenv(envAskpass), prompt, path, action)
	case envPassFile:
		return readPassphraseFile(os.Getenv(envPassFile))
	}
	return promptSecret(prompt)
}

// runAskpass executes the helper and takes the first line of its stdout.
// The passphrase comes back over a pipe, never in argv. The helper keeps
// schain's stderr, so it can explain itself, and gets no stdin, so it
// cannot eat input meant for schain.
//
// A helper that exits non-zero has answered about this one vault and the
// caller moves on; a helper that will not start at all is a broken setup
// that every vault would hit, so that aborts.
func runAskpass(prog, prompt, path, action string) ([]byte, error) {
	out := &capped{buf: make([]byte, 0, maxPassphrase)}
	cmd := exec.Command(prog, prompt, path, action)
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	pass := firstLine(out.buf)
	wipe(out.buf)
	if err != nil {
		wipe(pass)
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("%s: %s gave up (%v)", envAskpass, prog, exit)
		}
		return nil, abortErr{fmt.Errorf("%s: cannot run %s: %w", envAskpass, prog, err)}
	}
	if len(pass) == 0 {
		return nil, fmt.Errorf("%s: %s printed no passphrase", envAskpass, prog)
	}
	return pass, nil
}

// readPassphraseFile reads the first line of a file, refusing one that
// anyone but its owner can read, the way ssh refuses a loose private
// key. Every failure here is a setup failure rather than an answer about
// one vault, so they all abort a batch instead of skipping through it.
func readPassphraseFile(name string) ([]byte, error) {
	fail := func(err error) ([]byte, error) {
		return nil, abortErr{fmt.Errorf("%s: %w", envPassFile, err)}
	}
	f, err := os.Open(name)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !fi.Mode().IsRegular() {
		return fail(fmt.Errorf("%s is not a regular file", name))
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fail(fmt.Errorf("%s is readable by group or others (mode %04o); chmod 600 it", name, perm))
	}
	buf := make([]byte, maxPassphrase)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		wipe(buf)
		return fail(err)
	}
	pass := firstLine(buf[:n])
	wipe(buf)
	if len(pass) == 0 {
		return fail(fmt.Errorf("%s holds no passphrase", name))
	}
	return pass, nil
}

// capped collects a bounded amount of a helper's output. Overrunning the
// cap fails the copy, which closes the pipe and stops a helper that
// streams instead of answering. The buffer is allocated once, so growing
// it cannot leave a stale copy of the passphrase behind.
type capped struct{ buf []byte }

func (c *capped) Write(p []byte) (int, error) {
	if len(c.buf)+len(p) > cap(c.buf) {
		return 0, fmt.Errorf("passphrase helper wrote more than %d bytes", cap(c.buf))
	}
	c.buf = append(c.buf, p...)
	return len(p), nil
}

// firstLine copies the first line of b without its line ending. It is a
// copy so the caller can wipe the buffer it came from.
func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return append([]byte(nil), bytes.TrimSuffix(b, []byte("\r"))...)
}
