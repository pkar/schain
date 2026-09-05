package main

import (
	"fmt"
	"os/exec"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Portable construction keeps the macOS stdin protocol testable on Linux.
func securityStoreCommand(bin, user, service string, payload []byte) (*exec.Cmd, error) {
	quoted := make([]string, 2)
	for i, value := range []string{user, service} {
		if !utf8.ValidString(value) {
			return nil, fmt.Errorf("keychain account/service is not UTF-8")
		}
		for _, r := range value {
			if unicode.IsControl(r) || (unicode.IsSpace(r) && r != ' ') {
				return nil, fmt.Errorf("keychain account/service contains a control or unsupported whitespace character")
			}
		}
		// security -i is NOT a shell. Apple's split_line recognizes backslash
		// escapes inside either kind of quote; closing a quote finishes an arg.
		// https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/SecurityTool/macOS/security.c
		quoted[i] = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty keychain payload")
	}
	for _, b := range payload {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b == ':') {
			return nil, fmt.Errorf("invalid keychain payload encoding")
		}
	}
	line := fmt.Sprintf("add-generic-password -U -a %s -s %s -w %s\n", quoted[0], quoted[1], payload)
	// Apple's interactive reader has a 4096-byte buffer. Reject rather than
	// let a long command be split/truncated into a different command.
	if len(line) >= 4096 {
		return nil, fmt.Errorf("keychain command exceeds security's input limit")
	}
	cmd := exec.Command(bin, "-i")
	cmd.Stdin = strings.NewReader(line)
	return cmd, nil
}
