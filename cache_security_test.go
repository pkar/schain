package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityStoreCommandQuotes(t *testing.T) {
	user := `user ' " \\ name`
	service := `schain:/Users/a b/"quoted"/'single'/\\/.schain`
	payload := []byte("abcd:1234")
	cmd, err := securityStoreCommand("/usr/bin/security", user, service, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cmd.Args, []string{"/usr/bin/security", "-i"}) {
		t.Fatalf("secret or metadata in argv: %v", cmd.Args)
	}
	input, err := io.ReadAll(cmd.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	// Apple's split_line consumes backslash escapes inside double quotes;
	// unlike shell quoting, adjacent quoted fragments become separate args.
	want := "add-generic-password -U -a \"user ' \\\" \\\\\\\\ name\" -s \"schain:/Users/a b/\\\"quoted\\\"/'single'/\\\\\\\\/.schain\" -w abcd:1234\n"
	if string(input) != want {
		t.Fatalf("stdin = %q; want %q", input, want)
	}
}

// Optional source-parser verification, NOT native macOS keychain coverage.
// Set SCHAIN_TEST_APPLE_PARSER to a driver of Apple's unmodified split_line
// that reads stdin and writes each parsed argument followed by a NUL byte.
func TestSecurityStoreAppleParser(t *testing.T) {
	parser := os.Getenv("SCHAIN_TEST_APPLE_PARSER")
	if parser == "" {
		t.Skip("Apple source-parser driver unavailable; native macOS not tested")
	}
	values := []string{"", "plain", "space name", `single'quote`, `double"quote`, `back\slash`, `end\`, `a' " \\ b`, "é 日本語", "-w injected; $(ignored)"}
	for _, user := range values {
		for _, service := range values {
			cmd, err := securityStoreCommand("/usr/bin/security", user, service, []byte("ab:cd:123"))
			if err != nil {
				t.Fatal(err)
			}
			driver := exec.Command(parser)
			driver.Stdin = cmd.Stdin
			out, err := driver.Output()
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"add-generic-password", "-U", "-a", user, "-s", service, "-w", "ab:cd:123"}
			got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Apple split_line: got %q want %q", got, want)
			}
		}
	}
}

func TestSecurityStoreCommandRejectsUnsafeInput(t *testing.T) {
	for _, bad := range []string{"a\nb", "a\rb", "a\x00b", "a\tb", "a\x7fb", "a\u0085b", "a\u2028b", string([]byte{0xff}), strings.Repeat("x", 4096)} {
		for _, field := range []string{"user", "service"} {
			t.Run(fmt.Sprintf("%s/%q", field, bad[:min(len(bad), 20)]), func(t *testing.T) {
				user, service := "user", "schain:/safe"
				if field == "user" {
					user = bad
				} else {
					service = bad
				}
				cmd, err := securityStoreCommand("/usr/bin/security", user, service, []byte("ab:cd"))
				if err == nil || cmd != nil {
					t.Fatal("accepted unsafe input")
				}
			})
		}
	}
	for _, payload := range []string{"", "ab:cd\nquit", `ab:cd -a other`, `ab:cd"`, "zz:cd"} {
		if cmd, err := securityStoreCommand("/usr/bin/security", "user", "schain:/safe", []byte(payload)); err == nil || cmd != nil {
			t.Errorf("accepted payload %q", payload)
		}
	}
}
