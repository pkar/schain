package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// macOS: login keychain via the system /usr/bin/security tool. Items are
// created and read through the same tool, so no GUI permission prompt.
// The keychain has no native TTL, so expiry is enforced two ways: an
// expiry timestamp inside the payload (checked, and the entry deleted,
// on next use) plus a detached sleeper process that deletes the item on
// schedule. The sleeper dies on reboot/logout; the embedded timestamp
// still holds, so schain never honors an expired entry either way.

const securityBin = "/usr/bin/security"

func keychainService(vaultPath string) string { return "schain:" + vaultPath }

func account() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "schain"
}

// cacheStore writes the payload via `security -i` (commands on stdin) so
// the secret never appears in an argv visible to `ps`. The payload is
// hex+colon only, so no quoting issues.
func cacheStore(vaultPath string, payload []byte, ttlSeconds int) error {
	if ttlSeconds > 0 {
		payload = append(append([]byte{}, payload...),
			fmt.Sprintf(":%d", time.Now().Unix()+int64(ttlSeconds))...)
	}
	cmd := exec.Command(securityBin, "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(
		"add-generic-password -U -a %s -s %s -w %s\n",
		account(), keychainService(vaultPath), payload))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain store failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if ttlSeconds > 0 {
		scheduleDelete(vaultPath, ttlSeconds)
	}
	return nil
}

// scheduleDelete spawns a detached sleeper that removes the keychain
// item when the TTL elapses. Best effort: it does not survive reboot,
// but the embedded expiry timestamp covers that case.
func scheduleDelete(vaultPath string, ttlSeconds int) {
	quoted := "'" + strings.ReplaceAll(keychainService(vaultPath), "'", `'\''`) + "'"
	script := fmt.Sprintf("sleep %d; %s delete-generic-password -s %s >/dev/null 2>&1",
		ttlSeconds, securityBin, quoted)
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err == nil {
		cmd.Process.Release()
	}
}

func cacheLoad(vaultPath string) ([]byte, error) {
	out, err := exec.Command(securityBin,
		"find-generic-password", "-s", keychainService(vaultPath), "-w").Output()
	if err != nil {
		return nil, errNoCache
	}
	return []byte(strings.TrimSpace(string(out))), nil
}

func cacheForget(vaultPath string) error {
	err := exec.Command(securityBin,
		"delete-generic-password", "-s", keychainService(vaultPath)).Run()
	if err != nil {
		return errNoCache
	}
	return nil
}
