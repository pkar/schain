package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Linux: kernel user keyring via add_key(2)/keyctl(2). No daemon, no
// libsecret. Keys are held by the kernel, never touch disk, and vanish
// on reboot (or earlier with a TTL, or via `schain forget`).

const (
	keySpecUserKeyring = ^uintptr(3) // KEY_SPEC_USER_KEYRING (-4)

	keyctlUpdate     = 2
	keyctlUnlink     = 9
	keyctlSearch     = 10
	keyctlRead       = 11
	keyctlSetTimeout = 15
)

func keyDesc(vaultPath string) string { return "schain:" + vaultPath }

func cacheStore(vaultPath string, payload []byte, ttlSeconds int) error {
	typ, err := syscall.BytePtrFromString("user")
	if err != nil {
		return err
	}
	desc, err := syscall.BytePtrFromString(keyDesc(vaultPath))
	if err != nil {
		return err
	}
	id, _, errno := syscall.Syscall6(syscall.SYS_ADD_KEY,
		uintptr(unsafe.Pointer(typ)), uintptr(unsafe.Pointer(desc)),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		keySpecUserKeyring, 0)
	if errno != 0 {
		return fmt.Errorf("add_key: %v", errno)
	}
	if ttlSeconds > 0 {
		_, _, errno = syscall.Syscall6(syscall.SYS_KEYCTL,
			keyctlSetTimeout, id, uintptr(ttlSeconds), 0, 0, 0)
		if errno != 0 {
			return fmt.Errorf("keyctl set_timeout: %v", errno)
		}
	}
	return nil
}

func searchKey(vaultPath string) (uintptr, error) {
	typ, err := syscall.BytePtrFromString("user")
	if err != nil {
		return 0, err
	}
	desc, err := syscall.BytePtrFromString(keyDesc(vaultPath))
	if err != nil {
		return 0, err
	}
	id, _, errno := syscall.Syscall6(syscall.SYS_KEYCTL,
		keyctlSearch, keySpecUserKeyring,
		uintptr(unsafe.Pointer(typ)), uintptr(unsafe.Pointer(desc)), 0, 0)
	if errno != 0 {
		return 0, errNoCache
	}
	return id, nil
}

func cacheLoad(vaultPath string) ([]byte, error) {
	id, err := searchKey(vaultPath)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 256)
	n, _, errno := syscall.Syscall6(syscall.SYS_KEYCTL,
		keyctlRead, id, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 || int(n) > len(buf) {
		return nil, errNoCache
	}
	return buf[:n], nil
}

func cacheForget(vaultPath string) error {
	id, err := searchKey(vaultPath)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_KEYCTL,
		keyctlUnlink, id, keySpecUserKeyring, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("keyctl unlink: %v", errno)
	}
	return nil
}
