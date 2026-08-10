package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Linux: kernel user keyring via add_key(2)/keyctl(2). No daemon, no
// libsecret. Keys are held by the kernel, never touch disk, and vanish
// on reboot (or earlier with a TTL, or via `schain forget`).
//
// The user keyring is per uid and outlives any one login session, which
// is what a service or a second `container exec` needs. Reaching it is
// only half the job: see keyPerm.

const (
	keySpecUserKeyring = ^uintptr(3) // KEY_SPEC_USER_KEYRING (-4)

	keyctlSetPerm    = 5
	keyctlUnlink     = 9
	keyctlSearch     = 10
	keyctlRead       = 11
	keyctlSetTimeout = 15

	// KEY_POS_ALL | KEY_USR_ALL. add_key grants the owning uid
	// KEY_USR_VIEW and nothing else: reading, updating and searching all
	// ride on possession, and possession comes from the session keyring.
	// A key cached in one session is then findable and unreadable from
	// the next, which is exactly the unattended case `remember` exists
	// for. Widening it to the uid means any process running as this user
	// can open the vault until `schain forget`.
	keyPerm = 0x3f3f0000
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
		return keyringErr("add_key", errno)
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_KEYCTL,
		keyctlSetPerm, id, keyPerm, 0, 0, 0); errno != 0 {
		return keyringErr("keyctl setperm", errno)
	}
	if ttlSeconds > 0 {
		_, _, errno = syscall.Syscall6(syscall.SYS_KEYCTL,
			keyctlSetTimeout, id, uintptr(ttlSeconds), 0, 0, 0)
		if errno != 0 {
			return keyringErr("keyctl set_timeout", errno)
		}
	}
	return nil
}

// keyringErr names the failures worth explaining: a sandbox that blocks
// the syscalls outright, a keyring cached by a schain that predates the
// permission widening above, and a full quota.
func keyringErr(op string, errno syscall.Errno) error {
	switch errno {
	case syscall.EPERM, syscall.ENOSYS:
		return fmt.Errorf("%s: %v (no kernel keyring here; container runtimes commonly block add_key and keyctl, so `remember` cannot cache anything)", op, errno)
	case syscall.EACCES:
		return fmt.Errorf("%s: %v (a key cached by schain 0.0.7 or older can only be used from the session that cached it; `schain forget` there, then remember again)", op, errno)
	case syscall.EDQUOT:
		return fmt.Errorf("%s: %v (keyring quota is full; see /proc/sys/kernel/keys/maxkeys)", op, errno)
	}
	return fmt.Errorf("%s: %v", op, errno)
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
		return keyringErr("keyctl unlink", errno)
	}
	return nil
}
