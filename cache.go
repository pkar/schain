package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The remember cache stores hex(salt):hex(derived key)[:expiry-unix] in
// an OS-level store: the login keychain on macOS, the kernel user
// keyring on Linux. The passphrase itself is never cached. A cached key
// is bound to the vault's salt, so `schain passwd` (which rotates the
// salt) makes any stale cache entry useless and schain falls back to
// prompting. Both platforms embed an expiry for positive TTLs; Linux
// additionally enforces the timeout in the kernel.

var errNoCache = errors.New("no cached key")

// Indirection points for tests.
var (
	storeCache  = cacheStore
	forgetCache = cacheForget
)

// payloadWithExpiry bounds TTLs before OS conversion and embeds a deadline
// on both platforms. Linux still enforces its kernel timeout; the embedded
// deadline is a second line of defense if configuration/rollback fails.
func payloadWithExpiry(payload []byte, ttlSeconds int) ([]byte, error) {
	if ttlSeconds < 0 || int64(ttlSeconds) > 1<<31-1 {
		return nil, fmt.Errorf("cache TTL must be between 0 and %d seconds", int64(1<<31-1))
	}
	if ttlSeconds == 0 {
		return append([]byte(nil), payload...), nil
	}
	return append(append([]byte(nil), payload...), fmt.Sprintf(":%d", time.Now().Unix()+int64(ttlSeconds))...), nil
}

func cachePayload(salt, key []byte) []byte {
	return []byte(hex.EncodeToString(salt) + ":" + hex.EncodeToString(key))
}

func parseCachePayload(p []byte) (salt, key []byte, expiry int64, err error) {
	parts := strings.Split(string(p), ":")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, nil, 0, fmt.Errorf("malformed cache entry")
	}
	if salt, err = hex.DecodeString(parts[0]); err != nil {
		return nil, nil, 0, err
	}
	if key, err = hex.DecodeString(parts[1]); err != nil {
		return nil, nil, 0, err
	}
	if len(salt) != saltLen || len(key) != keyLen {
		return nil, nil, 0, fmt.Errorf("malformed cache entry")
	}
	if len(parts) == 3 {
		if expiry, err = strconv.ParseInt(parts[2], 10, 64); err != nil || expiry <= 0 {
			return nil, nil, 0, fmt.Errorf("malformed cache entry")
		}
	}
	return salt, key, expiry, nil
}

// tryCache attempts to open the vault with a cached key. Any failure
// (no entry, expired, stale salt, tampering) just means "prompt
// instead". Cache entries are keyed by the vault's absolute path.
func tryCache(path string) *vault {
	payload, err := cacheLoad(path)
	if err != nil {
		return nil
	}
	salt, key, expiry, err := parseCachePayload(payload)
	wipe(payload)
	if err != nil {
		return nil
	}
	if expiry > 0 && time.Now().Unix() >= expiry {
		wipe(key)
		cacheForget(path)
		return nil
	}
	v, err := openVaultKey(path, salt, key)
	if err != nil {
		wipe(key)
		return nil
	}
	return v
}
