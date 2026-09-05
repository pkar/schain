package main

import (
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestKeyringErrorDoesNotDenyPartialStore(t *testing.T) {
	for _, op := range []string{"keyctl setperm", "keyctl set_timeout", "rollback revoke", "rollback unlink"} {
		err := keyringErr(op, syscall.EPERM)
		if strings.Contains(err.Error(), "cannot cache anything") || strings.Contains(err.Error(), "no kernel keyring here") {
			t.Errorf("misleading post-insertion error: %v", err)
		}
	}
}

func TestCacheStoreExpiryDefense(t *testing.T) {
	oldAdd, oldCtl := cacheAddKey, cacheKeyctl
	t.Cleanup(func() { cacheAddKey, cacheKeyctl = oldAdd, oldCtl })
	original := cachePayload(make([]byte, saltLen), make([]byte, keyLen))
	before := time.Now().Unix()
	var stored []byte
	cacheAddKey = func(_ string, p []byte) (uintptr, error) { stored = append([]byte(nil), p...); return 123, nil }
	cacheKeyctl = func(op, id, arg uintptr) syscall.Errno { return syscall.EACCES }
	if err := cacheStore("/synthetic", original, 60); err == nil {
		t.Fatal("want error")
	}
	_, key, expiry, err := parseCachePayload(stored)
	defer wipe(key)
	if err != nil || expiry < before+60 || expiry > time.Now().Unix()+60 {
		t.Fatalf("missing embedded expiry on cleanup failure: expiry %d, err %v", expiry, err)
	}
	if strings.Count(string(original), ":") != 1 {
		t.Fatal("mutated caller payload")
	}
}

func TestCacheStoreRejectsInvalidTTL(t *testing.T) {
	oldAdd := cacheAddKey
	t.Cleanup(func() { cacheAddKey = oldAdd })
	cacheAddKey = func(_ string, _ []byte) (uintptr, error) { t.Fatal("invalid TTL reached add_key"); return 0, nil }
	invalid := []int{-1}
	if maxInt := int(^uint(0) >> 1); int64(maxInt) > 1<<31-1 {
		invalid = append(invalid, maxInt)
	}
	for _, ttl := range invalid {
		if err := cacheStore("/synthetic", []byte("ab:cd"), ttl); err == nil {
			t.Fatalf("accepted TTL %d", ttl)
		}
	}
}

func TestCacheStoreRollback(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		failOp               uintptr
		addFail, cleanupFail bool
		ttl                  int
		want                 []uintptr
	}{
		{"setperm failure", keyctlSetPerm, false, false, 60, []uintptr{5, 3, 9}},
		{"timeout failure", keyctlSetTimeout, false, false, 60, []uintptr{5, 15, 3, 9}},
		{"cleanup failure reported", keyctlSetTimeout, false, true, 60, []uintptr{5, 15, 3, 9}},
		{"add failure", 0, true, false, 60, nil},
		{"success with TTL", 0, false, false, 60, []uintptr{5, 15}},
		{"success without TTL", 0, false, false, 0, []uintptr{5, 15}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldAdd, oldCtl := cacheAddKey, cacheKeyctl
			t.Cleanup(func() { cacheAddKey, cacheKeyctl = oldAdd, oldCtl })
			cacheAddKey = func(path string, payload []byte) (uintptr, error) {
				if path != "/synthetic/vault" || strings.Split(string(payload), ":")[0] != "synthetic" {
					t.Fatal("wrong add arguments")
				}
				if tc.addFail {
					return 0, fmt.Errorf("synthetic add failure")
				}
				return 123, nil
			}
			var ops []uintptr
			cacheKeyctl = func(op, id, arg uintptr) syscall.Errno {
				if id != 123 {
					t.Fatalf("wrong key ID %d", id)
				}
				ops = append(ops, op)
				if op == keyctlSetTimeout && arg != uintptr(tc.ttl) {
					t.Fatalf("wrong timeout %d", arg)
				}
				if op == keyctlUnlink && arg != keySpecUserKeyring {
					t.Fatal("wrong rollback ring")
				}
				if op == tc.failOp || (tc.cleanupFail && (op == 3 || op == 9)) {
					return syscall.EACCES
				}
				return 0
			}
			err := cacheStore("/synthetic/vault", []byte("synthetic"), tc.ttl)
			if (err != nil) != (tc.addFail || tc.failOp != 0) {
				t.Fatalf("error = %v", err)
			}
			if !reflect.DeepEqual(ops, tc.want) {
				t.Fatalf("operations = %v; want %v", ops, tc.want)
			}
			if tc.cleanupFail && (!strings.Contains(err.Error(), "revoke") || !strings.Contains(err.Error(), "unlink")) {
				t.Fatalf("missing rollback errors: %v", err)
			}
		})
	}
}
