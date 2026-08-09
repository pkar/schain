package main

import (
	"os"
	"path/filepath"
	"testing"
)

func testVaultPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.vault")
}

func TestRoundtrip(t *testing.T) {
	path := testVaultPath(t)
	pass := []byte("correct horse")

	v, err := newVault(pass)
	if err != nil {
		t.Fatal(err)
	}
	v.Secrets["API_TOKEN"] = "hunter2"
	v.Secrets["EMPTY"] = ""
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}

	got, err := openVault(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secrets["API_TOKEN"] != "hunter2" {
		t.Errorf("secret mismatch: %q", got.Secrets["API_TOKEN"])
	}
	if val, ok := got.Secrets["EMPTY"]; !ok || val != "" {
		t.Errorf("empty value not preserved")
	}
}

func TestWrongPassphrase(t *testing.T) {
	path := testVaultPath(t)
	v, err := newVault([]byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	v.Secrets["K"] = "v"
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := openVault(path, []byte("wrong")); err != errBadPassphrase {
		t.Errorf("want errBadPassphrase, got %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	path := testVaultPath(t)
	pass := []byte("p")
	v, err := newVault(pass)
	if err != nil {
		t.Fatal(err)
	}
	v.Secrets["K"] = "v"
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one bit in every byte position, one at a time; every mutation
	// must be rejected (magic mismatch, weak-iters guard, or AEAD failure).
	for i := range blob {
		mutated := append([]byte(nil), blob...)
		mutated[i] ^= 0x01
		mpath := path + ".m"
		if err := os.WriteFile(mpath, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openVault(mpath, pass); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
}

func TestTruncated(t *testing.T) {
	path := testVaultPath(t)
	if err := os.WriteFile(path, []byte(magic), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openVault(path, []byte("p")); err == nil {
		t.Fatal("truncated file accepted")
	}
}

func TestRekey(t *testing.T) {
	path := testVaultPath(t)
	v, err := newVault([]byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	v.Secrets["K"] = "v"
	oldSalt := append([]byte(nil), v.salt...)
	if err := v.rekey([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if string(oldSalt) == string(v.salt) {
		t.Error("salt not rotated on rekey")
	}
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := openVault(path, []byte("old")); err != errBadPassphrase {
		t.Errorf("old passphrase still works: %v", err)
	}
	got, err := openVault(path, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Secrets["K"] != "v" {
		t.Error("secrets lost on rekey")
	}
}

func TestCachePayloadRoundtrip(t *testing.T) {
	salt := make([]byte, saltLen)
	key := make([]byte, keyLen)
	for i := range key {
		key[i] = byte(i)
	}
	gotSalt, gotKey, expiry, err := parseCachePayload(cachePayload(salt, key))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotSalt) != string(salt) || string(gotKey) != string(key) || expiry != 0 {
		t.Error("cache payload roundtrip mismatch")
	}
	withExpiry := append(cachePayload(salt, key), ":1234567890"...)
	if _, _, expiry, err = parseCachePayload(withExpiry); err != nil || expiry != 1234567890 {
		t.Errorf("expiry parse: expiry=%d err=%v", expiry, err)
	}
	valid := string(cachePayload(salt, key))
	for _, bad := range []string{"", "nocolon", "zz:zz", "abcd:", valid + ":", valid + ":-5", valid + ":x", valid + ":1:2"} {
		if _, _, _, err := parseCachePayload([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestVaultFilePermissions(t *testing.T) {
	path := testVaultPath(t)
	v, err := newVault([]byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("vault perm = %o, want 600", perm)
	}
}
