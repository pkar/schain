package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveIgnoresPreexistingTemporaryEntries(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "loose-file", true: "symlink"}[symlink], func(t *testing.T) {
			dir := t.TempDir()
			path, target := filepath.Join(dir, vaultName), filepath.Join(dir, "unrelated")
			if err := os.WriteFile(target, []byte("sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			if symlink {
				if err := os.Symlink(target, path+".tmp"); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path+".tmp", nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path+".tmp", 0666); err != nil {
					t.Fatal(err)
				}
			}
			v, err := newVault([]byte("synthetic-test-passphrase"))
			if err != nil {
				t.Fatal(err)
			}
			defer v.close()
			if err := v.save(path); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != "sentinel" {
				t.Error("unrelated file overwritten")
			}
			fi, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 {
				t.Errorf("unsafe final mode %v", fi.Mode())
			}
		})
	}
}
