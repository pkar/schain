package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRejectFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), vaultName)
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readVaultBytes(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("accepted FIFO")
		}
	case <-time.After(200 * time.Millisecond):
		// Release a blocked reader so a regression cannot leak a goroutine.
		f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		<-done
		t.Error("blocked opening FIFO before checking file type")
	}
}

func TestRejectOversizedVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), vaultName)
	blob := make([]byte, 16*1024*1024+1)
	copy(blob, magic)
	binary.BigEndian.PutUint32(blob[magicLen:], defaultIters)
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readVaultFile(path); err == nil {
		t.Fatal("accepted oversized vault")
	}
}

func TestVaultLimitBoundaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), vaultName)
	blob := make([]byte, maxVaultSize)
	copy(blob, magic)
	for _, n := range []uint32{minIters, defaultIters, maxIters} {
		binary.BigEndian.PutUint32(blob[magicLen:], n)
		if err := os.WriteFile(path, blob, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readVaultFile(path); err != nil {
			t.Errorf("boundary %d rejected: %v", n, err)
		}
	}
}

func TestOversizedSavePreservesVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), vaultName)
	v, err := newVault([]byte("synthetic-limit-pass"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v.Secrets["BIG"] = strings.Repeat("x", maxVaultSize)
	if err := v.save(path); err == nil {
		t.Fatal("oversized save accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("failed save changed vault")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".schain-tmp-*"))
	if err != nil || len(files) != 0 {
		t.Errorf("temporary files remain: %v %v", files, err)
	}
}

func TestRejectExcessiveKDFWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), vaultName)
	blob := make([]byte, magicLen+4+saltLen+nonceLen+16)
	copy(blob, magic)
	for _, n := range []uint32{10_000_001, ^uint32(0)} {
		binary.BigEndian.PutUint32(blob[magicLen:], n)
		if err := os.WriteFile(path, blob, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readVaultFile(path); err == nil {
			t.Errorf("accepted excessive iteration count %d", n)
		}
	}
}
