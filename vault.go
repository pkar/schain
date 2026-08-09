package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// File format (all bytes, big-endian ints):
//
//	magic   [8]  "schain1\n"
//	iters   [4]  PBKDF2-SHA256 iteration count
//	salt    [16] random, fixed per vault (rotated on passwd)
//	nonce   [12] random, fresh on every write
//	body    [..] AES-256-GCM ciphertext of JSON map[string]string
//
// The AEAD additional data covers magic+iters+salt, so tampering with
// KDF parameters is detected, not just tampering with the body.

const (
	magic        = "schain1\n"
	saltLen      = 16
	nonceLen     = 12
	keyLen       = 32
	defaultIters = 600_000
	minIters     = 100_000
)

var errBadPassphrase = errors.New("wrong passphrase or corrupted vault")

type vault struct {
	iters   int
	salt    []byte
	key     []byte // derived; kept for re-encryption on save
	Secrets map[string]string
}

func deriveKey(passphrase []byte, salt []byte, iters int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(passphrase), salt, iters, keyLen)
}

func newVault(passphrase []byte) (*vault, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := deriveKey(passphrase, salt, defaultIters)
	if err != nil {
		return nil, err
	}
	return &vault{iters: defaultIters, salt: salt, key: key, Secrets: map[string]string{}}, nil
}

func header(iters int, salt []byte) []byte {
	h := make([]byte, 0, len(magic)+4+saltLen)
	h = append(h, magic...)
	h = binary.BigEndian.AppendUint32(h, uint32(iters))
	return append(h, salt...)
}

type vaultFile struct {
	iters             int
	salt, nonce, body []byte
	hdr               []byte
}

func readVaultFile(path string) (*vaultFile, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hdrLen := len(magic) + 4 + saltLen
	if len(blob) < hdrLen+nonceLen+16 || string(blob[:len(magic)]) != magic {
		return nil, fmt.Errorf("%s: not a schain vault", path)
	}
	iters := int(binary.BigEndian.Uint32(blob[len(magic):]))
	if iters < minIters {
		return nil, fmt.Errorf("%s: refusing weak iteration count %d", path, iters)
	}
	return &vaultFile{
		iters: iters,
		salt:  blob[len(magic)+4 : hdrLen],
		nonce: blob[hdrLen : hdrLen+nonceLen],
		body:  blob[hdrLen+nonceLen:],
		hdr:   blob[:hdrLen],
	}, nil
}

func decrypt(f *vaultFile, key []byte, path string) (*vault, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, f.nonce, f.body, f.hdr)
	if err != nil {
		wipe(key)
		return nil, errBadPassphrase
	}
	v := &vault{iters: f.iters, salt: append([]byte(nil), f.salt...), key: key}
	err = json.Unmarshal(plain, &v.Secrets)
	wipe(plain)
	if err != nil {
		wipe(key)
		return nil, fmt.Errorf("%s: corrupted payload: %w", path, err)
	}
	return v, nil
}

func openVault(path string, passphrase []byte) (*vault, error) {
	f, err := readVaultFile(path)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(passphrase, f.salt, f.iters)
	if err != nil {
		return nil, err
	}
	return decrypt(f, key, path)
}

// openVaultKey opens with an already-derived key, bound to a salt. If the
// vault's salt differs (rekeyed since caching) the key is rejected.
func openVaultKey(path string, salt, key []byte) (*vault, error) {
	f, err := readVaultFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(salt, f.salt) {
		return nil, errBadPassphrase
	}
	return decrypt(f, key, path)
}

func (v *vault) save(path string) error {
	plain, err := json.Marshal(v.Secrets)
	if err != nil {
		return err
	}
	defer wipe(plain)
	aead, err := newAEAD(v.key)
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	hdr := header(v.iters, v.salt)
	out := append(append(hdr, nonce...), aead.Seal(nil, nonce, plain, hdr)...)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// rekey derives a fresh key from a new passphrase with a new salt.
func (v *vault) rekey(passphrase []byte) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key, err := deriveKey(passphrase, salt, defaultIters)
	if err != nil {
		return err
	}
	wipe(v.key)
	v.iters, v.salt, v.key = defaultIters, salt, key
	return nil
}

func (v *vault) close() {
	wipe(v.key)
	for k := range v.Secrets {
		v.Secrets[k] = ""
	}
}

func (v *vault) keys() []string {
	ks := make([]string, 0, len(v.Secrets))
	for k := range v.Secrets {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// wipe is best-effort clearing of key material. Go's GC may have copied
// the data; this narrows the window, it does not eliminate it.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

