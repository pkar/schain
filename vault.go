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
	"strconv"
	"strings"
	"time"
)

// File format (all bytes, big-endian ints):
//
//	magic   [8]  "schain1\n" or "schain2\n"
//	iters   [4]  PBKDF2-SHA256 iteration count
//	salt    [16] random, fixed per vault (rotated on passwd)
//	nonce   [12] random, fresh on every write
//	body    [..] AES-256-GCM ciphertext of the payload
//
// The payload is JSON: a bare map[string]string under schain1, and an
// envelope {"secrets":..., "history":...} under schain2. A vault is only
// written as schain2 once it actually holds history, so vaults with
// history switched off stay readable by older schain builds.
//
// The AEAD additional data covers magic+iters+salt, so tampering with
// KDF parameters is detected, not just tampering with the body.

const (
	magic        = "schain1\n"
	magic2       = "schain2\n"
	magicLen     = len(magic)
	saltLen      = 16
	nonceLen     = 12
	keyLen       = 32
	defaultIters = 600_000
	minIters     = 100_000
)

var errBadPassphrase = errors.New("wrong passphrase or corrupted vault")

// A revision is a value that was replaced: what it was, when it stopped
// being current, and who made that change.
type revision struct {
	At   int64  `json:"t"`
	Val  string `json:"v,omitempty"`
	By   string `json:"by,omitempty"`
	Gone bool   `json:"gone,omitempty"` // the key did not exist before
}

type vault struct {
	iters   int
	salt    []byte
	key     []byte // derived; kept for re-encryption on save
	Secrets map[string]string
	History map[string][]revision // per key, newest first
}

// envelope is the schain2 payload.
type envelope struct {
	Secrets map[string]string     `json:"secrets"`
	History map[string][]revision `json:"history,omitempty"`
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

func header(m string, iters int, salt []byte) []byte {
	h := make([]byte, 0, magicLen+4+saltLen)
	h = append(h, m...)
	h = binary.BigEndian.AppendUint32(h, uint32(iters))
	return append(h, salt...)
}

type vaultFile struct {
	magic             string
	iters             int
	salt, nonce, body []byte
	hdr               []byte
}

func readVaultFile(path string) (*vaultFile, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hdrLen := magicLen + 4 + saltLen
	if len(blob) < hdrLen+nonceLen+16 {
		return nil, fmt.Errorf("%s: not a schain vault", path)
	}
	m := string(blob[:magicLen])
	if m != magic && m != magic2 {
		if strings.HasPrefix(m, "schain") {
			return nil, fmt.Errorf("%s: format %q is newer than this schain understands; upgrade schain",
				path, strings.TrimSpace(m))
		}
		return nil, fmt.Errorf("%s: not a schain vault", path)
	}
	iters := int(binary.BigEndian.Uint32(blob[magicLen:]))
	if iters < minIters {
		return nil, fmt.Errorf("%s: refusing weak iteration count %d", path, iters)
	}
	return &vaultFile{
		magic: m,
		iters: iters,
		salt:  blob[magicLen+4 : hdrLen],
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
	if f.magic == magic2 {
		var env envelope
		if err = json.Unmarshal(plain, &env); err == nil && env.Secrets == nil {
			// A flat payload under a schain2 header: the AEAD binds the
			// magic, so this means the file was built by hand.
			err = errors.New("no secrets in envelope")
		}
		v.Secrets, v.History = env.Secrets, env.History
	} else {
		if err = json.Unmarshal(plain, &v.Secrets); err == nil && v.Secrets == nil {
			v.Secrets = map[string]string{}
		}
	}
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
	// Stay on the original format until there is history to store, so a
	// vault that never keeps one is still readable by older builds.
	m := magic
	var plain []byte
	var err error
	if len(v.History) > 0 {
		m = magic2
		plain, err = json.Marshal(envelope{Secrets: v.Secrets, History: v.History})
	} else {
		plain, err = json.Marshal(v.Secrets)
	}
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
	hdr := header(m, v.iters, v.salt)
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
	for _, revs := range v.History {
		for i := range revs {
			revs[i].Val = ""
		}
	}
}

// keep is how many past values this vault holds per key: the default
// unless SCHAIN_HISTORY says otherwise, 0 meaning history is off. The
// setting lives as a reserved key in the secrets map, so switching it off
// needs no format change.
func (v *vault) keep() int {
	s, ok := v.Secrets[historyKey]
	if !ok {
		return defaultHistory
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return defaultHistory
	}
	return n
}

// record pushes a key's current state onto its history, newest first. A
// key that does not exist yet is recorded as absent, so reverting to that
// point takes it back out.
func (v *vault) record(k string) {
	n := v.keep()
	if n == 0 || reserved[k] {
		return
	}
	r := revision{At: nowUnix(), By: changedBy()}
	if cur, ok := v.Secrets[k]; ok {
		r.Val = cur
	} else {
		r.Gone = true
	}
	if v.History == nil {
		v.History = map[string][]revision{}
	}
	h := append([]revision{r}, v.History[k]...)
	if len(h) > n {
		h = h[:n]
	}
	v.History[k] = h
}

// put sets a key, keeping the value it replaces. Rewriting the same value
// is not a change and is not recorded.
func (v *vault) put(k, val string) {
	if cur, ok := v.Secrets[k]; ok && cur == val {
		return
	}
	v.record(k)
	v.Secrets[k] = val
}

// drop removes a key, keeping its last value so it can be brought back.
func (v *vault) drop(k string) {
	v.record(k)
	delete(v.Secrets, k)
}

// changedBy labels a revision with who made it. Best effort: it is a
// convenience for shared vaults, not an identity claim.
func changedBy() string {
	user := os.Getenv("USER")
	host, _ := os.Hostname()
	switch {
	case user != "" && host != "":
		return user + "@" + host
	case user != "":
		return user
	}
	return host
}

// nowUnix is replaced in tests.
var nowUnix = func() int64 { return time.Now().Unix() }

func (v *vault) keys() []string {
	return sortedKeys(v.Secrets)
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
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
