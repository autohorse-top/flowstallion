// Package secret implements AES-256-GCM encryption for pipeline secret
// values (P6②).
//
// The key comes from the FLOWSTALLION_SECRET_KEY environment variable: either 64
// hex characters or base64 (standard, with or without padding) of a 32-byte
// value. Encrypted blobs are stored in SQLite as nonce(12) || ciphertext ||
// tag(16). Plaintext values are only ever materialised in memory at step
// execution time and are never written to disk.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// ErrNoKey is returned when secret operations are attempted while no
// encryption key is configured.
var ErrNoKey = errors.New("secret: encryption key not configured (set FLOWSTALLION_SECRET_KEY)")

// Vault seals and opens secret values with an AES-256-GCM key.
type Vault struct {
	gcm cipher.AEAD
}

// KeyFromString decodes a 32-byte key from 64 hex characters or base64.
// It returns an error describing the accepted formats on failure.
func KeyFromString(s string) ([]byte, error) {
	if len(s) == 2*KeySize {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == KeySize {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == KeySize {
		return b, nil
	}
	return nil, fmt.Errorf("secret: FLOWSTALLION_SECRET_KEY must be 64 hex characters or base64 of a 32-byte key (got %d chars)", len(s))
}

// New creates a Vault from a 32-byte key.
func New(key []byte) (*Vault, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secret: key must be %d bytes (got %d)", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{gcm: gcm}, nil
}

// Seal encrypts plaintext and returns nonce||ciphertext||tag.
func (v *Vault) Seal(plaintext []byte) ([]byte, error) {
	if v == nil {
		return nil, ErrNoKey
	}
	ns := v.gcm.NonceSize()
	nonce := make([]byte, ns)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secret: generate nonce: %w", err)
	}
	// Seal appends ciphertext||tag to nonce (in place, extended).
	return v.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a blob produced by Seal.
func (v *Vault) Open(blob []byte) ([]byte, error) {
	if v == nil {
		return nil, ErrNoKey
	}
	ns := v.gcm.NonceSize()
	if len(blob) < ns+1 {
		return nil, errors.New("secret: blob too short")
	}
	out, err := v.gcm.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return nil, errors.New("secret: decrypt failed (wrong key or corrupted data)")
	}
	return out, nil
}
