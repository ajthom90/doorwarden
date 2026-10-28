// Package secrets provides a Secret type that redacts itself in every common
// formatting path, and a Box that encrypts secrets at rest with AES-256-GCM.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
)

const redacted = "[redacted]"

// Secret is a string that never reveals itself except through Reveal.
type Secret string

// Reveal returns the plaintext. It is the only way to read a Secret.
func (s Secret) Reveal() string { return string(s) }

// String implements fmt.Stringer.
func (Secret) String() string { return redacted }

// GoString implements fmt.GoStringer (%#v).
func (Secret) GoString() string { return redacted }

// Format implements fmt.Formatter so every verb prints the redaction.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MarshalYAML implements yaml.Marshaler (yaml.v3).
func (Secret) MarshalYAML() (any, error) { return redacted, nil }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// ErrDecrypt is returned by Box.Open for any failure to authenticate or parse.
var ErrDecrypt = errors.New("secrets: decryption failed")

const (
	versionV1 byte = 1
	minKeyLen      = 16
	hkdfInfo       = "proxypilot/secrets/aes-256-gcm/v1"
	nonceSize      = 12
	keySize        = 32
)

// Box seals and opens data with AES-256-GCM.
// Sealed format: version(1) || nonce(12) || ciphertext+tag.
type Box struct {
	aead cipher.AEAD
}

// NewBox derives an AES-256 key from masterKey using HKDF-SHA256.
func NewBox(masterKey string) (*Box, error) {
	if masterKey == "" {
		return nil, errors.New("secrets: master key is empty (set PROXYPILOT_MASTER_KEY)")
	}
	if len(masterKey) < minKeyLen {
		return nil, fmt.Errorf("secrets: master key too short: need at least %d bytes", minKeyLen)
	}
	key, err := hkdf.Key(sha256.New, []byte(masterKey), nil, hkdfInfo, keySize)
	if err != nil {
		return nil, fmt.Errorf("secrets: derive key: %w", err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithNonceSize(blk, nonceSize)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plain with a fresh random nonce.
func (b *Box) Seal(plain []byte) ([]byte, error) {
	out := make([]byte, 1+nonceSize, 1+nonceSize+len(plain)+b.aead.Overhead())
	out[0] = versionV1
	if _, err := rand.Read(out[1 : 1+nonceSize]); err != nil {
		return nil, fmt.Errorf("secrets: nonce: %w", err)
	}
	return b.aead.Seal(out, out[1:1+nonceSize], plain, out[:1]), nil
}

// Open decrypts data produced by Seal. Any failure returns ErrDecrypt.
func (b *Box) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < 1+nonceSize+b.aead.Overhead() || sealed[0] != versionV1 {
		return nil, ErrDecrypt
	}
	plain, err := b.aead.Open(nil, sealed[1:1+nonceSize], sealed[1+nonceSize:], sealed[:1])
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}
