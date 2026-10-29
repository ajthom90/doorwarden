package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

// SecretKVPrefix starts the kv key of every stored secret: a config value
// "secret:<name>" resolves to kv SecretKVPrefix+<name>, which holds
// base64(Box.Seal(plaintext)).
const SecretKVPrefix = "secrets/"

// ErrSecretNotFound: no secret is stored under the reference.
var ErrSecretNotFound = errors.New("secret not found")

// KV is the key/value part of the store (*store.Store implements it).
type KV interface {
	GetSetting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
	DeleteSetting(ctx context.Context, key string) error
}

// SecretStore keeps secrets encrypted at rest (AES-256-GCM under the master
// key) in the store's kv table and resolves "secret:" references. It
// implements dns.SecretResolver. Errors name the reference, never a value.
type SecretStore struct {
	KV  KV
	Box *secrets.Box
	// Timeout bounds one store read in Resolve (0 means 5s).
	Timeout time.Duration
}

var _ dns.SecretResolver = (*SecretStore)(nil)

// ValidSecretName reports whether n can name a stored secret: 1-128 of
// [A-Za-z0-9._-].
func ValidSecretName(n string) bool { return validSecretName(n) }

func validSecretName(n string) bool {
	if n == "" || len(n) > 128 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// Put stores value under name (sealed).
func (s *SecretStore) Put(ctx context.Context, name string, value secrets.Secret) error {
	if !validSecretName(name) {
		return fmt.Errorf("secret name %q must be 1-128 of [A-Za-z0-9._-]", name)
	}
	if s == nil || s.Box == nil || s.KV == nil {
		return errors.New("secrets: no master key configured")
	}
	sealed, err := s.Box.Seal([]byte(value.Reveal()))
	if err != nil {
		return err
	}
	return s.KV.SetSetting(ctx, SecretKVPrefix+name, base64.StdEncoding.EncodeToString(sealed))
}

// Delete removes the secret stored under name (absent is not an error).
func (s *SecretStore) Delete(ctx context.Context, name string) error {
	if s == nil || s.KV == nil {
		return errors.New("secrets: no store")
	}
	return s.KV.DeleteSetting(ctx, SecretKVPrefix+name)
}

// Resolve implements dns.SecretResolver: ref is the part after "secret:".
func (s *SecretStore) Resolve(ref string) (secrets.Secret, error) {
	if !validSecretName(ref) {
		return "", fmt.Errorf("secret reference %q is not a valid name", ref)
	}
	if s == nil || s.Box == nil || s.KV == nil {
		return "", fmt.Errorf("secret %q: no master key configured (set DOORWARDEN_MASTER_KEY)", ref)
	}
	to := s.Timeout
	if to <= 0 {
		to = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	v, ok, err := s.KV.GetSetting(ctx, SecretKVPrefix+ref)
	if err != nil {
		return "", fmt.Errorf("secret %q: reading the store: %w", ref, err)
	}
	if !ok {
		return "", fmt.Errorf("secret %q: %w", ref, ErrSecretNotFound)
	}
	sealed, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", fmt.Errorf("secret %q: %w", ref, secrets.ErrDecrypt)
	}
	plain, err := s.Box.Open(sealed)
	if err != nil {
		return "", fmt.Errorf("secret %q: %w", ref, err)
	}
	return secrets.Secret(plain), nil
}

// Value resolves a config string: "secret:<name>" through Resolve, anything
// else as a literal.
func (s *SecretStore) Value(raw string) (secrets.Secret, error) {
	if ref, ok := strings.CutPrefix(raw, dns.SecretPrefix); ok {
		return s.Resolve(ref)
	}
	return secrets.Secret(raw), nil
}

// SettingValue is acme.ManagerConfig.SettingValue: a string "secret:<name>"
// is resolved; other strings and scalars pass as text.
func (s *SecretStore) SettingValue(raw any) (string, error) {
	switch v := raw.(type) {
	case string:
		sec, err := s.Value(v)
		if err != nil {
			return "", err
		}
		return sec.Reveal(), nil
	case nil:
		return "", nil
	case bool, int, int64, float64, uint64:
		return fmt.Sprint(v), nil
	}
	return "", fmt.Errorf("unsupported value type %T", raw)
}
