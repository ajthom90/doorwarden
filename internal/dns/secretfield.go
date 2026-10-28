package dns

import (
	"fmt"
	"strings"

	"github.com/ajthom90/doorwarden/internal/secrets"
)

// SecretPrefix marks a config string as a secret reference.
const SecretPrefix = "secret:"

// ResolveField reads the secret-flagged config field name from cfg.
//
//   - missing, non-string or empty => error naming the field (never the value)
//   - plain string => literal (also when sr == nil)
//   - "secret:<ref>" => sr.Resolve(ref); error if sr is nil (a reference
//     cannot be honoured without a resolver)
//
// Every provider must use it for each Secret schema field.
func ResolveField(cfg map[string]any, sr SecretResolver, name string) (secrets.Secret, error) {
	v, ok := cfg[name]
	if !ok || v == nil {
		return "", fmt.Errorf("config field %q is required", name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("config field %q must be a string", name)
	}
	if s == "" {
		return "", fmt.Errorf("config field %q is required", name)
	}
	if ref, isRef := strings.CutPrefix(s, SecretPrefix); isRef {
		if sr == nil {
			return "", fmt.Errorf("config field %q: secret reference given but no secret resolver is available", name)
		}
		if ref == "" {
			return "", fmt.Errorf("config field %q: empty secret reference", name)
		}
		sec, err := sr.Resolve(ref)
		if err != nil {
			return "", fmt.Errorf("config field %q: resolve secret reference: %w", name, err)
		}
		return sec, nil
	}
	return secrets.Secret(s), nil
}
