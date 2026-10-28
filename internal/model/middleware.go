package model

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidMiddlewareRef is wrapped when a middleware reference is not of
// the form name[@provider] with name and provider made of [A-Za-z0-9_.-].
var ErrInvalidMiddlewareRef = errors.New("invalid middleware reference")

// ErrUndefinedMiddleware is wrapped when a middleware reference resolves to
// no definition and is not allowlisted.
var ErrUndefinedMiddleware = errors.New("undefined middleware")

func mwChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// ValidMiddlewareName reports whether n is a usable middleware DEFINITION
// name: non-empty, [A-Za-z0-9_.-] only (no "@provider" suffix).
func ValidMiddlewareName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !mwChar(n[i]) {
			return false
		}
	}
	return true
}

// ParseMiddlewareRef splits a Traefik middleware reference "name" or
// "name@provider". Both parts must be ValidMiddlewareName; provider is ""
// for an unqualified reference.
func ParseMiddlewareRef(ref string) (name, provider string, err error) {
	name, provider, qualified := strings.Cut(ref, "@")
	if !ValidMiddlewareName(name) || (qualified && !ValidMiddlewareName(provider)) {
		return "", "", fmt.Errorf("%w %q: must be name[@provider] using [A-Za-z0-9_.-]", ErrInvalidMiddlewareRef, ref)
	}
	return name, provider, nil
}

// qualified returns ref in "name@provider" form; an unqualified reference
// from a file-provider router means "@file".
func qualified(name, provider string) string {
	if provider == "" {
		provider = "file"
	}
	return name + "@" + provider
}

// CheckMiddlewareRef reports whether ref, used by a doorwarden (file
// provider) router, resolves. An unqualified or "@file" reference resolves
// when defined(name) is true. Any reference also resolves when its qualified
// form ("x" counts as "x@file") is listed in external, the allowlist for
// middlewares defined outside doorwarden (another provider, or a hand-written
// file). Everything else wraps ErrUndefinedMiddleware (or
// ErrInvalidMiddlewareRef for a malformed reference): callers fail closed.
func CheckMiddlewareRef(ref string, defined func(name string) bool, external []string) error {
	name, provider, err := ParseMiddlewareRef(ref)
	if err != nil {
		return err
	}
	if (provider == "" || provider == "file") && defined != nil && defined(name) {
		return nil
	}
	q := qualified(name, provider)
	for _, e := range external {
		if e == q {
			return nil
		}
	}
	return fmt.Errorf("%w %q: not defined in middlewares and not listed in external_middlewares", ErrUndefinedMiddleware, ref)
}

// ValidateExternalMiddleware checks an allowlist entry: it must be a valid,
// provider-QUALIFIED reference ("name@provider").
func ValidateExternalMiddleware(ref string) error {
	_, provider, err := ParseMiddlewareRef(ref)
	if err != nil {
		return err
	}
	if provider == "" {
		return fmt.Errorf("%w %q: external middlewares must be qualified as name@provider", ErrInvalidMiddlewareRef, ref)
	}
	return nil
}

// ValidateMiddlewareDef checks a middleware definition rendered verbatim
// under Traefik's http.middlewares.<name>: a mapping with exactly one key
// (the middleware type, [A-Za-z0-9]+, e.g. basicAuth) whose value is a
// mapping (possibly empty). The type itself is not checked against a list.
func ValidateMiddlewareDef(def any) error {
	var typ any
	var val any
	switch m := def.(type) {
	case map[string]any:
		if len(m) != 1 {
			return fmt.Errorf("definition must have exactly one middleware type key, got %d", len(m))
		}
		for k, v := range m {
			typ, val = k, v
		}
	case map[any]any:
		if len(m) != 1 {
			return fmt.Errorf("definition must have exactly one middleware type key, got %d", len(m))
		}
		for k, v := range m {
			typ, val = k, v
		}
	default:
		return fmt.Errorf("definition must be a mapping of one middleware type to its options, got %T", def)
	}
	ts, ok := typ.(string)
	if !ok || ts == "" {
		return fmt.Errorf("middleware type %v must be a non-empty string", typ)
	}
	for i := 0; i < len(ts); i++ {
		c := ts[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return fmt.Errorf("middleware type %q must be [A-Za-z0-9]+", ts)
		}
	}
	switch val.(type) {
	case map[string]any, map[any]any:
		return nil
	}
	return fmt.Errorf("middleware type %q: options must be a mapping, got %T", ts, val)
}
