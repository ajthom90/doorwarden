package model

import (
	"errors"
	"fmt"
	"sort"
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
// Traefik's file provider matches keys case-insensitively (stated from
// memory, not verified against its source), so "Chain"/"CHAIN" is a chain
// and its "Middlewares" key is looked up ignoring case; keys that differ
// only by case (at the top level or in a chain's options) are rejected.
func ValidateMiddlewareDef(def any) error {
	var typ any
	var val any
	switch m := def.(type) {
	case map[string]any:
		if err := noCaseDupKeys(m); err != nil {
			return fmt.Errorf("definition: %w", err)
		}
		if len(m) != 1 {
			return fmt.Errorf("definition must have exactly one middleware type key, got %d", len(m))
		}
		for k, v := range m {
			typ, val = k, v
		}
	case map[any]any:
		if err := noCaseDupKeys(m); err != nil {
			return fmt.Errorf("definition: %w", err)
		}
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
	default:
		return fmt.Errorf("middleware type %q: options must be a mapping, got %T", ts, val)
	}
	if err := noTemplates(val); err != nil {
		return fmt.Errorf("middleware type %q: %w", ts, err)
	}
	// Traefik's file provider matches keys case-insensitively, so "Chain"
	// and "CHAIN" are chains too and get the same member checks.
	if strings.EqualFold(ts, "chain") {
		if _, err := chainMembers(val); err != nil {
			return err
		}
	}
	return nil
}

// noTemplates rejects "{{" or "}}" in any string key or value: Traefik runs
// Go templating over file-provider files, so such text would break (or be
// interpreted in) the whole generated file.
func noTemplates(v any) error {
	bad := func(s string) bool { return strings.Contains(s, "{{") || strings.Contains(s, "}}") }
	switch x := v.(type) {
	case string:
		if bad(x) {
			return fmt.Errorf("value %q contains {{ or }} (Traefik templating)", x)
		}
	case map[string]any:
		for k, e := range x {
			if bad(k) {
				return fmt.Errorf("key %q contains {{ or }} (Traefik templating)", k)
			}
			if err := noTemplates(e); err != nil {
				return err
			}
		}
	case map[any]any:
		for k, e := range x {
			if err := noTemplates(k); err != nil {
				return err
			}
			if err := noTemplates(e); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range x {
			if err := noTemplates(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// chainMembers returns the middleware references of a chain's options
// ({middlewares: [ref, ...]}, non-empty, each a valid reference).
func chainMembers(opts any) ([]string, error) {
	raw, found, err := foldLookup(opts, "middlewares")
	if err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	if !found {
		return nil, errors.New("chain: middlewares must be a non-empty list of middleware references")
	}
	list, ok := raw.([]any)
	if ss, isStrs := raw.([]string); isStrs {
		for _, s := range ss {
			list = append(list, s)
		}
		ok = true
	}
	if !ok || len(list) == 0 {
		return nil, errors.New("chain: middlewares must be a non-empty list of middleware references")
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, isStr := e.(string)
		if !isStr {
			return nil, fmt.Errorf("chain: member %v is not a string", e)
		}
		if _, _, err := ParseMiddlewareRef(s); err != nil {
			return nil, fmt.Errorf("chain: %w", err)
		}
		out = append(out, s)
	}
	return out, nil
}

// ValidateMiddlewareDefs validates a whole set of definitions and returns
// the names that are usable (valid) and a problem for every other name. A
// definition is valid when its name passes ValidMiddlewareName, it passes
// ValidateMiddlewareDef, and, for a chain, every member resolves
// (CheckMiddlewareRef) to a VALID definition or an allowlisted external
// reference, with no chain cycle. This is the single rule config
// validation, the reconcile plan and the Traefik renderer share.
func ValidateMiddlewareDefs(defs map[string]any, external []string) (valid map[string]bool, problems map[string]error) {
	valid, problems = map[string]bool{}, map[string]error{}
	members := map[string][]string{}
	for n, d := range defs {
		if !ValidMiddlewareName(n) {
			problems[n] = fmt.Errorf("definition name %q must be [A-Za-z0-9_.-]+ (no @provider)", n)
			continue
		}
		if err := ValidateMiddlewareDef(d); err != nil {
			problems[n] = err
			continue
		}
		valid[n] = true
		if m, ok := chainOpts(d); ok {
			members[n], _ = chainMembers(m)
		}
	}
	defined := func(n string) bool { return valid[n] }
	for changed := true; changed; {
		changed = false
		names := make([]string, 0, len(members))
		for n := range members {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if !valid[n] {
				continue
			}
			for _, ref := range members[n] {
				if err := CheckMiddlewareRef(ref, defined, external); err != nil {
					problems[n] = fmt.Errorf("chain member: %w", err)
					delete(valid, n)
					changed = true
					break
				}
			}
		}
		// Find every cycle member against the same valid set before removing
		// any, so all members of a cycle get the same message.
		var cyclic []string
		for _, n := range names {
			if valid[n] && chainReaches(n, n, members, valid, map[string]bool{}) {
				cyclic = append(cyclic, n)
			}
		}
		for _, n := range cyclic {
			problems[n] = fmt.Errorf("chain %q is part of a cycle", n)
			delete(valid, n)
			changed = true
		}
	}
	return valid, problems
}

// chainOpts returns the options of def when its type key is "chain" in any
// letter case (Traefik matches file-provider keys case-insensitively).
func chainOpts(def any) (any, bool) {
	v, ok, err := foldLookup(def, "chain")
	return v, ok && err == nil
}

// foldLookup returns the value of the single string key of mapping m equal
// to key ignoring case. Two keys that fold to key are an error (Traefik
// would pick one of them unpredictably); a non-mapping m finds nothing.
func foldLookup(m any, key string) (any, bool, error) {
	var val any
	n := 0
	visit := func(k any, v any) {
		if ks, ok := k.(string); ok && strings.EqualFold(ks, key) {
			val = v
			n++
		}
	}
	switch x := m.(type) {
	case map[string]any:
		for k, v := range x {
			visit(k, v)
		}
	case map[any]any:
		for k, v := range x {
			visit(k, v)
		}
	}
	if n > 1 {
		return nil, false, fmt.Errorf("key %q is given %d times in different letter case", key, n)
	}
	return val, n == 1, nil
}

// noCaseDupKeys rejects a mapping with two string keys that differ only by
// letter case: Traefik folds key case, so only one of them would apply.
func noCaseDupKeys[K comparable](m map[K]any) error {
	seen := map[string]string{}
	for k := range m {
		ks, ok := any(k).(string)
		if !ok {
			continue
		}
		f := strings.ToLower(ks)
		if prev, dup := seen[f]; dup {
			a, b := prev, ks
			if b < a {
				a, b = b, a
			}
			return fmt.Errorf("keys %q and %q differ only by letter case", a, b)
		}
		seen[f] = ks
	}
	return nil
}

// chainReaches reports whether chain from reaches target through local
// (unqualified or @file) members that are still valid.
func chainReaches(from, target string, members map[string][]string, valid, seen map[string]bool) bool {
	for _, ref := range members[from] {
		name, provider, _ := ParseMiddlewareRef(ref)
		if provider != "" && provider != "file" || !valid[name] {
			continue
		}
		if name == target {
			return true
		}
		if !seen[name] {
			seen[name] = true
			if chainReaches(name, target, members, valid, seen) {
				return true
			}
		}
	}
	return false
}
