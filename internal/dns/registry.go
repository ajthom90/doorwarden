package dns

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Factory builds a Provider from its config map. Config values are secret
// references or plain settings; never log cfg.
type Factory func(cfg map[string]any, sr SecretResolver) (Provider, error)

// Field describes one config key of a provider type.
type Field struct {
	Name     string
	Secret   bool // value is a secret reference, not plaintext
	Required bool
	Help     string
}

// ConfigSchema describes a provider type's config keys.
type ConfigSchema struct{ Fields []Field }

type entry struct {
	factory Factory
	schema  ConfigSchema
	caps    Capabilities
}

var (
	mu       sync.RWMutex
	registry = map[string]entry{}
)

// Register adds a provider type. It panics on an empty or duplicate type.
// caps are static capabilities available without credentials. They are an
// upper bound used only for config validation; the constructed instance's
// Capabilities() is authoritative at runtime and may be narrower.
func Register(typ string, f Factory, schema ConfigSchema, caps Capabilities) {
	if typ == "" {
		panic("dns: Register with empty type")
	}
	if f == nil {
		panic("dns: Register with nil factory for " + typ)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[typ]; dup {
		panic(fmt.Sprintf("dns: provider type %q registered twice", typ))
	}
	registry[typ] = entry{f, schema, caps}
}

// New constructs a provider of the given type. Unknown config keys are
// rejected (a typo must not silently change behaviour), then required fields
// are checked. Every key a provider honours must be declared in its schema.
func New(typ string, cfg map[string]any, sr SecretResolver) (Provider, error) {
	mu.RLock()
	e, ok := registry[typ]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("dns: unknown provider type %q (known types: %s)", typ, strings.Join(Types(), ", "))
	}
	valid := make([]string, 0, len(e.schema.Fields))
	known := make(map[string]bool, len(e.schema.Fields))
	for _, f := range e.schema.Fields {
		valid = append(valid, f.Name)
		known[f.Name] = true
	}
	sort.Strings(valid)
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !known[k] {
			return nil, fmt.Errorf("dns: provider type %q: unknown config field %q (valid fields: %s)", typ, k, strings.Join(valid, ", "))
		}
	}
	for _, f := range e.schema.Fields {
		if !f.Required {
			continue
		}
		if v, present := cfg[f.Name]; !present || v == nil || v == "" {
			return nil, fmt.Errorf("dns: provider type %q: required config field %q is missing", typ, f.Name)
		}
	}
	return e.factory(cfg, sr)
}

func unregister(typ string) {
	mu.Lock()
	delete(registry, typ)
	mu.Unlock()
}

// Types returns registered type names, sorted.
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// CapsFor returns a type's static capabilities without constructing it. This
// is an upper bound for validation only; callers that depend on a capability
// must check the constructed instance's Capabilities().
func CapsFor(typ string) (Capabilities, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := registry[typ]
	return e.caps, ok
}

// SchemaFor returns a type's config schema.
func SchemaFor(typ string) (ConfigSchema, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := registry[typ]
	return e.schema, ok
}
