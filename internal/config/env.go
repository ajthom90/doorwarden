package config

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var envRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// substituteEnv expands ${VAR} and ${VAR:-default}. An unset variable without
// a default is an error naming the variable. With ":-", the default is also
// used when the variable is set but empty (shell semantics).
func substituteEnv(in string, env func(string) (string, bool)) (string, error) {
	var missing []string
	out := envRe.ReplaceAllStringFunc(in, func(m string) string {
		sub := envRe.FindStringSubmatch(m)
		name, hasDef, def := sub[1], sub[2] != "", sub[3]
		v, ok := env(name)
		if hasDef && (!ok || v == "") {
			return def
		}
		if !ok {
			missing = append(missing, name)
			return ""
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("unset environment variable(s) with no default: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// substituteNode expands variables only inside string scalar values of the
// node tree (never keys, comments or non-string scalars). Missing variables
// are collected in missing. Under the top-level "providers" and
// "middlewares" subtrees (stringOnlyTopKeys) results are always plain
// strings. Elsewhere, an unquoted scalar that is exactly one
// placeholder takes the type (bool/int/float only) its substituted text
// resolves to; quoted or mixed text always stays a string. Substituted text
// is never re-parsed as YAML structure.
// stringOnlyTopKeys are the top-level subtrees whose substituted scalars are
// always plain strings: provider settings (secrets) and middleware
// definitions (header values, secrets), which must reach their consumer
// exactly as written (0123, 1e3, 0x1F, true stay those strings).
var stringOnlyTopKeys = map[string]bool{"providers": true, "middlewares": true, "notifications": true}

func substituteNode(n *yaml.Node, env func(string) (string, bool), missing *[]string) {
	walkNode(n, env, missing, true, false)
}

func walkNode(n *yaml.Node, env func(string) (string, bool), missing *[]string, top, strOnly bool) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			walkNode(c, env, missing, top, strOnly)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			walkNode(c, env, missing, false, strOnly)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 { // skip keys
			so := strOnly || (top && stringOnlyTopKeys[n.Content[i].Value])
			walkNode(n.Content[i+1], env, missing, false, so)
		}
	case yaml.ScalarNode:
		if n.ShortTag() != "!!str" || !envRe.MatchString(n.Value) {
			return
		}
		out, err := substituteEnv(n.Value, env)
		if err != nil {
			for _, m := range envRe.FindAllStringSubmatch(n.Value, -1) {
				if _, ok := env(m[1]); !ok && m[2] == "" {
					*missing = append(*missing, m[1])
				}
			}
			return
		}
		tag := "!!str"
		if !strOnly && n.Style == 0 && envRe.FindString(n.Value) == n.Value {
			tag = resolveScalar(out)
		}
		n.Value = out
		n.Tag = tag
		if tag == "!!str" {
			n.Style = yaml.DoubleQuotedStyle
		}
	}
}

// resolveScalar returns !!bool, !!int or !!float if s on its own is exactly
// such a YAML scalar, otherwise !!str.
func resolveScalar(s string) string {
	var d yaml.Node
	if err := yaml.Unmarshal([]byte(s), &d); err != nil || d.Kind != yaml.DocumentNode || len(d.Content) != 1 {
		return "!!str"
	}
	c := d.Content[0]
	if c.Kind != yaml.ScalarNode || c.Value != s {
		return "!!str"
	}
	switch t := c.ShortTag(); t {
	case "!!bool", "!!int", "!!float":
		return t
	}
	return "!!str"
}

// RejectMergeKeys refuses YAML merge keys (`<<`, tagged !!merge or not)
// anywhere in the document: they copy values between mappings after the
// per-field rules (secret fields, ${VAR} placement) were checked against
// where they were written.
func RejectMergeKeys(n *yaml.Node) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.ScalarNode && (k.ShortTag() == "!!merge" || k.Value == "<<") {
				return fmt.Errorf("YAML merge keys (<<) are not supported (line %d)", k.Line)
			}
		}
	}
	for _, c := range n.Content {
		if err := RejectMergeKeys(c); err != nil {
			return err
		}
	}
	return nil
}
