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
// node tree (never keys, comments or non-string scalars). Results stay plain
// strings and are never re-parsed. Missing variables are collected in missing.
func substituteNode(n *yaml.Node, env func(string) (string, bool), missing *[]string) {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			substituteNode(c, env, missing)
		}
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 { // skip keys
			substituteNode(n.Content[i], env, missing)
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
		n.Value = out
		n.Tag = "!!str"
		n.Style = yaml.DoubleQuotedStyle
	}
}
