package config

import (
	"fmt"
	"regexp"
	"strings"
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
