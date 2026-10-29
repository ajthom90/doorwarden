package config

import (
	"strings"
	"testing"
)

// YAML merge keys would let a ${VAR} written under a secret-looking path
// land in a plain field; the loader refuses them, naming the line.
func TestParseRejectsMergeKeys(t *testing.T) {
	env := func(k string) (string, bool) { return "s3cr3t", k == "SOME_SECRET" }
	for _, doc := range []string{
		"providers:\n  leak:\n    <<: {type: \"${SOME_SECRET}\"}\n",
		"providers:\n  leak:\n    !!merge <<: {type: cloudflare}\n",
		"providers:\n  a: &b {type: cloudflare}\n  leak:\n    <<: *b\n",
	} {
		_, err := Parse([]byte(doc), env)
		if err == nil || !strings.Contains(err.Error(), "merge key") || !strings.Contains(err.Error(), "line 3") && !strings.Contains(err.Error(), "line 4") {
			t.Errorf("%q: err = %v", doc, err)
		}
		if err != nil && strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("error echoes the secret: %v", err)
		}
	}
}
