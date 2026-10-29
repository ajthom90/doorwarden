package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const envSecret = "S3cretEnvValue-0123456789"

func assertNoFragment(t *testing.T, msg, secret string) {
	t.Helper()
	for n := 3; n <= len(secret); n++ {
		if strings.Contains(msg, secret[:n]) {
			t.Fatalf("message contains %d-char prefix %q of the env value: %s", n, secret[:n], msg)
		}
	}
}

// A substituted env value that fails type decoding (an int field) never
// appears in the error, not even the truncated prefix the YAML decoder
// quotes.
func TestLoadErrorHasNoEnvValueFragment(t *testing.T) {
	env := func(k string) (string, bool) {
		if k == "SECRET" {
			return envSecret, true
		}
		return "", false
	}
	yml := base + "static:\n  - name: app\n    host: 192.0.2.5\n    port: ${SECRET}\n"
	_, err := Parse([]byte(yml), env)
	if err == nil {
		t.Fatal("no error")
	}
	assertNoFragment(t, err.Error(), envSecret)
	if !strings.Contains(err.Error(), "line") {
		t.Fatalf("error lost its location: %v", err)
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, env); err == nil {
		t.Fatal("no error")
	} else {
		assertNoFragment(t, err.Error(), envSecret)
	}
}

func TestScrubEnvValues(t *testing.T) {
	env := func(k string) (string, bool) {
		return map[string]string{"A": envSecret, "B": "ab"}[k], k == "A" || k == "B"
	}
	raw := []byte("x: ${A}\ny: ${B:-z}\n")
	in := errors.New("full " + envSecret + "; quoted `" + envSecret[:7] + "...`; short ab stays")
	got := ScrubEnvValues(in, raw, env).Error()
	assertNoFragment(t, got, envSecret)
	if !strings.Contains(got, "short ab stays") || !strings.Contains(got, "[redacted]") {
		t.Fatalf("got %q", got)
	}
}
