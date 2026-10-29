package config

import (
	"encoding/json"
	"errors"
	"fmt"
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

// assertNoSubstring fails when msg contains any substring of secret of at
// least 3 bytes.
func assertNoSubstring(t *testing.T, msg, secret string) {
	t.Helper()
	for i := 0; i+3 <= len(secret); i++ {
		if f := secret[i : i+3]; strings.Contains(msg, f) {
			t.Fatalf("message contains fragment %q of the env value: %s", f, msg)
		}
	}
}

// A substituted value mixed with literal text (port: x${SECRET}) fails
// decoding; the error names where and why but quotes none of the value, for
// plain, quote/backslash/unicode-bearing secrets alike.
func TestDecodeErrorElidesMixedEnvValue(t *testing.T) {
	for name, secret := range map[string]string{
		"long":    "Qz7WkPjR9vLmTnXb4HsY2GdFcA8EuKoM",
		"special": `Qz"7W\kPj 'R9vL` + "é世界" + `<mT>&nX`,
	} {
		t.Run(name, func(t *testing.T) {
			env := func(k string) (string, bool) { return secret, k == "SECRET" }
			yml := base + "static:\n  - name: app\n    host: 192.0.2.5\n    port: x${SECRET}\n"
			_, err := Parse([]byte(yml), env)
			if err == nil {
				t.Fatal("no error")
			}
			msg := err.Error()
			assertNoSubstring(t, msg, secret)
			if !strings.Contains(msg, "static[0].port") || !strings.Contains(msg, "line 15") {
				t.Fatalf("error lost its location: %s", msg)
			}
		})
	}
}

// The substring scrub (defence in depth, also used for validation errors)
// removes Go-quoted (%q, %+q) and JSON-escaped forms of a value and any
// quoted token carrying a fragment of one.
func TestScrubEnvValuesEscapedForms(t *testing.T) {
	secret := `Qz"7W\kPj 'R9vL` + "é世界" + `<mT>&nX`
	env := func(k string) (string, bool) { return secret, k == "A" }
	raw := []byte("x: ${A}\n")
	jsonEsc, _ := json.Marshal(secret)
	for _, in := range []string{
		fmt.Sprintf("bad value %q here", secret),
		fmt.Sprintf("bad value %+q here", secret),
		"bad value " + string(jsonEsc) + " here",
		fmt.Sprintf("bad value %q here", "pre-"+secret[:9]),
		"bad value `" + secret[2:9] + "...` here",
	} {
		got := ScrubEnvValues(errors.New(in), raw, env).Error()
		assertNoSubstring(t, got, secret)
		if !strings.Contains(got, "bad value") || !strings.Contains(got, "here") {
			t.Fatalf("context lost: %q", got)
		}
	}
}
