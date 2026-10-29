package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/app"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const testMasterKey = "cli-test-master-key-0123456789"

// cliIO replaces stdin and stderr for one test and returns the stderr
// buffer.
func cliIO(t *testing.T, in string) *bytes.Buffer {
	t.Helper()
	var errb bytes.Buffer
	oldIn, oldErr := stdin, stderr
	stdin, stderr = strings.NewReader(in), &errb
	t.Cleanup(func() { stdin, stderr = oldIn, oldErr })
	return &errb
}

func secretRun(t *testing.T, in string, args ...string) (int, string, string) {
	t.Helper()
	errb := cliIO(t, in)
	var out bytes.Buffer
	c := run(append([]string{"admin", "secret"}, args...), &out)
	return c, out.String(), errb.String()
}

// set stores the value sealed under the master key; list prints names
// only; the value never appears on stdout or stderr; a config secret:
// reference resolves afterwards exactly as the server does at start-up.
func TestAdminSecretSetListResolve(t *testing.T) {
	t.Setenv("DOORWARDEN_MASTER_KEY", testMasterKey)
	p := adminDB(t, false)
	const value = "tn-api-key-Zq9xW3vT7"
	c, out, errs := secretRun(t, value+"\n", "set", "truenas_key", "-db", p)
	if c != 0 {
		t.Fatalf("set: exit %d: %s %s", c, out, errs)
	}
	if strings.Contains(out+errs, value) {
		t.Fatalf("value echoed: %q %q", out, errs)
	}
	st := openDB(t, p)
	raw, ok, _ := st.GetSetting(context.Background(), app.SecretKVPrefix+"truenas_key")
	if !ok || strings.Contains(raw, value) {
		t.Fatalf("stored raw = %q ok=%v", raw, ok)
	}
	box, _ := secrets.NewBox(testMasterKey)
	ss := &app.SecretStore{KV: st, Box: box}
	got, err := ss.Resolve("truenas_key")
	if err != nil || got.Reveal() != value {
		t.Fatalf("resolve = %q, %v (one trailing newline must be dropped)", got.Reveal(), err)
	}

	c, out, _ = secretRun(t, "", "list", "-db", p)
	if c != 0 || out != "truenas_key\n" {
		t.Fatalf("list: exit %d %q", c, out)
	}

	// Start-up: a config secret: reference resolves (RunWith builds the
	// same SecretStore over the store and DOORWARDEN_MASTER_KEY).
	cfgPath := filepath.Join(t.TempDir(), "doorwarden.yaml")
	yml := "zones:\n  - name: example.test\n    target_ip: 192.0.2.10\nsources:\n  truenas: {url: \"https://192.0.2.20\", api_key: \"secret:truenas_key\"}\ntraefik: {dynamic_dir: " + t.TempDir() + "}\n"
	if err := os.WriteFile(cfgPath, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := app.LoadConfig(cfgPath, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	for _, sp := range app.BuildSources(cfg, ss) {
		if sp.Name == "truenas" || (sp.Source != nil && sp.Source.Name() == "truenas") {
			if sp.Err != nil {
				t.Fatalf("truenas source: %v", sp.Err)
			}
			if c, ok := sp.Source.(io.Closer); ok {
				_ = c.Close()
			}
		}
	}
	// Without the secret the same config fails to build the source.
	if c, _, errs := secretRun(t, "", "delete", "truenas_key", "-db", p); c != 0 {
		t.Fatalf("delete: %d %s", c, errs)
	}
	if _, err := ss.Resolve("truenas_key"); !errors.Is(err, app.ErrSecretNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if c, out, _ := secretRun(t, "", "list", "-db", p); c != 0 || out != "" {
		t.Fatalf("list after delete: %d %q", c, out)
	}
}

// An existing secret is replaced only with -force.
func TestAdminSecretOverwrite(t *testing.T) {
	t.Setenv("DOORWARDEN_MASTER_KEY", testMasterKey)
	p := adminDB(t, false)
	if c, _, errs := secretRun(t, "first-value", "set", "tok", "-db", p); c != 0 {
		t.Fatal(errs)
	}
	c, out, errs := secretRun(t, "second-value", "set", "tok", "-db", p)
	if c == 0 || !strings.Contains(errs, "-force") {
		t.Fatalf("overwrite without -force: %d %q %q", c, out, errs)
	}
	box, _ := secrets.NewBox(testMasterKey)
	ss := &app.SecretStore{KV: openDB(t, p), Box: box}
	if v, _ := ss.Resolve("tok"); v.Reveal() != "first-value" {
		t.Fatalf("refused overwrite changed the value: %q", v.Reveal())
	}
	if c, _, errs := secretRun(t, "second-value\r\n", "set", "tok", "-force", "-db", p); c != 0 {
		t.Fatal(errs)
	}
	if v, _ := ss.Resolve("tok"); v.Reveal() != "second-value" {
		t.Fatalf("forced value = %q", v.Reveal())
	}
}

// Refusals: invalid names, values on the command line, empty values, no
// or a different master key, a foreign-owned or missing database. None
// of them prints the value.
func TestAdminSecretRefusals(t *testing.T) {
	t.Setenv("DOORWARDEN_MASTER_KEY", testMasterKey)
	p := adminDB(t, false)
	const value = "s3cr3t-value-never-shown"
	for _, tc := range []struct {
		name string
		in   string
		args []string
	}{
		{"bad name", value, []string{"set", "bad/name", "-db", p}},
		{"name with space", value, []string{"set", "a b", "-db", p}},
		{"no name", value, []string{"set"}},
		{"value as argument", "", []string{"set", "tok", "-db", p, value}},
		{"empty value", "\n", []string{"set", "tok", "-db", p}},
		{"missing db", value, []string{"set", "tok", "-db", filepath.Join(t.TempDir(), "nope.db")}},
		{"unknown action", value, []string{"show", "tok", "-db", p}},
		{"bad delete name", "", []string{"delete", "../x", "-db", p}},
	} {
		c, out, errs := secretRun(t, tc.in, tc.args...)
		if c == 0 {
			t.Errorf("%s: accepted", tc.name)
		}
		if strings.Contains(out+errs, value) {
			t.Errorf("%s: value printed: %q %q", tc.name, out, errs)
		}
	}
	if _, err := os.Stat(filepath.Join(t.TempDir(), "nope.db")); err == nil {
		t.Fatal("missing database was created")
	}

	t.Setenv("DOORWARDEN_MASTER_KEY", "")
	if c, _, errs := secretRun(t, value, "set", "tok", "-db", p); c == 0 || !strings.Contains(errs, "DOORWARDEN_MASTER_KEY") {
		t.Fatalf("no master key: %d %q", c, errs)
	}
	t.Setenv("DOORWARDEN_MASTER_KEY", testMasterKey)
	if c, _, errs := secretRun(t, value, "set", "tok", "-db", p); c != 0 {
		t.Fatal(errs)
	}
	// Another key could not be read by the server: refused.
	t.Setenv("DOORWARDEN_MASTER_KEY", "another-master-key-0123456789")
	if c, _, errs := secretRun(t, "other", "set", "tok2", "-db", p); c == 0 || !strings.Contains(errs, "cannot decrypt") {
		t.Fatalf("wrong master key: %d %q", c, errs)
	}
	t.Setenv("DOORWARDEN_MASTER_KEY", testMasterKey)

	old := dbOwner
	dbOwner = func(string) (int, bool) { return 4242, true }
	t.Cleanup(func() { dbOwner = old })
	if c, _, errs := secretRun(t, "x", "set", "tok3", "-db", p); c == 0 || !strings.Contains(errs, "uid 4242") {
		t.Fatalf("foreign owner: %d %q", c, errs)
	}
	if c, _, _ := secretRun(t, "", "list", "-db", p); c == 0 {
		t.Fatal("foreign owner list accepted")
	}
	dbOwner = old
	if c, out, _ := secretRun(t, "", "list", "-db", p); c != 0 || out != "tok\n" {
		t.Fatalf("refusals stored something: %q", out)
	}
}

// On a terminal the value is prompted twice without echo; differing
// entries store nothing.
func TestAdminSecretPrompt(t *testing.T) {
	t.Setenv("DOORWARDEN_MASTER_KEY", testMasterKey)
	p := adminDB(t, false)
	oldTerm, oldRead := isTerminal, readPassword
	t.Cleanup(func() { isTerminal, readPassword = oldTerm, oldRead })
	isTerminal = func(io.Reader) bool { return true }
	answers := []string{"prompted-value", "prompted-value"}
	readPassword = func(io.Reader) ([]byte, error) {
		v := answers[0]
		answers = answers[1:]
		return []byte(v), nil
	}
	c, out, errs := secretRun(t, "", "set", "tok", "-db", p)
	if c != 0 || !strings.Contains(errs, "not echoed") || strings.Contains(out+errs, "prompted-value") {
		t.Fatalf("prompt: %d %q %q", c, out, errs)
	}
	box, _ := secrets.NewBox(testMasterKey)
	if v, _ := (&app.SecretStore{KV: openDB(t, p), Box: box}).Resolve("tok"); v.Reveal() != "prompted-value" {
		t.Fatalf("value = %q", v.Reveal())
	}
	answers = []string{"one", "two"}
	if c, _, errs := secretRun(t, "", "set", "tok2", "-db", p); c == 0 || !strings.Contains(errs, "differ") {
		t.Fatalf("mismatch: %d %q", c, errs)
	}
}
