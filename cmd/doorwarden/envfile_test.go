package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseEnvFile(t *testing.T) {
	p := writeFile(t, "env", "# comment\n\nA=1\r\nB = two=2 \n  # indented comment\nC=\"quoted\"\nexport_ok=x\nEMPTY=\n")
	m, err := parseEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "1", "B": " two=2 ", "C": `"quoted"`, "export_ok": "x", "EMPTY": ""}
	if len(m) != len(want) {
		t.Fatalf("got %q", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
	// A malformed line is reported by number, never by content.
	bad := writeFile(t, "env", "OK=1\nthis-is-a-leaked-token\n")
	_, err = parseEnvFile(bad)
	if err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "leaked-token") {
		t.Fatalf("err = %v", err)
	}
	if _, err := parseEnvFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing file accepted")
	}
}

const envCfg = `zones:
  - name: ${ZONE}
    target_ip: 192.0.2.10
    records: {provider: cf, mode: wildcard}
providers:
  cf: {type: cloudflare, api_token: "${CF_TOKEN}"}
traefik: {dynamic_dir: /tmp}
`

// The process environment wins over the env file; unset variables expand
// to empty and are reported; errors never carry values.
func TestCLIConfig(t *testing.T) {
	cfgPath := writeFile(t, "dw.yaml", envCfg)
	envPath := writeFile(t, "env", "ZONE=example.test\n")
	cfg, unset, err := cliConfig(cfgPath, envPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Zones[0].Name != "example.test" || len(unset) != 1 || unset[0] != "CF_TOKEN" {
		t.Fatalf("zone %q unset %v", cfg.Zones[0].Name, unset)
	}
	t.Setenv("ZONE", "other.test")
	cfg, _, err = cliConfig(cfgPath, envPath)
	if err != nil || cfg.Zones[0].Name != "other.test" {
		t.Fatalf("process env must win: %v %v", cfg, err)
	}
	// A typed field fed an unset variable fails with a hint; a value from
	// the env file that breaks decoding is not echoed, not even the prefix
	// the YAML decoder quotes.
	typed := writeFile(t, "dw.yaml", envCfg+"settings:\n  poll_interval: ${POLL}\n  grace_period: ${GRACE}\n")
	_, _, err = cliConfig(typed, writeFile(t, "env", "GRACE=very-secret-grace\n"))
	if err == nil || !strings.Contains(err.Error(), "POLL") || strings.Contains(err.Error(), "very-se") {
		t.Fatalf("err = %v", err)
	}
}

// doorwarden import-npm with a config whose credentials are ${VAR}s not
// passed to the container: the zones still come through (from -env-file)
// and the missing variables are only noted.
func TestImportNPMEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "database.sqlite")
	db, _ := sql.Open("sqlite", p)
	for _, s := range []string{
		`CREATE TABLE proxy_host(id INTEGER PRIMARY KEY, domain_names TEXT, forward_scheme TEXT, forward_host TEXT, forward_port INT, certificate_id INT, access_list_id INT, allow_websocket_upgrade INT, ssl_forced INT, advanced_config TEXT, enabled INT, is_deleted INT)`,
		`CREATE TABLE certificate(id INTEGER PRIMARY KEY, provider TEXT, nice_name TEXT, domain_names TEXT, expires_on TEXT, is_deleted INT)`,
		`INSERT INTO proxy_host VALUES(1,'["x.example.test"]','http','192.0.2.10',80,0,0,0,1,'',1,0)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	cfgPath := writeFile(t, "dw.yaml", envCfg)
	envPath := writeFile(t, "env", "ZONE=example.test\n")
	errb := cliIO(t, "")
	var out bytes.Buffer
	if c := run([]string{"import-npm", "--db", p, "--config", cfgPath, "--env-file", envPath, "--yaml"}, &out); c != 0 {
		t.Fatalf("exit %d: %s", c, errb.String())
	}
	if !strings.Contains(out.String(), "zone: example.test") || !strings.Contains(errb.String(), "CF_TOKEN") {
		t.Fatalf("out %q err %q", out.String(), errb.String())
	}
	// Without the env file the zone is empty: the host is outside every
	// zone, so nothing is suggested.
	var out2 bytes.Buffer
	errb = cliIO(t, "")
	if c := run([]string{"import-npm", "--db", p, "--config", cfgPath, "--yaml"}, &out2); c != 0 {
		t.Fatalf("exit %d: %s", c, errb.String())
	}
	if out.String() == out2.String() || !strings.Contains(errb.String(), "ZONE") {
		t.Fatalf("zone from env file had no effect:\n%s\n---\n%s\n%s", out.String(), out2.String(), errb.String())
	}
	if c := run([]string{"import-npm", "--db", p, "--env-file", envPath}, &out2); c == 0 {
		t.Fatal("-env-file without -config accepted")
	}
}
