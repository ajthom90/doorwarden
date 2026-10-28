package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func loadStr(t *testing.T, yml string, env map[string]string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p, envMap(env))
}

const base = `
zones:
  - name: example.test
    target_ip: 192.0.2.10
    records: {provider: cf, mode: per-host}
    certificate: {issuer: le, strategy: per-host, challenge: dns-01, dns_provider: cf}
providers:
  cf: {type: cloudflare, api_token: tok}
  uni: {type: unifi, url: "https://192.0.2.1"}
issuers:
  le: {email: admin@example.test}
`

func mustLoad(t *testing.T, yml string) *Config {
	t.Helper()
	c, err := loadStr(t, yml, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func caps(wild bool) func(string) (Capabilities, bool) {
	return func(typ string) (Capabilities, bool) {
		switch typ {
		case "cloudflare":
			return Capabilities{WildcardA: wild}, true
		case "unifi":
			return Capabilities{}, true
		}
		return Capabilities{}, false
	}
}

func hasErr(errs []error, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), sub) {
			return true
		}
	}
	return false
}

func TestEnvSubstitution(t *testing.T) {
	yml := strings.Replace(base, "api_token: tok", "api_token: \"${A}\", region: \"${B:-x}\"", 1)
	c, err := loadStr(t, yml, map[string]string{"A": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	p := c.Providers["cf"]
	if p.Extra["api_token"] != "secret" || p.Extra["region"] != "x" {
		t.Fatalf("got %#v", p.Extra)
	}
}

func TestUnsetVarFails(t *testing.T) {
	yml := strings.Replace(base, "api_token: tok", "api_token: \"${UNSET_VAR}\"", 1)
	_, err := loadStr(t, yml, nil)
	if err == nil || !strings.Contains(err.Error(), "UNSET_VAR") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownKeyFails(t *testing.T) {
	_, err := loadStr(t, base+"bogus: 1\n", nil)
	if err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("err = %v", err)
	}
}

func TestWildcardRequiresDNS01(t *testing.T) {
	yml := strings.Replace(base, "strategy: per-host, challenge: dns-01", "strategy: wildcard, challenge: http-01", 1)
	errs := mustLoad(t, yml).Validate(caps(true))
	if !hasErr(errs, "dns-01") {
		t.Fatalf("errs = %v", errs)
	}
}

func TestUnifiNotChallengeProvider(t *testing.T) {
	yml := strings.Replace(base, "dns_provider: cf", "dns_provider: uni", 1)
	errs := mustLoad(t, yml).Validate(caps(true))
	if !hasErr(errs, "unifi") {
		t.Fatalf("errs = %v", errs)
	}
}

func TestWildcardModeNeedsCapability(t *testing.T) {
	yml := strings.Replace(base, "mode: per-host", "mode: wildcard", 1)
	c := mustLoad(t, yml)
	if errs := c.Validate(caps(false)); !hasErr(errs, "wildcard") {
		t.Fatalf("errs = %v", errs)
	}
	if errs := c.Validate(caps(true)); len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
}

func TestDefaultsStagingIssuer(t *testing.T) {
	c := mustLoad(t, base)
	if d := c.Issuers["le"].Directory; d != "staging" {
		t.Fatalf("directory = %q", d)
	}
	if c.Settings.GracePeriod.String() != "24h0m0s" || c.Settings.PollInterval.String() != "30s" || c.Settings.RenewBefore.String() != "720h0m0s" {
		t.Fatalf("settings = %+v", c.Settings)
	}
	if errs := c.Validate(caps(true)); len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
}

func TestUnknownProviderRef(t *testing.T) {
	yml := strings.Replace(base, "records: {provider: cf", "records: {provider: nope", 1)
	yml = strings.Replace(yml, "issuer: le", "issuer: missing", 1)
	errs := mustLoad(t, yml).Validate(caps(true))
	if !hasErr(errs, "nope") || !hasErr(errs, "missing") {
		t.Fatalf("errs = %v", errs)
	}
}

func TestZoneRequiredFields(t *testing.T) {
	yml := strings.Replace(base, "target_ip: 192.0.2.10", "target_ip: notip", 1)
	if errs := mustLoad(t, yml).Validate(caps(true)); !hasErr(errs, "target_ip") {
		t.Fatalf("errs = %v", errs)
	}
}

func tokenWith(t *testing.T, yamlVal string, env map[string]string) *Config {
	t.Helper()
	yml := strings.Replace(base, "api_token: tok", "api_token: "+yamlVal, 1)
	c, err := loadStr(t, yml, env)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSecretValuesSurvive(t *testing.T) {
	for _, v := range []string{"abc #x", "a: b", "*star", "&amp", "!bang", "{x", "[y", "@at", "null", "true", "0123", "line1\nline2\nevil_key: 1", "- item"} {
		c := tokenWith(t, `"${S}"`, map[string]string{"S": v})
		if got := c.Providers["cf"].Extra["api_token"]; got != v {
			t.Errorf("value %q became %#v", v, got)
		}
		if len(c.Providers["cf"].Extra) != 1 {
			t.Errorf("value %q injected keys: %#v", v, c.Providers["cf"].Extra)
		}
	}
}

func TestNoReExpansion(t *testing.T) {
	c := tokenWith(t, `"${S}"`, map[string]string{"S": "${T}", "T": "boom"})
	if got := c.Providers["cf"].Extra["api_token"]; got != "${T}" {
		t.Fatalf("got %#v", got)
	}
}

func TestUnsetVarInCommentOK(t *testing.T) {
	if _, err := loadStr(t, "# uses ${NOPE}\n"+base, nil); err != nil {
		t.Fatal(err)
	}
}

func TestUnsetVarsAllNamed(t *testing.T) {
	yml := strings.Replace(base, "api_token: tok", "api_token: \"${M1}-${M2}\"", 1)
	_, err := loadStr(t, yml, nil)
	if err == nil || !strings.Contains(err.Error(), "M1") || !strings.Contains(err.Error(), "M2") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateNilCaps(t *testing.T) {
	yml := strings.Replace(base, "mode: per-host", "mode: wildcard", 1)
	errs := mustLoad(t, yml).Validate(nil)
	if !hasErr(errs, "wildcard") {
		t.Fatalf("errs = %v", errs)
	}
}

func TestTypedSubstitution(t *testing.T) {
	yml := base + "settings:\n  dry_run: ${DRY}\n  poll_interval: ${POLL}\nstatic:\n  - name: ${N}\n    port: ${PORT}\n"
	c, err := loadStr(t, yml, map[string]string{"DRY": "true", "POLL": "45s", "N": "123", "PORT": "8080"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Settings.DryRun || c.Settings.PollInterval.String() != "45s" {
		t.Fatalf("settings = %+v", c.Settings)
	}
	if c.Static[0].Name != "123" || c.Static[0].Port != 8080 {
		t.Fatalf("static = %+v", c.Static[0])
	}
}

func TestTypedZoneNameFromInt(t *testing.T) {
	yml := strings.Replace(base, "name: example.test", "name: ${N}", 1)
	c, err := loadStr(t, yml, map[string]string{"N": "123"})
	if err != nil || c.Zones[0].Name != "123" {
		t.Fatalf("err=%v c=%+v", err, c)
	}
}

func TestQuotedPlaceholderStaysString(t *testing.T) {
	_, err := loadStr(t, base+"settings:\n  dry_run: \"${DRY}\"\n", map[string]string{"DRY": "true"})
	if err == nil || !strings.Contains(err.Error(), "dry_run") && !strings.Contains(err.Error(), "bool") {
		t.Fatalf("err = %v", err)
	}
}

func TestMixedPlaceholderStaysString(t *testing.T) {
	_, err := loadStr(t, base+"settings:\n  dry_run: x${DRY}\n", map[string]string{"DRY": "true"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestProvidersAlwaysStrings(t *testing.T) {
	for _, v := range []string{"true", "123", "null", "1.5"} {
		c := tokenWith(t, `"${T}"`, map[string]string{"T": v})
		if got := c.Providers["cf"].Extra["api_token"]; got != v {
			t.Errorf("T=%s became %#v", v, got)
		}
	}
}

func TestTypedPlainStillSafe(t *testing.T) {
	for _, v := range []string{"abc #x", "a: b", "null", "~", "x\ny: 1"} {
		_, err := loadStr(t, base+"static:\n  - name: ${S}\n", map[string]string{"S": v})
		if err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	c, _ := loadStr(t, base+"static:\n  - name: ${S}\n", map[string]string{"S": "abc #x"})
	if c.Static[0].Name != "abc #x" {
		t.Fatalf("got %q", c.Static[0].Name)
	}
}

func TestProvidersBlockPlainStaysString(t *testing.T) {
	yml := "providers:\n  cf:\n    type: cloudflare\n    api_token: ${T}\n"
	for _, v := range []string{"true", "123"} {
		c, err := loadStr(t, yml, map[string]string{"T": v})
		if err != nil || c.Providers["cf"].Extra["api_token"] != v {
			t.Fatalf("T=%s err=%v c=%+v", v, err, c)
		}
	}
}

func TestDefaultZone(t *testing.T) {
	tests := []struct {
		name, val string
		wantErr   bool
	}{
		{"unset", "", false},
		{"configured", "example.test", false},
		{"normalized", "Example.Test.", false},
		{"unknown", "other.test", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			yml := base
			if tc.val != "" {
				yml += "settings:\n  default_zone: \"" + tc.val + "\"\n"
			}
			c := mustLoad(t, yml)
			if c.Settings.DefaultZone != tc.val {
				t.Fatalf("DefaultZone = %q", c.Settings.DefaultZone)
			}
			if got := hasErr(c.Validate(caps(true)), "default_zone"); got != tc.wantErr {
				t.Fatalf("default_zone error = %v, want %v", got, tc.wantErr)
			}
		})
	}
}
