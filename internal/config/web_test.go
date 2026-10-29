package config

import (
	"strings"
	"testing"
	"time"
)

func TestWebDefaults(t *testing.T) {
	c := mustLoad(t, base)
	w := c.Web
	if w.CookieInsecure || w.SessionIdle != 8*time.Hour || w.SessionMax != 7*24*time.Hour {
		t.Fatalf("defaults = %+v", w)
	}
	if w.TrustedHeader.UserHeader != "Remote-User" || w.TrustedHeader.Role != "viewer" || len(w.TrustedHeader.Proxies) != 0 {
		t.Fatalf("trusted header defaults = %+v", w.TrustedHeader)
	}
	if errs := c.Validate(caps(true)); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestWebValidate(t *testing.T) {
	c := mustLoad(t, base+`web:
  trusted_header: {proxies: ["10.0.0.0/8", "nonsense"], user_header: "bad header", role: root}
  allowed_origins: ["https://dw.example.test", "dw.example.test", "https://x.example.test/path"]
  session_idle: -1s
  trusted_proxies: ["192.0.2.0/24", "not-a-cidr"]
`)
	errs := c.Validate(caps(true))
	var all []string
	for _, e := range errs {
		all = append(all, e.Error())
	}
	j := strings.Join(all, "\n")
	for _, want := range []string{"proxies", "nonsense", "user_header", "role", "allowed_origins", "dw.example.test\"", "/path", "session_idle", "trusted_proxies", "not-a-cidr"} {
		if !strings.Contains(j, want) {
			t.Errorf("missing %q in:\n%s", want, j)
		}
	}
	ok := mustLoad(t, base+`web:
  trusted_header: {proxies: ["10.0.0.0/8", "2001:db8::/32", "192.0.2.7/32"], user_header: X-Authentik-Username, role: admin}
  allowed_origins: ["https://dw.example.test", "http://192.0.2.5:8080"]
  trusted_proxies: ["192.0.2.0/24", "2001:db8::/32"]
`)
	if errs := ok.Validate(caps(true)); len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(ok.Web.TrustedProxies) != 2 {
		t.Fatalf("trusted_proxies = %v", ok.Web.TrustedProxies)
	}
}

// Parse is Load on bytes.
func TestParse(t *testing.T) {
	c, err := Parse([]byte(base+"settings: {default_zone: \"${Z}\"}\n"), func(k string) (string, bool) {
		return "example.test", k == "Z"
	})
	if err != nil || c.Settings.DefaultZone != "example.test" || c.Traefik.EntryPoint != "websecure" {
		t.Fatalf("parse: %+v %v", c, err)
	}
	if _, err := Parse([]byte(base+"bogus: 1\n"), nil); err == nil {
		t.Fatal("unknown key accepted")
	}
}
