package config

import (
	"strings"
	"testing"
)

const http01Base = `
zones:
  - name: example.test
    target_ip: 192.0.2.10
    records: {mode: off}
    certificate: {issuer: le, strategy: per-host, challenge: http-01}
issuers:
  le: {email: admin@example.test}
`

func TestHTTP01Defaults(t *testing.T) {
	c := mustLoad(t, http01Base+"acme: {http01_listen: ':8089'}\n")
	if c.Traefik.HTTPEntryPoint != "web" {
		t.Fatalf("http_entry_point = %q", c.Traefik.HTTPEntryPoint)
	}
	if c.ACME.HTTP01Backend != "http://doorwarden:8089" {
		t.Fatalf("http01_backend = %q", c.ACME.HTTP01Backend)
	}
	if errs := c.Validate(caps(true)); len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if c := mustLoad(t, http01Base+"acme: {http01_listen: '[::]:8090'}\n"); c.ACME.HTTP01Backend != "http://doorwarden:8090" {
		t.Fatalf("ipv6 listen backend = %q", c.ACME.HTTP01Backend)
	}
	if c := mustLoad(t, base); c.ACME.HTTP01Backend != "" {
		t.Fatalf("backend without listen = %q", c.ACME.HTTP01Backend)
	}
}

func TestHTTP01BackendValidation(t *testing.T) {
	for in, want := range map[string]string{
		"http://doorwarden:8089":         "",
		"https://192.0.2.7:8443":         "",
		"http://[2001:db8::1]:8089":      "",
		"http://doorwarden:8089/":        "",
		"ftp://doorwarden:8089":          "must be http:// or https://",
		"http://user:pw@doorwarden:8089": "without userinfo, path, query or fragment",
		"http://doorwarden:8089/acme":    "without userinfo, path, query or fragment",
		"http://doorwarden:8089?x=1":     "without userinfo, path, query or fragment",
		"http://:8089":                   "has no host",
		"http://doorwarden:99999":        "port",
		"http://bad host:80":             "not a valid URL",
	} {
		c := mustLoad(t, http01Base+"acme: {http01_listen: ':8089', http01_backend: '"+in+"'}\n")
		errs := c.Validate(caps(true))
		if want == "" {
			if len(errs) != 0 {
				t.Errorf("%s: %v", in, errs)
			}
			continue
		}
		if !hasErr(errs, "acme.http01_backend") || !hasErr(errs, want) {
			t.Errorf("%s: errs = %v, want %q", in, errs, want)
		}
	}
	errs := mustLoad(t, base+"acme: {http01_backend: 'http://doorwarden:8089'}\n").Validate(caps(true))
	if !hasErr(errs, "acme.http01_backend requires acme.http01_listen") {
		t.Fatalf("errs = %v", errs)
	}
}

func TestHTTPEntryPointValidation(t *testing.T) {
	errs := mustLoad(t, http01Base+"acme: {http01_listen: ':8089'}\ntraefik: {http_entry_point: 'we b'}\n").Validate(caps(true))
	if !hasErr(errs, "traefik.http_entry_point \"we b\" must be [A-Za-z0-9_-]+") {
		t.Fatalf("errs = %v", errs)
	}
	errs = mustLoad(t, http01Base+"acme: {http01_listen: ':8089'}\ntraefik: {http_entry_point: websecure}\n").Validate(caps(true))
	if !hasErr(errs, "traefik.http_entry_point must differ from traefik.entry_point") {
		t.Fatalf("errs = %v", errs)
	}
}

// Regression: entry_point web without http-01 must keep loading; the
// entry-point check applies only when the challenge route is rendered.
func TestHTTPEntryPointCheckOnlyWithHTTP01(t *testing.T) {
	for _, y := range []string{
		base + "traefik: {entry_point: web}\n",
		base + "traefik: {entry_point: web}\nacme: {http01_listen: ':8089'}\n",
	} {
		if errs := mustLoad(t, y).Validate(caps(true)); len(errs) != 0 {
			t.Fatalf("%s: errs = %v", y, errs)
		}
	}
	errs := mustLoad(t, http01Base+"acme: {http01_listen: ':8089'}\ntraefik: {entry_point: web}\n").Validate(caps(true))
	if !hasErr(errs, "traefik.http_entry_point must differ from traefik.entry_point (\"web\")") || !hasErr(errs, "http-01") {
		t.Fatalf("errs = %v", errs)
	}
	c := mustLoad(t, http01Base+"acme: {http01_listen: ':8089'}\n")
	if !c.UsesHTTP01() || mustLoad(t, base+"acme: {http01_listen: ':8089'}\n").UsesHTTP01() {
		t.Fatal("UsesHTTP01")
	}
}

func TestHTTP01Warnings(t *testing.T) {
	has := func(ws []string, s string) bool {
		for _, w := range ws {
			if strings.Contains(w, s) {
				return true
			}
		}
		return false
	}
	// No http-01: nothing.
	if ws := mustLoad(t, base+"acme: {http01_listen: '127.0.0.1:8089'}\n").HTTP01Warnings(); len(ws) != 0 {
		t.Fatalf("%v", ws)
	}
	// Default backend: the route is now rendered; the redirect priority.
	ws := mustLoad(t, http01Base+"acme: {http01_listen: ':8089'}\n").HTTP01Warnings()
	if len(ws) != 2 || !has(ws, "acme.http01_backend") || !has(ws, "priority: 1") || has(ws, "loopback") {
		t.Fatalf("%v", ws)
	}
	// Loopback listen with the default backend: unreachable.
	for _, l := range []string{"127.0.0.1:8089", "[::1]:8089", "localhost:8089"} {
		ws = mustLoad(t, http01Base+"acme: {http01_listen: '"+l+"'}\n").HTTP01Warnings()
		if !has(ws, "loopback") {
			t.Fatalf("%s: %v", l, ws)
		}
	}
	// Explicit backend: only the priority reminder (even if loopback).
	ws = mustLoad(t, http01Base+"acme: {http01_listen: '127.0.0.1:8089', http01_backend: 'http://127.0.0.1:8089'}\n").HTTP01Warnings()
	if len(ws) != 1 || !has(ws, "priority: 1") {
		t.Fatalf("%v", ws)
	}
}
