package traefik

import (
	"testing"

	"github.com/ajthom90/doorwarden/internal/store"
)

// An apex route renders Host(`zone`); a wildcard certificate alone does not
// cover it (KindNoCertificate), [*.zone, zone] does.
func TestRenderApexRoute(t *testing.T) {
	apex := store.Route{Key: "static:site", Source: "static", Zone: "example.test", Hostname: "example.test",
		Scheme: "http", Host: "198.51.100.5", Port: 80}
	routes := []store.Route{apex, rt("static:www", "www", 80)}
	_, _, d := mustRender(t, routes, nil, nil, Options{})
	if r := d.HTTP.Routers[Name("static:site")]; r.Rule != "Host(`example.test`)" {
		t.Fatalf("apex rule = %q", r.Rule)
	}
	noCert := func(certs []TLSCert) bool {
		_, probs, err := Render(routes, nil, certs, Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range probs {
			if p.Kind == KindNoCertificate && p.Hostname == "example.test" {
				return true
			}
		}
		return false
	}
	wc := TLSCert{ID: "w", Domains: []string{"*.example.test"}, CertFile: "w/1/fullchain.pem", KeyFile: "w/1/privkey.pem"}
	if !noCert([]TLSCert{wc}) {
		t.Fatal("*.example.test reported as covering the apex")
	}
	wc.Domains = append(wc.Domains, "example.test")
	if noCert([]TLSCert{wc}) {
		t.Fatal("[*.example.test, example.test] does not cover the apex")
	}
}
