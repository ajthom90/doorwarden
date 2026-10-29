package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/traefik"
)

// End to end with the fake provider: an apex entry and www are routed,
// the apex A record is created at the zone name next to foreign apex
// records (which stay untouched), the listing shows the apex hostname,
// and a UI rename of the apex is refused.
func TestApexEndToEnd(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	for _, r := range []dns.Record{
		{Name: "example.test", Type: "NS", Value: "ns1.example.test"},
		{Name: "example.test", Type: "MX", Value: "10 mail.example.test"},
		{Name: "example.test", Type: "TXT", Value: "v=spf1 -all"},
	} {
		if _, err := e.fk.CreateRecord(ctx, "example.test", r); err != nil {
			t.Fatal(err)
		}
	}
	site := svc("docker", "site")
	site.Options.Apex = true
	e.src.set(nil, site, svc("docker", "www"))
	a := e.app()
	if res := a.RunOnce(ctx); res.Err != nil {
		t.Fatal(res.Err)
	}
	b, err := os.ReadFile(filepath.Join(e.dir, traefik.RoutesFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "Host(`example.test`)") || !strings.Contains(string(b), "Host(`www.example.test`)") {
		t.Fatalf("routes:\n%s", b)
	}
	if !hasA(t, e.fk, "example.test", "192.0.2.10") || !hasA(t, e.fk, "www.example.test", "192.0.2.10") {
		t.Fatal("apex/www A records missing")
	}
	recs, _ := e.fk.ListRecords(ctx, "example.test")
	n := 0
	for _, r := range recs {
		if r.Name == "example.test" && r.Type != "A" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("foreign apex records touched: %+v", recs)
	}
	s := info(t, a, "docker/site")
	if s.Hostname != "example.test" || !s.Apex {
		t.Fatalf("listing: %+v", s)
	}
	err = a.SetServiceOverride(ctx, "docker/site", func(o *model.UIOverrides) error { n := "x"; o.Rename = &n; return nil })
	var oe *model.OverrideError
	if !errors.As(err, &oe) {
		t.Fatalf("rename of apex: %v", err)
	}
}
