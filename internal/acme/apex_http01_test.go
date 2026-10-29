package acme

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/ajthom90/doorwarden/internal/config"
)

// apexHTTP01Config: a zone whose DNS is hosted elsewhere (no records
// provider), certificates by http-01 from a production issuer.
func apexHTTP01Config() *config.Config {
	cfg := productionConfig()
	cfg.Zones = append(cfg.Zones, config.Zone{Name: "site.test", TargetIP: "192.0.2.10",
		Records:     config.Records{Mode: "off"},
		Certificate: config.Certificate{Issuer: "le", Strategy: "per-host", Challenge: "http-01"}})
	cfg.ACME.HTTP01Listen = "127.0.0.1:0"
	return cfg
}

// An imported per-host certificate for the apex and www (as Nginx Proxy
// Manager stores one) is adopted once due by an http-01 order for exactly
// its names, the apex included, when both are routes.
func TestImportedApexAdoptedByHTTP01(t *testing.T) {
	cfg := apexHTTP01Config()
	h := newHarness(t, cfg, func(mc *ManagerConfig) {
		mc.Wanted = func(zone string) []string {
			if zone == "site.test" {
				return []string{"site.test", "www.site.test"}
			}
			return nil
		}
	})
	chain, key := h.ca.ca.leaf(t, []string{"site.test", "www.site.test"}, t0.Add(20*24*time.Hour))
	ir, err := h.m.ImportPEM(ctx, "site.test", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	res := h.m.Renew(ctx)
	if len(res) != 1 || res[0].Err != nil || res[0].CertID != ir.Bundle.ID {
		t.Fatalf("%+v", res)
	}
	o := h.ca.last()
	if o.Challenge != ChallengeHTTP01 || !slices.Equal(o.Names, []string{"site.test", "www.site.test"}) {
		t.Fatalf("order %+v", o)
	}
	if r := h.row(t, ir.Bundle.ID); !r.Managed || r.Status != StatusValid {
		t.Fatalf("row %+v", r)
	}
	// No route for the apex any more: not ordered (only routes are).
	h2 := newHarness(t, apexHTTP01Config(), func(mc *ManagerConfig) {
		mc.Wanted = func(string) []string { return []string{"www.site.test"} }
	})
	chain, key = h2.ca.ca.leaf(t, []string{"site.test", "www.site.test"}, t0.Add(20*24*time.Hour))
	if _, err := h2.m.ImportPEM(ctx, "site.test", chain, key); err != nil {
		t.Fatal(err)
	}
	for _, r := range h2.m.Renew(ctx) {
		if r.Err == nil {
			t.Fatalf("unwanted apex certificate ordered: %+v", r)
		}
	}
	if h2.ca.count() != 0 {
		t.Fatal("ordered")
	}
	// The apex itself is orderable by http-01; its wildcard never is.
	if _, err := h.m.Issue(ctx, IssueRequest{Zone: "site.test", Names: []string{"*.site.test"}}); !errors.Is(err, ErrWildcardNeedsDNS01) {
		t.Fatalf("%v", err)
	}
}

// The default HTTP-01 solver is lego's server on acme.http01_listen only,
// and it answers a challenge request routed the way the rendered Traefik
// router forwards it (path /.well-known/acme-challenge/<token>, Host header
// passed through), for the apex too.
func TestDefaultHTTP01SolverBehindChallengeRoute(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	cfg := apexHTTP01Config()
	cfg.ACME.HTTP01Listen = addr
	h := newHarness(t, cfg, func(mc *ManagerConfig) { mc.HTTP01Provider = nil })
	p, err := h.m.http01()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Present("site.test", "tok123", "tok123.keyauth"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.CleanUp("site.test", "tok123", "tok123.keyauth") })
	get := func(host string) (int, string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/.well-known/acme-challenge/tok123", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("site.test"); code != http.StatusOK || strings.TrimSpace(body) != "tok123.keyauth" {
		t.Fatalf("apex: %d %q", code, body)
	}
	// lego matches the Host header: without passHostHeader (Traefik would
	// send the backend's host) the CA's request would not be answered.
	if _, body := get("doorwarden:8089"); strings.Contains(body, "keyauth") {
		t.Fatal("answered for a foreign Host header")
	}
	var _ challenge.Provider = p
}
