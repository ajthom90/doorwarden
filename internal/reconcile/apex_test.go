package reconcile

import (
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

func apexSvc(key, zone string) model.Service {
	s := pub(key, "site", zone, 80)
	s.Options.Apex = true
	return s
}

// per-host records + per-host certs: the apex gets its own A record at the
// zone name, its own certificate and a route, next to an ordinary www.
func TestPlanApexPerHost(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	desired := []model.Service{apexSvc("static:site", "example.test"), pub("static:www", "www", "example.test", 80)}
	acts := Plan(desired, Observed{Foreign: listed("example.test")}, cfg, t0)
	assertSums(t, acts,
		"DNSEnsure example.test example.test static:site [example.test A 192.0.2.10]",
		"DNSEnsure example.test www.example.test static:www [www.example.test A 192.0.2.10]",
		"CertEnsure example.test example.test static:site example.test",
		"CertEnsure example.test www.example.test static:www www.example.test",
		"RouteWrite example.test example.test static:site ->198.51.100.5:80",
		"RouteWrite example.test www.example.test static:www ->198.51.100.5:80",
	)
}

// Records Doorwarden does not own at the apex (NS, SOA, MX, TXT) never block
// the apex A record; a foreign A or CNAME at the apex is a Conflict, never
// overwritten.
func TestPlanApexForeignRecords(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	desired := []model.Service{apexSvc("static:site", "example.test")}
	benign := []dns.Record{
		{ID: "ns", Name: "example.test", Type: "NS", Value: "ns1.example.test"},
		{ID: "soa", Name: "example.test", Type: "SOA", Value: "ns1.example.test hostmaster.example.test 1 2 3 4 5"},
		{ID: "mx", Name: "example.test", Type: "MX", Value: "10 mail.example.test"},
		{ID: "txt", Name: "example.test", Type: "TXT", Value: "v=spf1 -all"},
	}
	acts := Plan(desired, Observed{Foreign: map[string][]dns.Record{"dnsp/example.test": benign}}, cfg, t0)
	if len(ofKind(acts, DNSEnsure)) != 1 || len(ofKind(acts, Conflict)) != 0 {
		t.Fatalf("benign apex records: %v", sums(acts))
	}
	for _, typ := range []string{"A", "CNAME"} {
		fr := append(append([]dns.Record{}, benign...), dns.Record{ID: "x", Name: "example.test", Type: typ, Value: "203.0.113.9"})
		acts := Plan(desired, Observed{Foreign: map[string][]dns.Record{"dnsp/example.test": fr}}, cfg, t0)
		c := ofKind(acts, Conflict)
		if len(c) != 1 || c[0].Record.Type != typ || len(ofKind(acts, DNSEnsure)) != 0 {
			t.Fatalf("foreign %s at the apex: %v", typ, sums(acts))
		}
		assertNone(t, acts, DNSDelete, DNSScheduleRemoval)
	}
}

// records.mode wildcard: "*.zone" does not cover the zone name, so the apex
// gets its own A record (owned by the apex service), and that record is
// wanted: never scheduled for removal as an orphan.
func TestPlanApexWildcardMode(t *testing.T) {
	cfg := cfgOf(zone("example.test", "wildcard", "wildcard"))
	desired := []model.Service{apexSvc("static:site", "example.test"), pub("static:www", "www", "example.test", 80)}
	acts := Plan(desired, Observed{Foreign: listed("example.test")}, cfg, t0)
	assertSums(t, ofKind(acts, DNSEnsure),
		"DNSEnsure example.test *.example.test [*.example.test A 192.0.2.10]",
		"DNSEnsure example.test example.test static:site [example.test A 192.0.2.10]",
	)
	if c := ofKind(acts, CertEnsure); len(c) != 1 || c[0].Names[0] != "*.example.test" || c[0].Names[1] != "example.test" {
		t.Fatalf("certs: %v", sums(c))
	}

	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{
		owned("example.test", "*.example.test", "A", target, WildcardOwnerKey("example.test")),
		owned("example.test", "example.test", "A", target, "static:site"),
	}}
	acts = Plan(desired, obs, cfg, t0)
	assertNone(t, acts, DNSEnsure, DNSScheduleRemoval, DNSDelete)

	// Once the apex entry is gone, its record is an orphan like any other.
	acts = Plan(desired[1:], obs, cfg, t0)
	if r := ofKind(acts, DNSScheduleRemoval); len(r) != 1 || r[0].Record.Name != "example.test" {
		t.Fatalf("orphan apex: %v", sums(acts))
	}
}

// Zones example.test and home.example.test: the sub-zone's apex is
// home.example.test, planned in the sub-zone (its provider and issuer), and
// never touches the parent's apex. It outranks a docker service named
// "home" in the parent zone (static > docker), which would map to the same
// hostname.
func TestPlanApexSubZone(t *testing.T) {
	parent, sub := zone("example.test", "per-host", "per-host"), zone("home.example.test", "per-host", "per-host")
	sub.Certificate.Issuer = "le2"
	cfg := cfgOf(parent, sub)
	desired := []model.Service{apexSvc("static:home", "home.example.test"), pub("docker:home", "home", "example.test", 80)}
	acts := Plan(desired, Observed{Foreign: listed("example.test", "home.example.test")}, cfg, t0)
	for _, a := range acts {
		if a.Host == "example.test" || (a.Record != nil && a.Record.Name == "example.test") {
			t.Fatalf("parent apex touched: %v", sum(a))
		}
	}
	w := forKey(ofKind(acts, RouteWrite), "static:home")
	if len(w) != 1 || w[0].Zone != "home.example.test" || w[0].Host != "home.example.test" {
		t.Fatalf("routes: %v", sums(acts))
	}
	if r := forKey(ofKind(acts, RouteWrite), "docker:home"); len(r) != 0 {
		t.Fatalf("docker loser routed: %v", sums(acts))
	}
	c := forKey(ofKind(acts, CertEnsure), "static:home")
	if len(c) != 1 || c[0].Zone != "home.example.test" || c[0].Issuer != "le2" {
		t.Fatalf("cert: %v", sums(acts))
	}
	d := ofKind(acts, DNSEnsure)
	if len(d) != 1 || d[0].Zone != "home.example.test" || d[0].Record.Name != "home.example.test" {
		t.Fatalf("dns: %v", sums(acts))
	}
}

// A covering certificate: wildcard [*.zone, zone] and a per-host cert for
// the apex both cover it (no CertEnsure); *.zone alone does not.
func TestPlanApexCertCoverage(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	desired := []model.Service{apexSvc("static:site", "example.test")}
	cert := func(names string) store.Cert {
		return store.Cert{ID: "c", Zone: "example.test", DomainsJSON: names, NotAfter: t0.AddDate(0, 2, 0)}
	}
	for names, want := range map[string]int{
		`["example.test"]`:                    0,
		`["*.example.test","example.test"]`:   0,
		`["*.example.test"]`:                  1,
		`["example.test","www.example.test"]`: 0,
	} {
		acts := Plan(desired, Observed{Foreign: listed("example.test"), Certs: []store.Cert{cert(names)}}, cfg, t0)
		if got := len(ofKind(acts, CertEnsure)); got != want {
			t.Errorf("%s: %d CertEnsure, want %d", names, got, want)
		}
	}
}
