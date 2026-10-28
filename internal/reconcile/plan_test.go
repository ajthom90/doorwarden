package reconcile

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// --- new services, record modes, certs -------------------------------------

func TestPlanNewServicePerHost(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 32768)}, Observed{Foreign: listed("example.test")}, cfg, t0)
	assertSums(t, got,
		"DNSEnsure example.test app.example.test docker:app [app.example.test A 192.0.2.10]",
		"CertEnsure example.test app.example.test docker:app app.example.test",
		"RouteWrite example.test app.example.test docker:app ->198.51.100.5:32768",
	)
	d := ofKind(got, DNSEnsure)[0]
	if d.Provider != "dnsp" || d.Owner != "docker:app" || d.Svc == nil || d.Svc.Key != "docker:app" {
		t.Fatalf("DNSEnsure fields: provider=%q owner=%q svc=%v", d.Provider, d.Owner, d.Svc)
	}
	if c := ofKind(got, CertEnsure)[0]; c.Issuer != "le" {
		t.Fatalf("CertEnsure issuer %q", c.Issuer)
	}
}

func TestPlanDefaultZone(t *testing.T) {
	one := []config.Zone{zone("example.test", "off", "wildcard")}
	two := []config.Zone{zone("example.test", "off", "wildcard"), zone("other.test", "off", "wildcard")}
	tests := []struct {
		name     string
		zones    []config.Zone
		def      string
		wantHost string // "" => Invalid
		msg      string
	}{
		{"no zones", nil, "", "", "no default_zone is set while 0 zones"},
		{"one zone implicit", one, "", "app.example.test", ""},
		{"two zones no default", two, "", "", "no default_zone is set while 2 zones"},
		{"two zones default second", two, "Other.Test.", "app.other.test", ""},
		{"one zone explicit default", one, "example.test", "app.example.test", ""},
		{"default not configured", two, "nope.test", "", "unknown zone"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgOf(tc.zones...)
			cfg.Settings.DefaultZone = tc.def
			// TrueNAS-style zone-less service
			s := pub("truenas:app", "app", "", 80)
			got := Plan([]model.Service{s}, Observed{}, cfg, t0)
			if tc.wantHost == "" {
				if len(got) != 1 || got[0].Kind != Invalid || !strings.Contains(got[0].Reason, tc.msg) {
					t.Fatalf("want Invalid %q, got %v %q", tc.msg, sums(got), func() string {
						if len(got) > 0 {
							return got[0].Reason
						}
						return ""
					}())
				}
				return
			}
			if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Host != tc.wantHost {
				t.Fatalf("route: %v", sums(got))
			}
			// an explicit zone is unaffected by the default
			s.Zone = "example.test"
			if r := ofKind(Plan([]model.Service{s}, Observed{}, cfg, t0), RouteWrite); len(r) != 1 || r[0].Host != "app.example.test" {
				t.Fatalf("explicit zone overridden")
			}
		})
	}
}

func TestPlanIPv6TargetUsesAAAA(t *testing.T) {
	z := zone("example.test", "per-host", "per-host")
	z.TargetIP = "2001:db8::10"
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, Observed{Foreign: listed("example.test")}, cfgOf(z), t0)
	d := ofKind(got, DNSEnsure)
	if len(d) != 1 || d[0].Record.Type != "AAAA" || d[0].Record.Value != "2001:db8::10" {
		t.Fatalf("got %v", sums(got))
	}
}

func TestPlanWildcardModeOneRecordPerZone(t *testing.T) {
	cfg := cfgOf(zone("example.test", "wildcard", "wildcard"), zone("other.test", "wildcard", "wildcard"))
	desired := []model.Service{
		pub("docker:a", "a", "example.test", 1),
		pub("docker:b", "b", "example.test", 2),
		pub("truenas:c", "c", "example.test", 3),
		pub("docker:d", "d", "other.test", 4),
	}
	got := Plan(desired, Observed{Foreign: listed("example.test", "other.test")}, cfg, t0)
	assertSums(t, ofKind(got, DNSEnsure),
		"DNSEnsure example.test *.example.test [*.example.test A 192.0.2.10]",
		"DNSEnsure other.test *.other.test [*.other.test A 192.0.2.10]",
	)
	if o := ofKind(got, DNSEnsure)[0].Owner; o != WildcardOwnerKey("example.test") {
		t.Fatalf("wildcard owner %q", o)
	}
	assertSums(t, ofKind(got, CertEnsure),
		"CertEnsure example.test *.example.test *.example.test,example.test",
		"CertEnsure other.test *.other.test *.other.test,other.test",
	)
	if n := len(ofKind(got, RouteWrite)); n != 4 {
		t.Fatalf("want 4 RouteWrite, got %d", n)
	}
}

func TestPlanWildcardNotEmittedForZoneWithoutPublished(t *testing.T) {
	cfg := cfgOf(zone("example.test", "wildcard", "wildcard"))
	got := Plan([]model.Service{svc("docker:a", "a", "example.test", model.StatePending, "198.51.100.5", 80)}, Observed{}, cfg, t0)
	if len(got) != 0 {
		t.Fatalf("want nothing, got %v", sums(got))
	}
}

func TestPlanWildcardIdempotentAndUpdate(t *testing.T) {
	cfg := cfgOf(zone("Example.Test.", "wildcard", "wildcard"))
	desired := []model.Service{pub("docker:a", "a", "example.test", 1)}
	tests := []struct {
		name  string
		owned []store.DNSRecord
		want  []string
	}{
		{"owned with right value", []store.DNSRecord{owned("example.test", "*.example.test", "A", target, WildcardOwnerKey("example.test"))}, nil},
		{"owned unnormalized", []store.DNSRecord{owned("EXAMPLE.test.", "*.Example.Test.", "a", target, WildcardOwnerKey("example.test"))}, nil},
		{"owned stale value", []store.DNSRecord{owned("example.test", "*.example.test", "A", "198.51.100.99", WildcardOwnerKey("example.test"))},
			[]string{"DNSEnsure example.test *.example.test [*.example.test A 192.0.2.10]"}},
		{"owned by other provider", []store.DNSRecord{{Provider: "other", Zone: "example.test", Name: "*.example.test", Type: "A", Value: target}},
			[]string{"DNSEnsure example.test *.example.test [*.example.test A 192.0.2.10]"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ofKind(Plan(desired, Observed{Owned: tc.owned, Foreign: listed("example.test")}, cfg, t0), DNSEnsure)
			assertSums(t, got, tc.want...)
			if len(got) == 1 && tc.name == "owned stale value" && got[0].Record.ID != "id-*.example.test" {
				t.Fatalf("update must carry provider record id, got %q", got[0].Record.ID)
			}
		})
	}
}

func TestPlanRecordsModeOffOrUnset(t *testing.T) {
	for _, mode := range []string{"off", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			cfg := cfgOf(zone("example.test", mode, "wildcard"))
			got := Plan([]model.Service{pub("docker:a", "a", "example.test", 1)}, Observed{}, cfg, t0)
			assertNone(t, got, DNSEnsure, DNSDelete)
			if len(ofKind(got, RouteWrite)) != 1 || len(ofKind(got, CertEnsure)) != 1 {
				t.Fatalf("mode off still gets route and cert: %v", sums(got))
			}
		})
	}
}

func TestPlanForeignRecordConflict(t *testing.T) {
	cfgPH := cfgOf(zone("example.test", "per-host", "per-host"))
	cfgWC := cfgOf(zone("example.test", "wildcard", "wildcard"))
	desired := []model.Service{pub("docker:app", "app", "example.test", 80)}
	tests := []struct {
		name     string
		cfg      *config.Config
		foreign  []dns.Record
		owned    []store.DNSRecord
		conflict bool
		ensure   int
	}{
		{"foreign same name+type", cfgPH, []dns.Record{{ID: "f1", Name: "app.example.test", Type: "A", Value: "198.51.100.7"}}, nil, true, 0},
		{"foreign exact desired value", cfgPH, []dns.Record{{ID: "f1", Name: "app.example.test", Type: "A", Value: target}}, nil, true, 0},
		{"foreign unnormalized name", cfgPH, []dns.Record{{Name: "APP.example.test.", Type: "a", Value: target}}, nil, true, 0},
		{"foreign CNAME same name", cfgPH, []dns.Record{{Name: "app.example.test", Type: "CNAME", Value: "elsewhere.example.test"}}, nil, true, 0},
		{"foreign other name", cfgPH, []dns.Record{{Name: "web.example.test", Type: "A", Value: target}}, nil, false, 1},
		{"foreign TXT same name", cfgPH, []dns.Record{{Name: "app.example.test", Type: "TXT", Value: "x"}}, nil, false, 1},
		{"listed but owned", cfgPH, []dns.Record{{Name: "app.example.test", Type: "A", Value: target}},
			[]store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:app")}, false, 0},
		{"foreign wildcard", cfgWC, []dns.Record{{Name: "*.example.test", Type: "A", Value: target}}, nil, true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs := Observed{Owned: tc.owned, Foreign: map[string][]dns.Record{"dnsp/example.test": tc.foreign}}
			got := Plan(desired, obs, tc.cfg, t0)
			c := ofKind(got, Conflict)
			if tc.conflict != (len(c) == 1) {
				t.Fatalf("conflict=%v want %v: %v", len(c), tc.conflict, sums(got))
			}
			if tc.conflict && !strings.Contains(c[0].Reason, "foreign record exists") {
				t.Fatalf("reason %q", c[0].Reason)
			}
			if n := len(ofKind(got, DNSEnsure)); n != tc.ensure {
				t.Fatalf("DNSEnsure=%d want %d: %v", n, tc.ensure, sums(got))
			}
			if len(ofKind(got, RouteWrite)) != 1 {
				t.Fatalf("a DNS conflict must not block the route: %v", sums(got))
			}
		})
	}
}

func TestPlanCerts(t *testing.T) {
	future, past := t0.Add(60*24*time.Hour), t0.Add(-time.Hour)
	cert := func(domains string, notAfter time.Time) store.Cert {
		return store.Cert{ID: "c", Zone: "example.test", DomainsJSON: domains, NotAfter: notAfter, Status: "ok"}
	}
	two := []model.Service{pub("docker:a", "a", "example.test", 1), pub("docker:b", "b", "example.test", 2)}
	tests := []struct {
		name     string
		strategy string
		certs    []store.Cert
		want     []string
	}{
		{"wildcard none", "wildcard", nil, []string{"CertEnsure example.test *.example.test *.example.test,example.test"}},
		{"wildcard default strategy", "", nil, []string{"CertEnsure example.test *.example.test *.example.test,example.test"}},
		{"wildcard covered", "wildcard", []store.Cert{cert(`["example.test","*.Example.test"]`, future)}, nil},
		{"wildcard expired", "wildcard", []store.Cert{cert(`["*.example.test","example.test"]`, past)},
			[]string{"CertEnsure example.test *.example.test *.example.test,example.test"}},
		{"wildcard partial", "wildcard", []store.Cert{cert(`["*.example.test"]`, future)},
			[]string{"CertEnsure example.test *.example.test *.example.test,example.test"}},
		{"wildcard bad json", "wildcard", []store.Cert{cert(`not json`, future)},
			[]string{"CertEnsure example.test *.example.test *.example.test,example.test"}},
		{"per-host none", "per-host", nil, []string{
			"CertEnsure example.test a.example.test docker:a a.example.test",
			"CertEnsure example.test b.example.test docker:b b.example.test"}},
		{"per-host one covered", "per-host", []store.Cert{cert(`["a.example.test"]`, future)}, []string{
			"CertEnsure example.test b.example.test docker:b b.example.test"}},
		{"per-host covered by wildcard cert", "per-host", []store.Cert{cert(`["*.example.test"]`, future)}, nil},
		{"san none", "san", nil, []string{"CertEnsure example.test a.example.test a.example.test,b.example.test"}},
		{"san one missing reissues all", "san", []store.Cert{cert(`["a.example.test"]`, future)},
			[]string{"CertEnsure example.test a.example.test a.example.test,b.example.test"}},
		{"san all covered", "san", []store.Cert{cert(`["a.example.test","b.example.test"]`, future)}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgOf(zone("example.test", "off", tc.strategy))
			assertSums(t, ofKind(Plan(two, Observed{Certs: tc.certs}, cfg, t0), CertEnsure), tc.want...)
		})
	}
	t.Run("no issuer means no certs", func(t *testing.T) {
		z := zone("example.test", "off", "wildcard")
		z.Certificate.Issuer = ""
		got := Plan(two, Observed{}, cfgOf(z), t0)
		assertNone(t, got, CertEnsure)
		if len(ofKind(got, RouteWrite)) != 2 {
			t.Fatalf("routes still written: %v", sums(got))
		}
	})
	t.Run("wildcard cert does not cover nested names", func(t *testing.T) {
		cfg := cfgOf(zone("example.test", "off", "per-host"))
		got := Plan([]model.Service{pub("docker:a", "a", "example.test", 1)},
			Observed{Certs: []store.Cert{cert(`["*.test"]`, future)}}, cfg, t0)
		if len(ofKind(got, CertEnsure)) != 1 {
			t.Fatalf("got %v", sums(got))
		}
	})
}

// --- non-published states ---------------------------------------------------

func TestPlanNonPublishedCreateNothing(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	for _, st := range []string{model.StatePending, model.StateDiscovered, model.StateError, model.StateStopped, model.StateConflict, ""} {
		t.Run("state="+st, func(t *testing.T) {
			got := Plan([]model.Service{svc("docker:a", "a", "example.test", st, "198.51.100.5", 80)}, Observed{}, cfg, t0)
			if len(got) != 0 {
				t.Fatalf("want no actions, got %v", sums(got))
			}
		})
	}
}

func TestPlanPublishedWithoutBackend(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	s := svc("docker:a", "a", "example.test", model.StatePublished, "", 0)
	got := Plan([]model.Service{s}, Observed{}, cfg, t0)
	assertSums(t, got, "Invalid example.test a.example.test docker:a")

	lk := model.Backend{Scheme: "http", Host: "198.51.100.5", Port: 4242}
	got = Plan([]model.Service{s}, Observed{LastKnown: map[string]model.Backend{"docker:a": lk}}, cfg, t0)
	if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Backend.Port != 4242 {
		t.Fatalf("want RouteWrite with last-known backend, got %v", sums(got))
	}
}

// --- rule 2: stopped / error keep last-known --------------------------------

func TestPlanStoppedKnownKeepsRoute(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	lk := model.Backend{Scheme: "http", Host: "198.51.100.5", Port: 32768}
	ownedRec := []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:app")}
	for _, st := range []string{model.StateStopped, model.StateError} {
		t.Run(st, func(t *testing.T) {
			s := svc("docker:app", "app", "example.test", st, "", 0)
			obs := Observed{Owned: ownedRec, Known: knownMap(known("docker:app", "example.test", "app.example.test", nil)),
				LastKnown: map[string]model.Backend{"docker:app": lk}}
			got := Plan([]model.Service{s}, obs, cfg, t0)
			assertSums(t, got, "RouteWrite example.test app.example.test docker:app ->198.51.100.5:32768")

			obs.LastKnown = nil
			got = Plan([]model.Service{s}, obs, cfg, t0)
			assertSums(t, got, "Skip example.test app.example.test docker:app")
			if !strings.Contains(got[0].Reason, "last-known") {
				t.Fatalf("reason %q", got[0].Reason)
			}
		})
	}
}

func TestPlanStopRestartOnNewPort(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	obs := Observed{Known: map[string]KnownService{}, LastKnown: map[string]model.Backend{}, Foreign: listed("example.test")}
	// The orchestrator's bookkeeping, simulated: only RouteWrites for
	// non-stopped services update LastKnown (Discovered/Published backends).
	persist := func(desired []model.Service, acts []Action) {
		for _, a := range acts {
			switch a.Kind {
			case DNSEnsure:
				obs.Owned = append(obs.Owned, store.DNSRecord{Provider: a.Provider, Zone: a.Zone, Name: a.Record.Name,
					Type: a.Record.Type, Value: a.Record.Value, OwnerKey: a.Owner})
			case RouteWrite:
				obs.Known[a.Key] = KnownService{Key: a.Key, Source: a.Svc.Source, Zone: a.Zone, Hostname: a.Host}
			}
		}
		for _, s := range desired {
			if s.State == model.StatePublished {
				obs.LastKnown[s.Key] = s.Backend
			}
		}
	}

	running := pub("docker:app", "app", "example.test", 32768)
	a1 := Plan([]model.Service{running}, obs, cfg, t0)
	persist([]model.Service{running}, a1)
	if r := ofKind(a1, RouteWrite); len(r) != 1 || r[0].Backend.Port != 32768 {
		t.Fatalf("cycle 1: %v", sums(a1))
	}

	stopped := svc("docker:app", "app", "example.test", model.StateStopped, "", 0)
	a2 := Plan([]model.Service{stopped}, obs, cfg, t0.Add(time.Minute))
	persist([]model.Service{stopped}, a2)
	assertNone(t, a2, RouteRemove, DNSDelete, ScheduleRemoval, DNSEnsure, CertEnsure)
	if r := ofKind(a2, RouteWrite); len(r) != 1 || r[0].Backend == nil || r[0].Backend.Port != 32768 || r[0].Backend.Host != "198.51.100.5" {
		t.Fatalf("cycle 2 must emit exactly one RouteWrite carrying the last-known backend, got %v", sums(a2))
	}
	if lk := obs.LastKnown["docker:app"]; lk.Port != 32768 {
		t.Fatalf("stopped service overwrote last-known: %+v", lk)
	}

	restarted := pub("docker:app", "app", "example.test", 32999)
	a3 := Plan([]model.Service{restarted}, obs, cfg, t0.Add(2*time.Minute))
	assertNone(t, a3, RouteRemove, DNSDelete, ScheduleRemoval, DNSEnsure)
	if r := ofKind(a3, RouteWrite); len(r) != 1 || r[0].Backend.Port != 32999 {
		t.Fatalf("cycle 3 RouteWrite must carry the new backend: %v", sums(a3))
	}
}

// --- rule 1: source outage --------------------------------------------------

func TestPlanUnavailableSourceNeverRemoves(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	ownedRec := []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "truenas:app")}
	for _, ra := range []*time.Time{nil, tp(t0.Add(-time.Hour)), tp(t0.Add(time.Hour))} {
		obs := Observed{Owned: ownedRec, Unavailable: map[string]bool{"truenas": true},
			Known: knownMap(known("truenas:app", "example.test", "app.example.test", ra))}
		got := Plan(nil, obs, cfg, t0)
		if len(got) != 0 {
			t.Fatalf("removedAfter=%v: want no actions, got %v", ra, sums(got))
		}
	}
}

func TestPlanUnavailableSourceStillClaimsHostname(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	obs := Observed{Unavailable: map[string]bool{"truenas": true}, LastKnown: map[string]model.Backend{
		"docker:app": {Scheme: "http", Host: "198.51.100.5", Port: 81}},
		Known: knownMap(known("truenas:app", "example.test", "app.example.test", nil),
			known("docker:app", "example.test", "app.example.test", nil))}
	// A non-published claimant loses to the phantom (higher source rank).
	stopped := svc("docker:app", "app", "example.test", model.StateStopped, "", 0)
	got := Plan([]model.Service{stopped}, obs, cfg, t0)
	assertSums(t, got, "Conflict example.test app.example.test docker:app")
	if !strings.Contains(got[0].Reason, "truenas:app") {
		t.Fatalf("reason %q", got[0].Reason)
	}
	// Source-first: even a Published docker claimant loses to the phantom of
	// a higher-ranked source, and its Known route is not removed.
	got = Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, cfg, t0)
	assertSums(t, got, "Conflict example.test app.example.test docker:app")
}

func TestPlanOtherSourcesUnaffectedByOutage(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	obs := Observed{Unavailable: map[string]bool{"truenas": true},
		Known: knownMap(known("docker:gone", "example.test", "gone.example.test", nil))}
	got := Plan(nil, obs, cfg, t0)
	assertSums(t, got, "ScheduleRemoval example.test gone.example.test docker:gone")
}

// --- rule 6: removal and grace ----------------------------------------------

func TestPlanRemoval(t *testing.T) {
	ph := cfgOf(zone("example.test", "per-host", "per-host"))
	wc := cfgOf(zone("example.test", "wildcard", "wildcard"))
	recs := []store.DNSRecord{
		owned("example.test", "app.example.test", "A", target, "docker:app"),
		owned("example.test", "*.example.test", "A", target, WildcardOwnerKey("example.test")),
		owned("example.test", "other.example.test", "A", target, "docker:other"),
	}
	foreign := map[string][]dns.Record{"dnsp/example.test": {{Name: "app.example.test", Type: "AAAA", Value: "2001:db8::1"}}}
	tests := []struct {
		name  string
		cfg   *config.Config
		ra    *time.Time
		owned []store.DNSRecord
		want  []string
	}{
		{"first absence schedules", ph, nil, recs, []string{"ScheduleRemoval example.test app.example.test docker:app"}},
		{"within grace", ph, tp(t0.Add(time.Minute)), recs, nil},
		{"exactly at deadline waits", ph, tp(t0), recs, nil},
		{"past grace per-host", ph, tp(t0.Add(-time.Second)), recs, []string{
			"RouteRemove example.test app.example.test docker:app",
			"DNSDelete example.test app.example.test docker:app [app.example.test A 192.0.2.10]"}},
		{"past grace not owned", ph, tp(t0.Add(-time.Second)), nil, []string{"RouteRemove example.test app.example.test docker:app"}},
		{"past grace owned by other key", ph, tp(t0.Add(-time.Second)),
			[]store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:someone")},
			[]string{"RouteRemove example.test app.example.test docker:app"}},
		{"past grace wildcard never deletes wildcard record", wc, tp(t0.Add(-time.Second)), recs,
			[]string{"RouteRemove example.test app.example.test docker:app"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs := Observed{Owned: tc.owned, Foreign: foreign, Known: knownMap(known("docker:app", "example.test", "app.example.test", tc.ra))}
			got := Plan(nil, obs, tc.cfg, t0)
			assertSums(t, got, tc.want...)
			if s := ofKind(got, ScheduleRemoval); len(s) == 1 {
				if s[0].RemovedAfter == nil || !s[0].RemovedAfter.Equal(t0.Add(24*time.Hour)) {
					t.Fatalf("RemovedAfter %v", s[0].RemovedAfter)
				}
			}
			if d := ofKind(got, DNSDelete); len(d) == 1 {
				if d[0].Record.ID != "id-app.example.test" || d[0].Provider != "dnsp" {
					t.Fatalf("delete must target the owned record id: %+v", d[0].Record)
				}
			}
		})
	}
}

func TestPlanRemovalGraceDefaultsWhenUnset(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	cfg.Settings.GracePeriod = 0
	got := Plan(nil, Observed{Known: knownMap(known("docker:app", "example.test", "app.example.test", nil))}, cfg, t0)
	if s := ofKind(got, ScheduleRemoval); len(s) != 1 || !s[0].RemovedAfter.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("got %v", sums(got))
	}
}

func TestPlanRemovalSkipsDNSDeleteWhenHostnameTakenOver(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	obs := Observed{
		Owned: []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:old")},
		Known: knownMap(known("docker:old", "example.test", "app.example.test", tp(t0.Add(-time.Hour)))),
	}
	got := Plan([]model.Service{pub("docker:new", "app", "example.test", 80)}, obs, cfg, t0)
	assertNone(t, got, DNSDelete, DNSEnsure)
	if len(ofKind(got, RouteRemove)) != 1 || len(ofKind(got, RouteWrite)) != 1 {
		t.Fatalf("got %v", sums(got))
	}
}

func TestPlanReappearanceCancelsRemoval(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	for _, st := range []string{model.StatePublished, model.StatePending, model.StateStopped} {
		t.Run(st, func(t *testing.T) {
			s := svc("docker:app", "app", "example.test", st, "198.51.100.5", 80)
			for _, ra := range []*time.Time{tp(t0.Add(time.Hour)), tp(t0.Add(-time.Hour))} {
				obs := Observed{Known: knownMap(known("docker:app", "example.test", "app.example.test", ra))}
				got := Plan([]model.Service{s}, obs, cfg, t0)
				if c := ofKind(got, CancelRemoval); len(c) != 1 || c[0].Key != "docker:app" {
					t.Fatalf("want CancelRemoval, got %v", sums(got))
				}
				assertNone(t, got, RouteRemove, DNSDelete, ScheduleRemoval)
			}
		})
	}
}

// --- rule 3: hostname conflicts, invalid services ---------------------------

func TestPlanHostnameConflicts(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	renamed := func(s model.Service, r string) model.Service { s.Options.Rename = r; return s }
	tests := []struct {
		name   string
		in     []model.Service
		winner string
		losers []string
	}{
		{"static beats docker", []model.Service{pub("docker:app", "app", "example.test", 1), pub("static:app", "App", "EXAMPLE.test", 2)}, "static:app", []string{"docker:app"}},
		{"truenas beats docker", []model.Service{pub("docker:x", "x", "example.test", 1), renamed(pub("truenas:y", "y", "example.test", 2), "X")}, "truenas:y", []string{"docker:x"}},
		{"static beats truenas", []model.Service{pub("truenas:app", "app", "example.test", 1), pub("static:app", "app", "example.test", 2)}, "static:app", []string{"truenas:app"}},
		{"same source by key", []model.Service{renamed(pub("docker:b", "b", "example.test", 1), "app"), renamed(pub("docker:a", "a", "example.test", 2), "app"), renamed(pub("docker:c", "c", "example.test", 3), "APP")}, "docker:a", []string{"docker:b", "docker:c"}},
		{"slug collision", []model.Service{pub("docker:my_app", "my_app", "example.test", 1), pub("docker:my-app", "my-app", "example.test", 2)}, "docker:my-app", []string{"docker:my_app"}},
		{"pending static beats published docker", []model.Service{pub("docker:app", "app", "example.test", 1), svc("static:app", "app", "example.test", model.StatePending, "198.51.100.5", 2)}, "static:app", []string{"docker:app"}},
		{"error static beats published docker", []model.Service{pub("docker:app", "app", "example.test", 1), svc("static:app", "app", "example.test", model.StateError, "", 0)}, "static:app", []string{"docker:app"}},
		{"key prefix beats source name", []model.Service{
			func() model.Service { s := pub("static:x", "app", "example.test", 1); s.Source = "docker"; return s }(),
			func() model.Service { s := pub("docker:y", "app", "example.test", 2); s.Source = "static"; return s }()}, "static:x", []string{"docker:y"}},
		{"source name fallback for unknown prefix", []model.Service{
			func() model.Service { s := pub("custom:a", "app", "example.test", 1); s.Source = "docker"; return s }(),
			func() model.Service { s := pub("custom:b", "app", "example.test", 2); s.Source = "static"; return s }()}, "custom:b", []string{"custom:a"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Plan(tc.in, Observed{}, cfg, t0)
			for _, l := range tc.losers {
				acts := forKey(got, l)
				if len(acts) != 1 || acts[0].Kind != Conflict || !strings.Contains(acts[0].Reason, tc.winner) {
					t.Fatalf("loser %s: %v", l, sums(acts))
				}
			}
			for _, a := range got {
				if a.Kind != Conflict && a.Key != "" && a.Key != tc.winner {
					t.Fatalf("non-winner got %v", sum(a))
				}
			}
			if dn := ofKind(got, DNSEnsure); len(dn) > 1 {
				t.Fatalf("one hostname must get at most one record: %v", sums(dn))
			}
		})
	}
}

func TestPlanInvalidServices(t *testing.T) {
	long := strings.Repeat("a", 60)
	longZone := strings.Join([]string{long, long, long, "example", "test"}, ".") // 195 chars
	cfg := cfgOf(zone("example.test", "per-host", "per-host"), zone(longZone, "per-host", "per-host"))
	tests := []struct {
		name string
		s    model.Service
		msg  string
	}{
		{"unknown zone", pub("docker:a", "a", "nope.test", 1), "unknown zone"},
		{"bad name", pub("docker:b", "---", "example.test", 1), "no characters"},
		{"too long", pub("docker:c", strings.Repeat("c", 63), longZone, 1), "253"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Plan([]model.Service{tc.s}, Observed{}, cfg, t0)
			if len(got) != 1 || got[0].Kind != Invalid || !strings.Contains(got[0].Reason, tc.msg) {
				t.Fatalf("got %v (reason %q)", sums(got), func() string {
					if len(got) > 0 {
						return got[0].Reason
					}
					return ""
				}())
			}
		})
	}
	t.Run("no zones configured", func(t *testing.T) {
		got := Plan([]model.Service{pub("docker:a", "a", "", 1)}, Observed{}, cfgOf(), t0)
		if len(got) != 1 || got[0].Kind != Invalid {
			t.Fatalf("got %v", sums(got))
		}
	})
	t.Run("invalid known stopped service removes nothing", func(t *testing.T) {
		obs := Observed{Known: knownMap(known("docker:b", "example.test", "b.example.test", nil))}
		got := Plan([]model.Service{svc("docker:b", "---", "example.test", model.StateStopped, "", 0)}, obs, cfg, t0)
		assertNone(t, got, RouteRemove, DNSDelete, ScheduleRemoval)
	})
}

// --- rule 9: determinism, duplicates ----------------------------------------

func TestPlanDuplicateKeysLastWins(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	first := pub("docker:app", "app", "example.test", 1)
	last := pub("docker:app", "app", "example.test", 2)
	got := Plan([]model.Service{first, last}, Observed{}, cfg, t0)
	if inv := ofKind(got, Invalid); len(inv) != 1 || !strings.Contains(inv[0].Reason, "duplicate") {
		t.Fatalf("want one Invalid duplicate, got %v", sums(got))
	}
	if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Backend.Port != 2 {
		t.Fatalf("last must win: %v", sums(got))
	}
}

func TestPlanDeterministic(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"), zone("other.test", "wildcard", "san"))
	desired := []model.Service{
		pub("docker:c", "c", "other.test", 3), pub("docker:a", "a", "example.test", 1),
		pub("static:b", "b", "example.test", 2), pub("docker:b", "b", "example.test", 9),
		pub("truenas:z", "z", "other.test", 4), pub("docker:bad", "x", "nope.test", 5),
	}
	obs := Observed{Known: knownMap(known("docker:gone", "example.test", "gone.example.test", nil),
		known("docker:old", "example.test", "old.example.test", tp(t0.Add(-time.Hour))))}
	want := sums(Plan(desired, obs, cfg, t0))
	for i := 0; i < 20; i++ {
		perm := append([]model.Service{}, desired...)
		for j := range perm { // deterministic rotation-based shuffle
			k := (j*7 + i) % len(perm)
			perm[j], perm[k] = perm[k], perm[j]
		}
		if got := sums(Plan(perm, obs, cfg, t0)); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("order-dependent output:\n%v\nvs\n%v", got, want)
		}
	}
	// kind order: Invalid/Conflict first, then bookkeeping, then ensures, then removals
	rank := map[ActionKind]int{}
	for i, k := range KindOrder {
		rank[k] = i
	}
	gotActs := Plan(desired, obs, cfg, t0)
	for i := 1; i < len(gotActs); i++ {
		if rank[gotActs[i-1].Kind] > rank[gotActs[i].Kind] {
			t.Fatalf("not sorted by kind: %v", sums(gotActs))
		}
	}
}

// --- property: applying DNSEnsure makes the next plan quiet -----------------

func TestPlanIdempotentAfterApplyingDNSEnsure(t *testing.T) {
	cfgs := []*config.Config{
		cfgOf(zone("example.test", "per-host", "per-host"), zone("other.test", "wildcard", "wildcard")),
		cfgOf(zone("Example.Test.", "wildcard", "san"), zone("other.test", "per-host", "san")),
	}
	names := []string{"a", "b", "c", "d", "e"}
	zones := []string{"example.test", "other.test", ""}
	prefixes := []string{"docker:", "truenas:", "static:"}
	for ci, cfg := range cfgs {
		for seed := 0; seed < 30; seed++ {
			var desired []model.Service
			for i := 0; i < 1+seed%6; i++ {
				n := names[(seed+i*3)%len(names)]
				desired = append(desired, pub(prefixes[(seed+i)%3]+n+string(rune('0'+i)), n, zones[(seed*i+i)%3], 1000+i))
			}
			obs := Observed{Foreign: listed("example.test", "other.test")}
			acts := Plan(desired, obs, cfg, t0)
			for _, a := range ofKind(acts, DNSEnsure) {
				obs.Owned = append(obs.Owned, store.DNSRecord{Provider: a.Provider, Zone: a.Zone, Name: a.Record.Name,
					Type: a.Record.Type, Value: a.Record.Value, OwnerKey: a.Owner})
			}
			again := Plan(desired, obs, cfg, t0)
			if d := ofKind(again, DNSEnsure); len(d) != 0 {
				t.Fatalf("cfg %d seed %d: re-plan emitted %v", ci, seed, sums(d))
			}
			if strings.Join(sortedCopy(sums(ofKind(again, RouteWrite))), "|") != strings.Join(sortedCopy(sums(ofKind(acts, RouteWrite))), "|") {
				t.Fatalf("cfg %d seed %d: routes changed", ci, seed)
			}
		}
	}
}

func TestPlanDoesNotMutateInputs(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	desired := []model.Service{pub("docker:b", "b", "example.test", 1), pub("docker:a", "a", "example.test", 2)}
	orig := append([]model.Service{}, desired...)
	acts := Plan(desired, Observed{}, cfg, t0)
	for i := range desired {
		if desired[i].Key != orig[i].Key {
			t.Fatalf("desired reordered")
		}
	}
	for _, a := range acts {
		if a.Svc != nil {
			a.Svc.Name = "mutated"
		}
		if a.Backend != nil {
			a.Backend.Port = -1
		}
	}
	if desired[0].Name != "b" || desired[0].Backend.Port != 1 {
		t.Fatalf("actions alias caller's services")
	}
}

// --- fix round 1 ------------------------------------------------------------

func TestPlanPublishedTierBeatsExistingRoute(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	lk := map[string]model.Backend{"docker:app_v1": {Scheme: "http", Host: "198.51.100.5", Port: 1111}}
	v1 := svc("docker:app_v1", "app", "example.test", model.StateStopped, "", 0)
	v2 := pub("docker:app_v2", "app", "example.test", 2222)
	obs := Observed{LastKnown: lk, Known: knownMap(known("docker:app_v1", "example.test", "app.example.test", nil))}
	got := Plan([]model.Service{v1, v2}, obs, cfg, t0)
	assertSums(t, got,
		"Conflict example.test app.example.test docker:app_v1",
		"CertEnsure example.test *.example.test *.example.test,example.test",
		"RouteWrite example.test app.example.test docker:app_v2 ->198.51.100.5:2222",
		"RouteRemove example.test app.example.test docker:app_v1",
	)
}

func TestPlanNonPublishedClaimantsDecidedByRank(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	lk := map[string]model.Backend{"docker:app": {Scheme: "http", Host: "198.51.100.5", Port: 1111}}
	st := svc("static:app", "app", "example.test", model.StatePending, "198.51.100.6", 80)
	dk := svc("docker:app", "app", "example.test", model.StateStopped, "", 0)
	// docker has an existing route but loses to a higher-ranked non-published
	// claimant: Conflict only (the winner is not published, so no RouteRemove),
	// and the pending winner creates nothing.
	got := Plan([]model.Service{st, dk}, Observed{LastKnown: lk,
		Known: knownMap(known("docker:app", "example.test", "app.example.test", nil))}, cfg, t0)
	assertSums(t, got, "Conflict example.test app.example.test docker:app")
	// without Known nothing has a route
	got = Plan([]model.Service{st, dk}, Observed{LastKnown: lk}, cfg, t0)
	assertSums(t, got, "Conflict example.test app.example.test docker:app")
}

func TestPlanLoserRouteRemovedThenRestored(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	obs := Observed{Foreign: listed("example.test"),
		Owned: []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:app")},
		Known: knownMap(known("docker:app", "example.test", "app.example.test", nil))}
	dk := pub("docker:app", "app", "example.test", 1)
	st := pub("static:app", "app", "example.test", 2)

	got := Plan([]model.Service{dk, st}, obs, cfg, t0)
	dkActs := forKey(got, "docker:app")
	assertSums(t, dkActs, "Conflict example.test app.example.test docker:app", "RouteRemove example.test app.example.test docker:app")
	if !strings.Contains(dkActs[1].Reason, "static:app") {
		t.Fatalf("RouteRemove reason %q", dkActs[1].Reason)
	}
	assertNone(t, got, DNSDelete, DNSEnsure) // the record already has the right value
	if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Key != "static:app" {
		t.Fatalf("winner route: %v", sums(got))
	}

	// caller forgets docker:app after its RouteRemove: no flapping
	obs.Known = knownMap(known("static:app", "example.test", "app.example.test", nil))
	got = Plan([]model.Service{dk, st}, obs, cfg, t0)
	assertSums(t, forKey(got, "docker:app"), "Conflict example.test app.example.test docker:app")

	// winner disappears: docker is no longer a loser and gets its route back
	got = Plan([]model.Service{dk}, obs, cfg, t0)
	if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Key != "docker:app" {
		t.Fatalf("docker route not restored: %v", sums(got))
	}
	assertNone(t, got, Conflict, DNSDelete)
}

func TestPlanUnknownForeignListing(t *testing.T) {
	ph := cfgOf(zone("example.test", "per-host", "per-host"))
	wc := cfgOf(zone("example.test", "wildcard", "wildcard"))
	desired := []model.Service{pub("docker:app", "app", "example.test", 80)}
	tests := []struct {
		name    string
		cfg     *config.Config
		foreign map[string][]dns.Record
		owned   []store.DNSRecord
		want    []string // DNS-related actions (Skip/Conflict/DNSEnsure)
	}{
		{"absent per-host", ph, nil, nil, []string{"Skip example.test app.example.test docker:app"}},
		{"absent wildcard", wc, nil, nil, []string{"Skip example.test *.example.test"}},
		{"absent other zone listed", ph, listed("other.test"), nil, []string{"Skip example.test app.example.test docker:app"}},
		{"present nil slice", ph, map[string][]dns.Record{"dnsp/example.test": nil}, nil,
			[]string{"DNSEnsure example.test app.example.test docker:app [app.example.test A 192.0.2.10]"}},
		{"present empty unnormalized key", ph, map[string][]dns.Record{"dnsp/Example.Test.": {}}, nil,
			[]string{"DNSEnsure example.test app.example.test docker:app [app.example.test A 192.0.2.10]"}},
		{"absent but owned stale value updates", ph, nil,
			[]store.DNSRecord{owned("example.test", "app.example.test", "A", "198.51.100.99", "docker:app")},
			[]string{"DNSEnsure example.test app.example.test docker:app [app.example.test A 192.0.2.10]"}},
		{"listed identical user record conflicts", ph, map[string][]dns.Record{"dnsp/example.test": {{Name: "app.example.test", Type: "A", Value: target}}}, nil,
			[]string{"Conflict example.test app.example.test docker:app [app.example.test A 192.0.2.10]"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Plan(desired, Observed{Foreign: tc.foreign, Owned: tc.owned}, tc.cfg, t0)
			var dnsActs []Action
			for _, a := range got {
				if a.Kind == Skip || a.Kind == Conflict || a.Kind == DNSEnsure {
					dnsActs = append(dnsActs, a)
				}
			}
			assertSums(t, dnsActs, tc.want...)
			if len(dnsActs) == 1 && dnsActs[0].Kind == Skip && !strings.Contains(dnsActs[0].Reason, "foreign records for dnsp/example.test unknown") {
				t.Fatalf("reason %q", dnsActs[0].Reason)
			}
			if len(ofKind(got, RouteWrite)) != 1 || len(ofKind(got, CertEnsure)) != 1 {
				t.Fatalf("routes/certs must proceed: %v", sums(got))
			}
		})
	}
}

func TestPlanForeignNormalizationDeterministic(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	foreign := map[string][]dns.Record{
		"dnsp/example.test":  {{Name: "app.example.test", Type: "A", Value: "198.51.100.1"}},
		"dnsp/EXAMPLE.TEST.": {{Name: "app.example.test", Type: "A", Value: "198.51.100.2"}},
		"dnsp/Example.Test":  {{Name: "app.example.test", Type: "A", Value: "198.51.100.3"}},
	}
	want := ""
	for i := 0; i < 50; i++ {
		c := ofKind(Plan([]model.Service{pub("docker:app", "app", "example.test", 1)}, Observed{Foreign: foreign}, cfg, t0), Conflict)
		if len(c) != 1 {
			t.Fatalf("got %v", sums(c))
		}
		if i == 0 {
			want = c[0].Reason
		} else if c[0].Reason != want {
			t.Fatalf("map-order dependent: %q vs %q", c[0].Reason, want)
		}
	}
}

func TestPlanInvalidTargetIPSkipsDNSOnly(t *testing.T) {
	for _, mode := range []string{"per-host", "wildcard"} {
		t.Run(mode, func(t *testing.T) {
			z := zone("example.test", mode, "wildcard")
			z.TargetIP = "not-an-ip"
			got := Plan([]model.Service{pub("docker:app", "app", "example.test", 1)}, Observed{Foreign: listed("example.test")}, cfgOf(z), t0)
			sk := ofKind(got, Skip)
			if len(sk) != 1 || !strings.Contains(sk[0].Reason, "target_ip") {
				t.Fatalf("got %v", sums(got))
			}
			assertNone(t, got, DNSEnsure, DNSDelete)
			if len(ofKind(got, RouteWrite)) != 1 {
				t.Fatalf("route must proceed: %v", sums(got))
			}
		})
	}
}

func TestPlanZoneRemovedFromConfig(t *testing.T) {
	cfg := cfgOf(zone("other.test", "per-host", "per-host"))
	ownedRec := []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:app")}
	k := known("docker:app", "example.test", "app.example.test", nil)
	t.Run("present service", func(t *testing.T) {
		obs := Observed{Owned: ownedRec, Foreign: listed("example.test", "other.test"), Known: knownMap(k)}
		got := Plan([]model.Service{pub("docker:app", "app", "example.test", 1)}, obs, cfg, t0)
		if len(got) != 1 || got[0].Kind != Invalid {
			t.Fatalf("want only Invalid, got %v", sums(got))
		}
	})
	t.Run("absent service past grace", func(t *testing.T) {
		k := k
		k.RemovedAfter = tp(t0.Add(-time.Hour))
		obs := Observed{Owned: ownedRec, Known: knownMap(k)}
		got := Plan(nil, obs, cfg, t0)
		assertNone(t, got, DNSDelete)
		assertSums(t, got, "RouteRemove example.test app.example.test docker:app")
	})
}

func TestPlanStoppedOnlyZoneKeepsZoneLevelActions(t *testing.T) {
	cfg := cfgOf(zone("example.test", "wildcard", "wildcard"))
	obs := Observed{Foreign: listed("example.test"),
		LastKnown: map[string]model.Backend{"docker:app": {Scheme: "http", Host: "198.51.100.5", Port: 1}},
		Known:     knownMap(known("docker:app", "example.test", "app.example.test", nil))}
	got := Plan([]model.Service{svc("docker:app", "app", "example.test", model.StateStopped, "", 0)}, obs, cfg, t0)
	assertSums(t, got,
		"DNSEnsure example.test *.example.test [*.example.test A 192.0.2.10]",
		"CertEnsure example.test *.example.test *.example.test,example.test",
		"RouteWrite example.test app.example.test docker:app ->198.51.100.5:1",
	)
}

// --- fix round 2: source-first ranking --------------------------------------

func TestPlanLowerSourceNeverBeatsHigherSource(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	dk := pub("docker:app", "app", "example.test", 80)
	dkKnown := known("docker:app", "example.test", "app.example.test", nil)
	tests := []struct {
		name   string
		higher []model.Service
		obs    Observed
	}{
		{"pending static", []model.Service{svc("static:app", "app", "example.test", model.StatePending, "198.51.100.6", 80)}, Observed{}},
		{"error static", []model.Service{svc("static:app", "app", "example.test", model.StateError, "", 0)}, Observed{}},
		{"stopped truenas", []model.Service{svc("truenas:app", "app", "example.test", model.StateStopped, "", 0)}, Observed{}},
		{"pending truenas", []model.Service{svc("truenas:app", "app", "example.test", model.StatePending, "198.51.100.6", 80)}, Observed{}},
		{"phantom truenas", nil, Observed{Unavailable: map[string]bool{"truenas": true},
			Known: knownMap(known("truenas:app", "example.test", "app.example.test", nil))}},
	}
	for _, tc := range tests {
		for _, withKnown := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/dockerKnown=%v", tc.name, withKnown), func(t *testing.T) {
				obs := tc.obs
				if withKnown {
					m := knownMap(dkKnown)
					for k, v := range obs.Known {
						m[k] = v
					}
					obs.Known = m
				}
				got := Plan(append([]model.Service{dk}, tc.higher...), obs, cfg, t0)
				assertSums(t, forKey(got, "docker:app"), "Conflict example.test app.example.test docker:app")
				assertNone(t, got, RouteWrite, RouteRemove)
			})
		}
	}
}

func TestPlanLoserRouteRemovedOnlyWhenWinnerRouted(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	dk := pub("docker:app", "app", "example.test", 80)
	obs := Observed{Known: knownMap(known("docker:app", "example.test", "app.example.test", nil))}

	// (ii) routable static winner: docker's Known route is removed
	got := Plan([]model.Service{dk, pub("static:app", "app", "example.test", 81)}, obs, cfg, t0)
	assertSums(t, forKey(got, "docker:app"), "Conflict example.test app.example.test docker:app", "RouteRemove example.test app.example.test docker:app")
	if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Key != "static:app" {
		t.Fatalf("winner route: %v", sums(got))
	}

	// winner routable only via LastKnown still counts
	noBackend := svc("static:app", "app", "example.test", model.StatePublished, "", 0)
	lkObs := obs
	lkObs.LastKnown = map[string]model.Backend{"static:app": {Scheme: "http", Host: "198.51.100.6", Port: 82}}
	got = Plan([]model.Service{dk, noBackend}, lkObs, cfg, t0)
	if len(ofKind(got, RouteRemove)) != 1 || len(ofKind(got, RouteWrite)) != 1 {
		t.Fatalf("LastKnown winner: %v", sums(got))
	}

	// (iii) static published without any backend: Invalid, nobody removed, but
	// static still holds the name (source-first), so docker gets no new route.
	got = Plan([]model.Service{dk, noBackend}, obs, cfg, t0)
	assertNone(t, got, RouteRemove, RouteWrite)
	assertSums(t, got, "Invalid example.test app.example.test static:app", "Conflict example.test app.example.test docker:app")

	// non-authoritative LastKnown does not make it routable
	badLK := obs
	badLK.LastKnown = map[string]model.Backend{"static:app": {Scheme: "http"}}
	got = Plan([]model.Service{dk, noBackend}, badLK, cfg, t0)
	assertNone(t, got, RouteRemove, RouteWrite)
}

func TestPlanSameSourceTiers(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	rn := func(s model.Service) model.Service { s.Options.Rename = "app"; return s }
	t.Run("stopped v1 never beats published v2", func(t *testing.T) {
		v1 := rn(svc("docker:a_v1", "x", "example.test", model.StateStopped, "", 0))
		v2 := rn(pub("docker:b_v2", "y", "example.test", 2))
		obs := Observed{Known: knownMap(known("docker:a_v1", "example.test", "app.example.test", nil)),
			LastKnown: map[string]model.Backend{"docker:a_v1": {Scheme: "http", Host: "198.51.100.5", Port: 1}}}
		got := Plan([]model.Service{v1, v2}, obs, cfg, t0)
		if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Key != "docker:b_v2" {
			t.Fatalf("got %v", sums(got))
		}
		assertSums(t, forKey(got, "docker:a_v1"), "Conflict example.test app.example.test docker:a_v1", "RouteRemove example.test app.example.test docker:a_v1")
	})
	t.Run("published without backend is not serving", func(t *testing.T) {
		a := rn(svc("docker:a", "x", "example.test", model.StatePublished, "", 0))
		b := rn(pub("docker:b", "y", "example.test", 2))
		got := Plan([]model.Service{a, b}, Observed{}, cfg, t0)
		if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Key != "docker:b" {
			t.Fatalf("got %v", sums(got))
		}
	})
	t.Run("equal tier stable by key whichever is known", func(t *testing.T) {
		a := rn(pub("docker:a", "x", "example.test", 1))
		b := rn(pub("docker:b", "y", "example.test", 2))
		for _, k := range []string{"docker:a", "docker:b"} {
			obs := Observed{Known: knownMap(known(k, "example.test", "app.example.test", nil))}
			got := Plan([]model.Service{b, a}, obs, cfg, t0)
			if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Key != "docker:a" {
				t.Fatalf("known=%s: %v", k, sums(got))
			}
		}
	})
	t.Run("phantom with route beats non-serving newcomer of same source", func(t *testing.T) {
		obs := Observed{Unavailable: map[string]bool{"docker": true},
			Known: knownMap(known("docker:z", "example.test", "app.example.test", nil))}
		// docker:a is from another docker source name that is available
		a := rn(svc("docker:a", "x", "example.test", model.StatePending, "198.51.100.5", 1))
		a.Source = "docker2"
		got := Plan([]model.Service{a}, obs, cfg, t0)
		assertSums(t, got, "Conflict example.test app.example.test docker:a")
	})
}

func TestPlanUnavailableLoserKeepsRoute(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	dk := pub("docker:app", "app", "example.test", 80)
	obs := Observed{Unavailable: map[string]bool{"docker": true},
		Known: knownMap(known("docker:app", "example.test", "app.example.test", nil))}
	got := Plan([]model.Service{dk, pub("static:app", "app", "example.test", 81)}, obs, cfg, t0)
	assertNone(t, got, RouteRemove)
	assertSums(t, forKey(got, "docker:app"), "Conflict example.test app.example.test docker:app")
}

func TestPlanTrueNASOutageNoFlip(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	tn := pub("truenas:app", "app", "example.test", 30000)
	dk := pub("docker:app", "app", "example.test", 32768)
	obs := Observed{Foreign: listed("example.test"), Known: map[string]KnownService{}, LastKnown: map[string]model.Backend{}}
	apply := func(acts []Action) {
		for _, a := range acts {
			switch a.Kind {
			case RouteWrite:
				obs.Known[a.Key] = KnownService{Key: a.Key, Source: a.Svc.Source, Zone: a.Zone, Hostname: a.Host}
				obs.LastKnown[a.Key] = *a.Backend
			case RouteRemove:
				delete(obs.Known, a.Key)
			case DNSEnsure:
				obs.Owned = append(obs.Owned, store.DNSRecord{Provider: a.Provider, Zone: a.Zone, Name: a.Record.Name,
					Type: a.Record.Type, Value: a.Record.Value, OwnerKey: a.Owner})
			}
		}
	}
	check := func(cycle string, acts []Action) {
		t.Helper()
		for _, a := range forKey(acts, "docker:app") {
			if a.Kind != Conflict {
				t.Fatalf("%s: docker got %v", cycle, sum(a))
			}
		}
		assertNone(t, acts, DNSDelete, ScheduleRemoval)
	}
	c1 := Plan([]model.Service{tn, dk}, obs, cfg, t0)
	check("healthy", c1)
	if r := ofKind(c1, RouteWrite); len(r) != 1 || r[0].Key != "truenas:app" {
		t.Fatalf("healthy: %v", sums(c1))
	}
	apply(c1)

	obs.Unavailable = map[string]bool{"truenas": true}
	c2 := Plan([]model.Service{dk}, obs, cfg, t0.Add(time.Minute))
	check("outage", c2)
	assertNone(t, c2, RouteWrite, RouteRemove)
	apply(c2)

	obs.Unavailable = nil
	c3 := Plan([]model.Service{tn, dk}, obs, cfg, t0.Add(2*time.Minute))
	check("recovered", c3)
	assertNone(t, c3, RouteRemove)
	if r := ofKind(c3, RouteWrite); len(r) != 1 || r[0].Key != "truenas:app" {
		t.Fatalf("recovered: %v", sums(c3))
	}
}

// mayRemoveLoserRoute's published and rank checks are redundant by
// construction (routable implies published; the winner never ranks below the
// loser); pin them directly so they cannot silently disappear.
func TestMayRemoveLoserRouteGuards(t *testing.T) {
	p := newPlanner(Observed{Unavailable: map[string]bool{"truenas": true}}, cfgOf(), t0)
	loser := pub("docker:app", "app", "example.test", 1)
	ok := claimant{key: "static:app", source: "static", published: true, routable: true, serving: true}
	tests := []struct {
		name  string
		loser model.Service
		w     func(claimant) claimant
		want  bool
	}{
		{"all hold", loser, func(c claimant) claimant { return c }, true},
		{"winner not published", loser, func(c claimant) claimant { c.published = false; return c }, false},
		{"winner not routable", loser, func(c claimant) claimant { c.routable = false; return c }, false},
		{"winner phantom", loser, func(c claimant) claimant { c.phantom = true; return c }, false},
		{"winner lower rank", pub("static:other", "app", "example.test", 1), func(c claimant) claimant {
			c.key, c.source = "docker:app", "docker"
			return c
		}, false},
		{"loser source unavailable", pub("truenas:app", "app", "example.test", 1), func(c claimant) claimant { return c }, false},
		{"loser source empty", func() model.Service { s := loser; s.Source = ""; return s }(), func(c claimant) claimant { return c }, false},
	}
	for _, tc := range tests {
		if got := p.mayRemoveLoserRoute(tc.loser, tc.w(ok)); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
