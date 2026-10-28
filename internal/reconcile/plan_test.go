package reconcile

import (
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
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 32768)}, Observed{}, cfg, t0)
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

func TestPlanDefaultZoneIsFirstConfigured(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"), zone("other.test", "off", "wildcard"))
	got := Plan([]model.Service{pub("docker:app", "app", "", 80)}, Observed{}, cfg, t0)
	if r := ofKind(got, RouteWrite); len(r) != 1 || r[0].Host != "app.example.test" {
		t.Fatalf("route: %v", sums(got))
	}
}

func TestPlanIPv6TargetUsesAAAA(t *testing.T) {
	z := zone("example.test", "per-host", "per-host")
	z.TargetIP = "2001:db8::10"
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, Observed{}, cfgOf(z), t0)
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
	got := Plan(desired, Observed{}, cfg, t0)
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
			got := ofKind(Plan(desired, Observed{Owned: tc.owned}, cfg, t0), DNSEnsure)
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
	obs := Observed{Known: map[string]KnownService{}, LastKnown: map[string]model.Backend{}}
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
	for _, r := range ofKind(a2, RouteWrite) {
		if r.Backend == nil || r.Backend.Port != 32768 || r.Backend.Host != "198.51.100.5" {
			t.Fatalf("cycle 2 RouteWrite must carry last-known backend, got %v", sums(a2))
		}
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
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	obs := Observed{Unavailable: map[string]bool{"truenas": true},
		Known: knownMap(known("truenas:app", "example.test", "app.example.test", nil))}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, cfg, t0)
	assertSums(t, got, "Conflict example.test app.example.test docker:app")
	if !strings.Contains(got[0].Reason, "truenas:app") {
		t.Fatalf("reason %q", got[0].Reason)
	}
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
		{"pending winner still blocks", []model.Service{pub("docker:app", "app", "example.test", 1), svc("static:app", "app", "example.test", model.StatePending, "198.51.100.5", 2)}, "static:app", []string{"docker:app"}},
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
			obs := Observed{}
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
