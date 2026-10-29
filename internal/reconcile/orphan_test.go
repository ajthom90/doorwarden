package reconcile

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// orphanKinds are the DNS removal-lifecycle kinds the orphan rule emits.
var orphanKinds = []ActionKind{DNSScheduleRemoval, DNSCancelRemoval, DNSDelete}

// (DNSReassign is checked separately, with reassigns.)

func orphanActs(as []Action) []string {
	var out []string
	for _, a := range as {
		for _, k := range orphanKinds {
			if a.Kind == k {
				out = append(out, sum(a))
			}
		}
	}
	return out
}

func assertOrphans(t *testing.T, got []Action, want ...string) {
	t.Helper()
	g := orphanActs(got)
	if strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Fatalf("orphan actions mismatch\n got:\n  %s\nwant:\n  %s\nplan:\n  %s",
			strings.Join(g, "\n  "), strings.Join(want, "\n  "), strings.Join(sums(got), "\n  "))
	}
}

func ownedRA(zone, name, typ, value, owner string, ra *time.Time) store.DNSRecord {
	o := owned(zone, name, typ, value, owner)
	o.RemovedAfter = ra
	return o
}

func phCfg() *config.Config { return cfgOf(zone("example.test", "per-host", "wildcard")) }

const (
	schedApp = "DNSScheduleRemoval example.test app.example.test docker:app [app.example.test A 192.0.2.10]"
	delApp   = "DNSDelete example.test app.example.test docker:app [app.example.test A 192.0.2.10]"
	cancApp  = "DNSCancelRemoval example.test app.example.test docker:app [app.example.test A 192.0.2.10]"
)

func TestOrphanRenameSchedulesOldRowAndEnsuresNew(t *testing.T) {
	obs := Observed{Foreign: listed("example.test"),
		Owned: []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:app")},
		Known: knownMap(known("docker:app", "example.test", "app.example.test", nil))}
	got := Plan([]model.Service{pub("docker:app", "web", "example.test", 80)}, obs, phCfg(), t0)
	assertOrphans(t, got, schedApp)
	s := ofKind(got, DNSScheduleRemoval)[0]
	if s.RemovedAfter == nil || !s.RemovedAfter.Equal(t0.Add(24*time.Hour)) || s.Owner != "docker:app" ||
		s.Provider != "dnsp" || s.Record.ID != "id-app.example.test" {
		t.Fatalf("schedule %+v %+v", s, s.Record)
	}
	if e := ofKind(got, DNSEnsure); len(e) != 1 || e[0].Record.Name != "web.example.test" || e[0].Owner != "docker:app" {
		t.Fatalf("plan %v", sums(got))
	}
}

func TestOrphanLifecycleTiming(t *testing.T) {
	desired := []model.Service{pub("docker:app", "web", "example.test", 80)} // renamed away from app
	for _, tc := range []struct {
		name string
		ra   *time.Time
		want []string
	}{
		{"unscheduled: schedule", nil, []string{schedApp}},
		{"within grace: nothing", tp(t0.Add(time.Second)), nil},
		{"exactly at deadline: nothing (strictly after)", tp(t0), nil},
		{"past deadline: delete stored row", tp(t0.Add(-time.Second)), []string{delApp}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := Observed{Foreign: listed("example.test"),
				Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", target, "docker:app", tc.ra)}}
			got := Plan(desired, obs, phCfg(), t0)
			assertOrphans(t, got, tc.want...)
			if d := ofKind(got, DNSDelete); len(d) == 1 {
				if d[0].Record.ID != "id-app.example.test" || d[0].Owner != "docker:app" || d[0].Provider != "dnsp" ||
					d[0].Record.Value != target {
					t.Fatalf("delete must carry the stored row: %+v", d[0].Record)
				}
			}
		})
	}
}

func TestOrphanCancelWhenWantedAgainNeverDeleted(t *testing.T) {
	for _, ra := range []*time.Time{tp(t0.Add(time.Hour)), tp(t0.Add(-time.Hour))} {
		obs := Observed{Foreign: listed("example.test"),
			Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", target, "docker:app", ra)}}
		got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)
		assertOrphans(t, got, cancApp)
		assertNone(t, got, DNSEnsure)
	}
	// wanted and unscheduled: nothing at all
	obs := Observed{Foreign: listed("example.test"),
		Owned: []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:app")}}
	assertOrphans(t, Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0))
}

// (a) a present owner that is not cleanly Published keeps every row; a
// removal scheduled while it was absent is cancelled (it is present again),
// never executed.
func TestOrphanPresentNonPublishedOwnerKeepsRows(t *testing.T) {
	bad := pub("docker:app", "web", "example.test", 80)
	bad.Options.Middlewares = []string{"undefined@file"}
	cases := map[string]model.Service{
		"stopped":                 svc("docker:app", "web", "example.test", model.StateStopped, "198.51.100.5", 80),
		"pending":                 svc("docker:app", "web", "example.test", model.StatePending, "198.51.100.5", 80),
		"error":                   svc("docker:app", "web", "example.test", model.StateError, "", 0),
		"discovered":              svc("docker:app", "web", "example.test", model.StateDiscovered, "198.51.100.5", 80),
		"invalid labels":          pub("docker:app", "web", "missing.test", 80),
		"undefined middleware":    bad,
		"published, no backend":   pub("docker:app", "web", "example.test", 0),
		"held invalid with Known": pub("docker:app", "web", "missing.test", 80),
	}
	for name, s := range cases {
		for _, ra := range []*time.Time{nil, tp(t0.Add(-time.Hour)), tp(t0.Add(time.Hour))} {
			t.Run(name, func(t *testing.T) {
				obs := Observed{Foreign: listed("example.test"),
					Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", target, "docker:app", ra)}}
				if name == "held invalid with Known" || name == "stopped" {
					obs.Known = knownMap(known("docker:app", "example.test", "app.example.test", nil))
				}
				var want []string
				if ra != nil {
					want = append(want, "DNSCancelRemoval example.test app.example.test docker:app [app.example.test A 192.0.2.10]")
				}
				assertOrphans(t, Plan([]model.Service{s}, obs, phCfg(), t0), want...)
			})
		}
	}
}

// (b) a source outage, or a source that cannot be determined, never
// schedules and never deletes.
func TestOrphanSourceUnavailableOrUnknownNeverRemoves(t *testing.T) {
	past := tp(t0.Add(-time.Hour))
	row := func(owner string, ra *time.Time) []store.DNSRecord {
		return []store.DNSRecord{ownedRA("example.test", "gone.example.test", "A", target, owner, ra)}
	}
	cases := []struct {
		name    string
		desired []model.Service
		obs     Observed
	}{
		{"Known source unavailable", nil, Observed{Owned: row("docker:gone", past), Unavailable: map[string]bool{"docker": true},
			Known: knownMap(known("docker:gone", "example.test", "gone.example.test", past))}},
		{"Known source empty", nil, Observed{Owned: row("docker:gone", past),
			Known: map[string]KnownService{"docker:gone": {Key: "docker:gone", Zone: "example.test", Hostname: "gone.example.test"}}}},
		{"no Known, prefix source unavailable", nil, Observed{Owned: row("docker:gone", past), Unavailable: map[string]bool{"docker": true}}},
		{"no Known, prefix source unavailable, unscheduled", nil, Observed{Owned: row("docker:gone", nil), Unavailable: map[string]bool{"docker": true}}},
		{"no Known, prefix source unavailable case-insensitively", nil, Observed{Owned: row("docker:gone", past), Unavailable: map[string]bool{"Docker": true}}},
		{"no Known, renamed source seen on a present service is unavailable",
			[]model.Service{{Key: "docker:other", Source: "dock1", Name: "other", Zone: "example.test", State: model.StateStopped}},
			Observed{Owned: row("docker:gone", past), Unavailable: map[string]bool{"dock1": true}}},
		{"no Known, renamed source seen in Known is unavailable", nil,
			Observed{Owned: row("docker:gone", past), Unavailable: map[string]bool{"dock1": true},
				Known: map[string]KnownService{"docker:x": {Key: "docker:x", Source: "dock1", Zone: "example.test", Hostname: "x.example.test"}}}},
		{"no Known, an unmappable source is unavailable", nil, Observed{Owned: row("docker:gone", past), Unavailable: map[string]bool{"mystery": true}}},
		{"no Known, a source named like another prefix is unavailable and maps to nothing", nil,
			Observed{Owned: row("truenas:gone", past), Unavailable: map[string]bool{"docker": true}}},
		{"no Known, a source named like another prefix is unavailable and maps to nothing (other prefix)", nil,
			Observed{Owned: row("docker:gone", past), Unavailable: map[string]bool{"truenas": true}}},
		{"no Known, a TrueNAS source named docker is unavailable; docker evidence elsewhere does not map it", []model.Service{pub("docker:x", "x", "example.test", 80)},
			Observed{Owned: row("truenas:gone", past), Unavailable: map[string]bool{"nas": true}}},
		{"unknown key prefix", nil, Observed{Owned: row("other:gone", past)}},
		{"unknown key prefix, unscheduled", nil, Observed{Owned: row("other:gone", nil)}},
		{"no prefix", nil, Observed{Owned: row("gone", past)}},
		{"empty owner", nil, Observed{Owned: row("", past)}},
		{"present service whose source is marked unavailable", []model.Service{pub("docker:gone", "web", "example.test", 80)},
			Observed{Owned: row("docker:gone", nil), Unavailable: map[string]bool{"docker": true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.obs.Foreign = listed("example.test")
			got := Plan(tc.desired, tc.obs, phCfg(), t0)
			assertOrphans(t, got)
		})
	}
	// present (carried forward) with a schedule from its absence: cancelled
	got := Plan([]model.Service{pub("docker:gone", "web", "example.test", 80)},
		Observed{Foreign: listed("example.test"), Owned: row("docker:gone", past), Unavailable: map[string]bool{"docker": true}}, phCfg(), t0)
	assertOrphans(t, got, "DNSCancelRemoval example.test gone.example.test docker:gone [gone.example.test A 192.0.2.10]")
	// control: another source's outage does not block an owner once evidence
	// (a desired or Known key) maps the unavailable name to another prefix.
	// A source's name alone never maps it: a TrueNAS source may be named
	// "docker" (T19 contract: Service.Source equals the key prefix, or Known
	// carries the Source).
	obs := Observed{Foreign: listed("example.test"), Owned: row("docker:gone", past), Unavailable: map[string]bool{"truenas": true},
		Known: map[string]KnownService{"truenas:x": {Key: "truenas:x", Source: "truenas", Zone: "example.test", Hostname: "x.example.test"}}}
	assertOrphans(t, Plan(nil, obs, phCfg(), t0), "DNSDelete example.test gone.example.test docker:gone [gone.example.test A 192.0.2.10]")
	obs.Known = nil
	stopped := svc("truenas:y", "y", "example.test", model.StateStopped, "198.51.100.5", 80)
	assertOrphans(t, Plan([]model.Service{stopped}, obs, phCfg(), t0), "DNSDelete example.test gone.example.test docker:gone [gone.example.test A 192.0.2.10]")
}

// (c) the wildcard record is never scheduled or deleted.
func TestOrphanWildcardRowsUntouched(t *testing.T) {
	for _, mode := range []string{"wildcard", "per-host"} {
		cfg := cfgOf(zone("example.test", mode, "wildcard"))
		for _, ra := range []*time.Time{nil, tp(t0.Add(-time.Hour))} {
			obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{
				ownedRA("example.test", "*.example.test", "A", target, WildcardOwnerKey("example.test"), ra),
				ownedRA("example.test", "*.example.test", "AAAA", "2001:db8::1", "docker:weird", ra),
				ownedRA("example.test", "x.example.test", "A", target, "zone:example.test", ra),
				ownedRA("example.test", "y.example.test", "A", target, "ZONE:other.test", ra),
			}}
			assertOrphans(t, Plan(nil, obs, cfg, t0))
		}
	}
}

// (d) records mode off: nothing is touched; wildcard: per-host leftovers are
// orphans once the zone's wildcard record is owned, after the grace period.
func TestOrphanZoneModes(t *testing.T) {
	past := tp(t0.Add(-time.Hour))
	app := pub("docker:app", "app", "example.test", 80)
	t.Run("off", func(t *testing.T) {
		for _, mode := range []string{"off", ""} {
			cfg := cfgOf(zone("example.test", mode, "wildcard"))
			for _, ra := range []*time.Time{nil, past} {
				obs := Observed{Foreign: listed("example.test"),
					Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", target, "docker:app", ra)}}
				got := Plan(nil, obs, cfg, t0)
				assertOrphans(t, got)
				assertNone(t, got, Skip)
			}
		}
	})
	wc := cfgOf(zone("example.test", "wildcard", "wildcard"))
	wcRow := owned("example.test", "*.example.test", "A", target, WildcardOwnerKey("example.test"))
	t.Run("wildcard with owned wildcard record", func(t *testing.T) {
		for _, tc := range []struct {
			ra   *time.Time
			want []string
		}{{nil, []string{schedApp}}, {tp(t0.Add(time.Hour)), nil}, {past, []string{delApp}}} {
			obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{wcRow,
				ownedRA("example.test", "app.example.test", "A", target, "docker:app", tc.ra)}}
			assertOrphans(t, Plan([]model.Service{app}, obs, wc, t0), tc.want...)
		}
	})
	t.Run("wildcard without owned wildcard record waits", func(t *testing.T) {
		obs := Observed{Foreign: listed("example.test"),
			Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", target, "docker:app", past)}}
		assertOrphans(t, Plan([]model.Service{app}, obs, wc, t0))
	})
}

// (e) a row whose zone is no longer configured, or whose provider is not the
// zone's records provider, is left alone and reported.
func TestOrphanUnverifiableZoneOrProviderSkips(t *testing.T) {
	past := tp(t0.Add(-time.Hour))
	other := ownedRA("gone.test", "app.gone.test", "A", target, "docker:app", past)
	moved := ownedRA("example.test", "app.example.test", "A", target, "docker:app", past)
	moved.Provider = "oldp"
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{other, moved}}
	got := Plan(nil, obs, phCfg(), t0)
	assertOrphans(t, got)
	sk := ofKind(got, Skip)
	if len(sk) != 2 || !strings.Contains(sk[0].Reason+sk[1].Reason, "not configured") ||
		!strings.Contains(sk[0].Reason+sk[1].Reason, "records provider") {
		t.Fatalf("skips %v %q %q", sums(sk), sk[0].Reason, sk[1].Reason)
	}
}

// (f) an owner absent from desired (removed, or approval off/Skip) is
// removal by admin intent: scheduled after grace like its route, with the
// route's deadline when it has one.
func TestOrphanAbsentOwnerAlignsWithRoute(t *testing.T) {
	rows := []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:app")}
	t.Run("route unscheduled: same deadline as ScheduleRemoval", func(t *testing.T) {
		obs := Observed{Foreign: listed("example.test"), Owned: rows,
			Known: knownMap(known("docker:app", "example.test", "app.example.test", nil))}
		got := Plan(nil, obs, phCfg(), t0)
		assertOrphans(t, got, schedApp)
		r, d := ofKind(got, ScheduleRemoval), ofKind(got, DNSScheduleRemoval)
		if len(r) != 1 || !r[0].RemovedAfter.Equal(*d[0].RemovedAfter) || !d[0].RemovedAfter.Equal(t0.Add(24*time.Hour)) {
			t.Fatalf("deadlines differ: %v", sums(got))
		}
	})
	t.Run("route already scheduled: its deadline is reused", func(t *testing.T) {
		ra := t0.Add(3 * time.Hour)
		obs := Observed{Foreign: listed("example.test"), Owned: rows,
			Known: knownMap(known("docker:app", "example.test", "app.example.test", &ra))}
		got := Plan(nil, obs, phCfg(), t0)
		if d := ofKind(got, DNSScheduleRemoval); len(d) != 1 || !d[0].RemovedAfter.Equal(ra) {
			t.Fatalf("plan %v", sums(got))
		}
	})
	t.Run("route and record past grace go together", func(t *testing.T) {
		ra := t0.Add(-time.Second)
		obs := Observed{Foreign: listed("example.test"),
			Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", target, "docker:app", &ra)},
			Known: knownMap(known("docker:app", "example.test", "app.example.test", &ra))}
		assertSums(t, Plan(nil, obs, phCfg(), t0), "RouteRemove example.test app.example.test docker:app", delApp)
	})
	t.Run("no route any more (failed delete earlier): delete re-emitted", func(t *testing.T) {
		obs := Observed{Foreign: listed("example.test"),
			Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", target, "docker:app", tp(t0.Add(-time.Hour)))}}
		assertSums(t, Plan(nil, obs, phCfg(), t0), delApp)
	})
}

// Hostname conflicts: a loser that still declares the hostname wants its
// record; once it renames away or is gone the record is an orphan.
func TestOrphanHostnameConflicts(t *testing.T) {
	rows := []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:b")}
	winner := pub("static:a", "app", "example.test", 80)
	t.Run("loser still declares: kept, winner silently uses it", func(t *testing.T) {
		obs := Observed{Foreign: listed("example.test"), Owned: rows,
			Known: knownMap(known("docker:b", "example.test", "app.example.test", nil))}
		got := Plan([]model.Service{winner, pub("docker:b", "app", "example.test", 81)}, obs, phCfg(), t0)
		assertOrphans(t, got)
		assertNone(t, got, DNSEnsure)
	})
	t.Run("loser renamed away: the winner takes the record over", func(t *testing.T) {
		obs := Observed{Foreign: listed("example.test"), Owned: rows}
		got := Plan([]model.Service{winner, pub("docker:b", "web", "example.test", 81)}, obs, phCfg(), t0)
		assertOrphans(t, got)
		if r := reassigns(got); len(r) != 1 || r[0] != "app.example.test A docker:b->static:a" {
			t.Fatalf("plan %v", sums(got))
		}
		if e := ofKind(got, DNSEnsure); len(e) != 1 || e[0].Record.Name != "web.example.test" {
			t.Fatalf("plan %v", sums(got))
		}
	})
	t.Run("absent loser taken over: same value reassigned, other value an orphan; never a DNSEnsure for the row", func(t *testing.T) {
		for _, val := range []string{target, "192.0.2.99"} {
			r := []store.DNSRecord{owned("example.test", "app.example.test", "A", val, "docker:b")}
			obs := Observed{Foreign: listed("example.test"), Owned: r,
				Known: knownMap(known("docker:b", "example.test", "app.example.test", nil))}
			// a higher rank takes over at once (a same-rank one waits for
			// the absent incumbent's grace period, final-review H1)
			got := Plan([]model.Service{pub("static:a", "app", "example.test", 80)}, obs, phCfg(), t0)
			want := DNSScheduleRemoval
			if val == target {
				want = DNSReassign
			}
			if len(ofKind(got, RouteRemove)) != 1 || len(ofKind(got, want)) != 1 {
				t.Fatalf("plan %v", sums(got))
			}
			assertNone(t, got, DNSEnsure)
			checkRowOnce(t, got)
		}
	})
}

// A target_ip that does not parse leaves the record type unknown: the owner
// is protected rather than losing its records.
func TestOrphanUnparsableTargetProtectsOwner(t *testing.T) {
	cfg := phCfg()
	cfg.Zones[0].TargetIP = "not-an-ip"
	obs := Observed{Foreign: listed("example.test"),
		Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", target, "docker:app", tp(t0.Add(-time.Hour)))}}
	// present again: the schedule is cancelled, nothing is removed
	assertOrphans(t, Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, cfg, t0),
		"DNSCancelRemoval example.test app.example.test docker:app [app.example.test A 192.0.2.10]")
	obs.Owned[0].RemovedAfter = nil
	assertOrphans(t, Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, cfg, t0))
}

// A zone moved to AAAA: the old A row is an orphan, the AAAA one is ensured.
func TestOrphanTypeChangeAndZoneMove(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "wildcard"), zone("other.test", "per-host", "wildcard"))
	obs := Observed{Foreign: listed("example.test", "other.test"),
		Owned: []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:app")}}
	got := Plan([]model.Service{pub("docker:app", "app", "other.test", 80)}, obs, cfg, t0)
	assertOrphans(t, got, schedApp)
	if e := ofKind(got, DNSEnsure); len(e) != 1 || e[0].Zone != "other.test" {
		t.Fatalf("plan %v", sums(got))
	}
	cfg6 := phCfg()
	cfg6.Zones[0].TargetIP = "2001:db8::10"
	got = Plan([]model.Service{pub("docker:app", "app", "example.test", 80)},
		Observed{Foreign: listed("example.test"), Owned: obs.Owned}, cfg6, t0)
	assertOrphans(t, got, schedApp)
	if e := ofKind(got, DNSEnsure); len(e) != 1 || e[0].Record.Type != "AAAA" {
		t.Fatalf("plan %v", sums(got))
	}
}

// A row the same plan ensures is never scheduled or deleted, and a row owned
// by another key is never "ensured" over (a doomed DNSEnsure would block its
// owner's cleanup forever).
func TestOrphanNeverScheduleWhatIsEnsured(t *testing.T) {
	r := []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", "192.0.2.99", "docker:b", tp(t0.Add(-time.Hour)))}
	obs := Observed{Foreign: listed("example.test"), Owned: r}
	got := Plan([]model.Service{pub("docker:a", "app", "example.test", 80)}, obs, phCfg(), t0)
	assertNone(t, got, DNSEnsure)
	assertOrphans(t, got, "DNSDelete example.test app.example.test docker:b [app.example.test A 192.0.2.99]")
	if sk := ofKind(got, Skip); len(sk) != 1 || !strings.Contains(sk[0].Reason, "owned by docker:b") {
		t.Fatalf("plan %v", sums(got))
	}
	checkNoEnsureAndRemoval(t, got)
}

func checkNoEnsureAndRemoval(t *testing.T, acts []Action) {
	t.Helper()
	ens := map[string]bool{}
	for _, a := range ofKind(acts, DNSEnsure) {
		ens[a.Provider+"|"+a.Zone+"|"+normName(a.Record.Name)+"|"+normType(a.Record.Type)] = true
	}
	for _, a := range acts {
		if a.Kind == DNSScheduleRemoval || a.Kind == DNSDelete {
			if ens[a.Provider+"|"+a.Zone+"|"+normName(a.Record.Name)+"|"+normType(a.Record.Type)] {
				t.Fatalf("%s for a row the plan also ensures: %v", a.Kind, sums(acts))
			}
		}
	}
}

func TestOrphanDeterministicUnderShuffle(t *testing.T) {
	desired := []model.Service{pub("docker:a", "web", "example.test", 80), pub("docker:b", "app", "example.test", 81),
		svc("truenas:c", "c", "", model.StateStopped, "198.51.100.5", 82)}
	var rows []store.DNSRecord
	for i, n := range []string{"app", "web", "old", "c", "x", "y"} {
		ra := []*time.Time{nil, tp(t0.Add(-time.Hour)), tp(t0.Add(time.Hour))}[i%3]
		rows = append(rows, ownedRA("example.test", n+".example.test", "A", target, []string{"docker:a", "docker:b", "truenas:c", "docker:gone"}[i%4], ra))
	}
	obs := Observed{Foreign: listed("example.test"), Owned: rows}
	want := Plan(desired, obs, phCfg(), t0)
	if len(orphanActs(want)) == 0 {
		t.Fatal("vacuous")
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 50; i++ {
		d := append([]model.Service(nil), desired...)
		o := append([]store.DNSRecord(nil), rows...)
		r.Shuffle(len(d), func(a, b int) { d[a], d[b] = d[b], d[a] })
		r.Shuffle(len(o), func(a, b int) { o[a], o[b] = o[b], o[a] })
		if got := Plan(d, Observed{Foreign: obs.Foreign, Owned: o}, phCfg(), t0); !reflect.DeepEqual(got, want) {
			t.Fatalf("plan depends on input order\n%v\n%v", sums(got), sums(want))
		}
	}
}

// A wanted row whose value changes is updated AND its removal cancelled in
// the same plan (the cancel is not a removal; the update keeps RemovedAfter).
func TestOrphanCancelAlongsideUpdate(t *testing.T) {
	obs := Observed{Foreign: listed("example.test"),
		Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", "192.0.2.99", "docker:app", tp(t0.Add(-time.Hour)))}}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)
	assertOrphans(t, got, "DNSCancelRemoval example.test app.example.test docker:app [app.example.test A 192.0.2.99]")
	if e := ofKind(got, DNSEnsure); len(e) != 1 || e[0].Record.Value != target {
		t.Fatalf("plan %v", sums(got))
	}
}
