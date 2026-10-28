package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// ---- GatherObserved: OwnedMissing / OwnedDrifted ----

func TestGatherObservedOwnedMissingAndDrifted(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	f1, f2 := fake.New(true), fake.New(true)
	present, _ := f1.CreateRecord(ctx, dz, dns.Record{Name: "app.example.test", Type: "A", Value: ip1})
	changed, _ := f1.CreateRecord(ctx, dz, dns.Record{Name: "web.example.test", Type: "A", Value: ipFX})
	_, _ = f1.CreateRecord(ctx, dz, dns.Record{Name: "gone.example.test", Type: "TXT", Value: "v=x"}) // another type only
	add := func(p, z, name, value, id, owner string) {
		t.Helper()
		if err := st.AddOwnedRecord(ctx, store.DNSRecord{Provider: p, Zone: z, Name: name, Type: "A", Value: value,
			ProviderRecordID: id, OwnerKey: owner, CreatedAt: t0}); err != nil {
			t.Fatal(err)
		}
	}
	add(dzp, dz, "App.Example.Test.", ip1, present.ID, "docker:app") // present (unnormalized row)
	add(dzp, dz, "web.example.test", ip1, changed.ID, "docker:web")  // same ID, other value: drifted
	add(dzp, dz, "gone.example.test", ip1, "fake-99", "docker:gone") // missing (a TXT at the name does not count)
	add(dzp, dz, "*.example.test", ip1, "fake-98", WildcardOwnerKey(dz))
	add("p2", "other.test", "x.other.test", ip1, "p2-1", "docker:x") // listing fails: unknown
	add("oldp", dz, "old.example.test", ip1, "o-1", "docker:old")    // provider not listed: unknown
	f2.FailNext("ListRecords", errors.New("unreachable"))
	obs, errs := GatherObserved(ctx, map[string]dns.Provider{dzp: f1, "p2": f2}, st,
		[]ZoneRef{{dzp, dz}, {"p2", "other.test"}}, 0)
	if len(errs) != 1 || len(obs.Owned) != 6 {
		t.Fatalf("errs %v owned %d", errs, len(obs.Owned))
	}
	wantMissing := []string{OwnedRowKey(dzp, dz, "*.example.test", "A"), OwnedRowKey(dzp, dz, "gone.example.test", "A")}
	if len(obs.OwnedMissing) != 2 || !obs.OwnedMissing[wantMissing[0]] || !obs.OwnedMissing[wantMissing[1]] {
		t.Fatalf("missing %v", obs.OwnedMissing)
	}
	d, ok := obs.OwnedDrifted[OwnedRowKey(dzp, dz, "web.example.test", "A")]
	if len(obs.OwnedDrifted) != 1 || !ok || len(d) != 1 || d[0].Value != ipFX {
		t.Fatalf("drifted %v", obs.OwnedDrifted)
	}
	var o Observed
	obs.Fill(&o)
	if len(o.Owned) != 6 || len(o.Foreign) != 1 || len(o.OwnedMissing) != 2 || len(o.OwnedDrifted) != 1 {
		t.Fatalf("fill %+v", o)
	}
}

// ---- Plan ----

func missing(rows ...store.DNSRecord) map[string]bool {
	m := map[string]bool{}
	for _, o := range rows {
		m[OwnedRowKey(o.Provider, o.Zone, o.Name, o.Type)] = true
	}
	return m
}

func repairs(as []Action) []string {
	var out []string
	for _, a := range ofKind(as, DNSEnsure) {
		if a.Repair {
			out = append(out, sum(a)+" id="+a.Record.ID)
		}
	}
	return out
}

func TestPlanRepairsMissingOwnedRecord(t *testing.T) {
	row := owned("example.test", "app.example.test", "A", target, "docker:app")
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}, OwnedMissing: missing(row)}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)
	if r := repairs(got); len(r) != 1 || r[0] != "DNSEnsure example.test app.example.test docker:app [app.example.test A 192.0.2.10] repair id=id-app.example.test" {
		t.Fatalf("repairs %v\nplan %v", r, sums(got))
	}
	assertNone(t, got, DNSScheduleRemoval, DNSDelete, Conflict)
	// not missing: nothing
	obs.OwnedMissing = nil
	if r := repairs(Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)); len(r) != 0 {
		t.Fatalf("repairs %v", r)
	}
}

func TestPlanRepairsWildcardRowInWildcardMode(t *testing.T) {
	row := owned("example.test", "*.example.test", "A", target, WildcardOwnerKey("example.test"))
	cfg := cfgOf(zone("example.test", "wildcard", "wildcard"))
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}, OwnedMissing: missing(row)}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, cfg, t0)
	if r := repairs(got); len(r) != 1 || !strings.Contains(r[0], "*.example.test") {
		t.Fatalf("repairs %v\nplan %v", r, sums(got))
	}
}

// A hostname loser still wants its record: it is repaired from planOrphans.
func TestPlanRepairsHostnameLoserRow(t *testing.T) {
	row := owned("example.test", "app.example.test", "A", target, "docker:b")
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}, OwnedMissing: missing(row)}
	desired := []model.Service{pub("docker:a", "app", "example.test", 80), pub("docker:b", "app", "example.test", 81)}
	got := Plan(desired, obs, phCfg(), t0)
	if r := repairs(got); len(r) != 1 || !strings.Contains(r[0], "docker:b") {
		t.Fatalf("repairs %v\nplan %v", r, sums(got))
	}
}

func TestPlanNoRepairWhenNotEligible(t *testing.T) {
	row := owned("example.test", "app.example.test", "A", target, "docker:app")
	sched := ownedRA("example.test", "app.example.test", "A", target, "docker:app", tp(t0.Add(-time.Hour)))
	cases := []struct {
		name    string
		desired []model.Service
		row     store.DNSRecord
		cfg     *config.Config
		unavail map[string]bool
	}{
		{"orphan (owner absent)", nil, sched, phCfg(), nil},
		{"orphan (owner renamed)", []model.Service{pub("docker:app", "web", "example.test", 80)}, sched, phCfg(), nil},
		{"protected (stopped)", []model.Service{svc("docker:app", "app", "example.test", model.StateStopped, "198.51.100.5", 80)}, row, phCfg(), nil},
		{"protected (pending)", []model.Service{svc("docker:app", "app", "example.test", model.StatePending, "198.51.100.5", 80)}, row, phCfg(), nil},
		{"source unavailable", []model.Service{pub("docker:app", "app", "example.test", 80)}, row, phCfg(), map[string]bool{"docker": true}},
		{"records mode off", []model.Service{pub("docker:app", "app", "example.test", 80)}, row, cfgOf(zone("example.test", "off", "wildcard")), nil},
		{"per-host row in wildcard mode", []model.Service{pub("docker:app", "app", "example.test", 80)}, row, cfgOf(zone("example.test", "wildcard", "wildcard")), nil},
		{"another owner's row", []model.Service{pub("docker:other", "app", "example.test", 80)}, row, phCfg(), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{c.row}, OwnedMissing: missing(c.row),
				Unavailable: c.unavail}
			got := Plan(c.desired, obs, c.cfg, t0)
			if r := repairs(got); len(r) != 0 {
				t.Fatalf("repairs %v\nplan %v", r, sums(got))
			}
		})
	}
}

// A foreign blocker (a CNAME at the name) makes the repair a Conflict.
func TestPlanRepairForeignBlockerIsConflict(t *testing.T) {
	row := owned("example.test", "app.example.test", "A", target, "docker:app")
	obs := Observed{Owned: []store.DNSRecord{row}, OwnedMissing: missing(row),
		Foreign: map[string][]dns.Record{"dnsp/example.test": {{ID: "f1", Name: "app.example.test", Type: "CNAME", Value: "elsewhere.test"}}}}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)
	if r := repairs(got); len(r) != 0 {
		t.Fatalf("repairs %v", r)
	}
	if c := ofKind(got, Conflict); len(c) != 1 || !strings.Contains(c[0].Reason, "foreign record") {
		t.Fatalf("plan %v", sums(got))
	}
}

// An owned record whose value was changed out of band is reported, never
// overwritten.
func TestPlanDriftedOwnedRecordIsSkip(t *testing.T) {
	row := owned("example.test", "app.example.test", "A", target, "docker:app")
	k := OwnedRowKey(row.Provider, row.Zone, row.Name, row.Type)
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row},
		OwnedDrifted: map[string][]dns.Record{k: {{ID: row.ProviderRecordID, Name: row.Name, Type: "A", Value: ipFX}}}}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)
	assertNone(t, got, DNSEnsure)
	if s := ofKind(got, Skip); len(s) != 1 || !strings.Contains(s[0].Reason, "changed out of band") || !strings.Contains(s[0].Reason, ipFX) {
		t.Fatalf("plan %v", sums(got))
	}
}

// A wanted scheduled row that is missing is cancelled and repaired.
func TestPlanRepairScheduledWantedRowAlsoCancels(t *testing.T) {
	row := ownedRA("example.test", "app.example.test", "A", target, "docker:app", tp(t0.Add(time.Hour)))
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}, OwnedMissing: missing(row)}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)
	if len(repairs(got)) != 1 || len(ofKind(got, DNSCancelRemoval)) != 1 {
		t.Fatalf("plan %v", sums(got))
	}
}

// A missing row whose desired value changed takes the update path (no
// Repair flag): UpdateRecord's ErrNotFound already falls back to a guarded
// create.
func TestPlanMissingRowWithNewValueIsPlainUpdate(t *testing.T) {
	row := owned("example.test", "app.example.test", "A", "192.0.2.77", "docker:app")
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}, OwnedMissing: missing(row)}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)
	e := ofKind(got, DNSEnsure)
	if len(e) != 1 || e[0].Repair || e[0].Record.Value != target {
		t.Fatalf("plan %v", sums(got))
	}
}

// ---- executor ----

type clockRig struct {
	*dnsRig
	mu  sync.Mutex
	now time.Time
}

func (c *clockRig) set(t time.Time) { c.mu.Lock(); c.now = t; c.mu.Unlock() }

func newClockRig(t *testing.T, mod ...func(*DNSExecutorConfig)) *clockRig {
	c := &clockRig{now: t0}
	mod = append([]func(*DNSExecutorConfig){func(cfg *DNSExecutorConfig) {
		cfg.Now = func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
	}}, mod...)
	c.dnsRig = perHostRig(t, mod...)
	return c
}

func repairOf(name, value, id, owner string) Action {
	a := ensure(name, value, owner)
	a.Record.ID, a.Repair = id, true
	return a
}

func (r *dnsRig) repairState(t *testing.T, name string) (repairState, bool) {
	t.Helper()
	v, ok, err := r.st.GetSetting(context.Background(), repairKey(dzp, dz, name, "A"))
	if err != nil {
		t.Fatal(err)
	}
	var s repairState
	if ok {
		if err := json.Unmarshal([]byte(v), &s); err != nil {
			t.Fatal(err)
		}
	}
	return s, ok
}

func TestDNSExecRepairRecreatesMissingRecord(t *testing.T) {
	r := newClockRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:app")
	before := r.rows(t)[0]
	keep := r.seed(t, "app.example.test", "TXT", "v=x") // another type: not a blocker
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, repairOf("app.example.test", ip1, "fake-gone", "docker:app")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords,CreateRecord" {
		t.Fatalf("calls %s", got)
	}
	recs, rows := r.zoneRecords(t), r.rows(t)
	if len(recs) != 2 || recs[0] != keep || recs[1].Value != ip1 || len(rows) != 1 || rows[0].ProviderRecordID != recs[1].ID ||
		!rows[0].CreatedAt.Equal(before.CreatedAt) || rows[0].OwnerKey != "docker:app" {
		t.Fatalf("records %+v rows %+v", recs, rows)
	}
	if !strings.Contains(r.act.messages(), "missing") {
		t.Fatalf("activity %q", r.act.messages())
	}
	if s, ok := r.repairState(t, "app.example.test"); !ok || s.Attempts != 1 {
		t.Fatalf("attempt not recorded: %+v %v", s, ok)
	}
}

// The executor's own listing shows our record after all (listing lag): no
// write, and the backoff state is reset.
func TestDNSExecRepairPresentAfterAllIsNoopAndResets(t *testing.T) {
	r := newClockRig(t)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	if err := r.st.SetSetting(context.Background(), repairKey(dzp, dz, "app.example.test", "A"), `{"attempts":3,"next_at":1,"last_at":1}`); err != nil {
		t.Fatal(err)
	}
	r.set(time.Unix(1, 0).Add(time.Minute)) // within the stale window, due
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, repairOf("app.example.test", ip1, rec.ID, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords" {
		t.Fatalf("calls %s", got)
	}
	if _, ok := r.repairState(t, "app.example.test"); ok {
		t.Fatal("backoff state not reset")
	}
}

// Never over a foreign record: one at the name (same type, or a CNAME) is a
// Conflict, nothing is created, and the attempt counts for the backoff.
func TestDNSExecRepairRefusesForeignRecord(t *testing.T) {
	for _, f := range []dns.Record{{Name: "app.example.test", Type: "A", Value: ipFX}, {Name: "app.example.test", Type: "CNAME", Value: "x.test"},
		{Name: "app.example.test", Type: "A", Value: ip1}} { // identical value, another ID: still not ours
		t.Run(f.Type+" "+f.Value, func(t *testing.T) {
			r := newClockRig(t)
			r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:app")
			r.seed(t, f.Name, f.Type, f.Value)
			skip := len(r.fk.Calls())
			err := r.apply(t, false, repairOf("app.example.test", ip1, "fake-gone", "docker:app"))
			if !errors.Is(err, ErrForeignRecord) {
				t.Fatalf("err %v", err)
			}
			if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords" {
				t.Fatalf("calls %s", got)
			}
			if s, _ := r.repairState(t, "app.example.test"); s.Attempts != 1 {
				t.Fatalf("state %+v", s)
			}
		})
	}
}

func TestDNSExecRepairListingFailureCreatesNothing(t *testing.T) {
	r := newClockRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:app")
	r.fk.FailNext("ListRecords", errors.New("down"))
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, repairOf("app.example.test", ip1, "fake-gone", "docker:app")); !errors.Is(err, ErrListingUnavailable) {
		t.Fatalf("err %v", err)
	}
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords" {
		t.Fatalf("calls %s", got)
	}
}

// A stale repair (the row changed since the plan) does nothing at all.
func TestDNSExecRepairStaleDoesNothing(t *testing.T) {
	cases := []struct {
		name string
		prep func(r *dnsRig)
		a    Action
	}{
		{"no row", func(r *dnsRig) {}, repairOf("app.example.test", ip1, "fake-gone", "docker:app")},
		{"row re-created meanwhile (other id)", func(r *dnsRig) { r.addRow(t, "app.example.test", "A", ip1, "fake-new", "docker:app") },
			repairOf("app.example.test", ip1, "fake-gone", "docker:app")},
		{"other value", func(r *dnsRig) { r.addRow(t, "app.example.test", "A", ip2, "fake-gone", "docker:app") },
			repairOf("app.example.test", ip1, "fake-gone", "docker:app")},
		{"removal scheduled", func(r *dnsRig) {
			r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:app")
			r.due(t, "app.example.test", "docker:app")
		}, repairOf("app.example.test", ip1, "fake-gone", "docker:app")},
		{"other owner", func(r *dnsRig) { r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:other") },
			repairOf("app.example.test", ip1, "fake-gone", "docker:app")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newClockRig(t)
			c.prep(r.dnsRig)
			before := r.rows(t)
			skip := len(r.fk.Calls())
			_ = r.apply(t, false, c.a)
			if got := ops(r.fk, skip); len(got) != 0 {
				t.Fatalf("provider calls %v", got)
			}
			if after := r.rows(t); fmt.Sprintf("%+v", after) != fmt.Sprintf("%+v", before) {
				t.Fatalf("rows %+v -> %+v", before, after)
			}
		})
	}
}

// Attempts back off exponentially (1m, 2m, 4m, ... capped at 1h); a repair
// that is not due makes no provider call at all.
func TestDNSExecRepairBackoff(t *testing.T) {
	r := newClockRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:app")
	a := repairOf("app.example.test", ip1, "fake-gone", "docker:app")
	now := t0
	var creates int
	for i, wait := range []time.Duration{0, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		32 * time.Minute, time.Hour, time.Hour} {
		now = now.Add(wait)
		// just before it is due: nothing
		if wait > 0 {
			r.set(now.Add(-time.Second))
			skip := len(r.fk.Calls())
			if err := r.apply(t, false, a); err != nil {
				t.Fatalf("not due: %v", err)
			}
			if got := ops(r.fk, skip); len(got) != 0 {
				t.Fatalf("attempt %d before due: %v", i, got)
			}
		}
		r.set(now)
		r.fk.FailNext("CreateRecord", errors.New("rate limited"))
		skip := len(r.fk.Calls())
		if err := r.apply(t, false, a); err == nil {
			t.Fatalf("attempt %d: want the create error", i)
		}
		if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords,CreateRecord" {
			t.Fatalf("attempt %d calls %s", i, got)
		}
		creates++
		s, _ := r.repairState(t, "app.example.test")
		want := time.Minute << i
		if want > time.Hour {
			want = time.Hour
		}
		if s.Attempts != i+1 || s.NextAt != now.Add(want).Unix() {
			t.Fatalf("attempt %d state %+v, want next %v", i, s, now.Add(want))
		}
	}
	// a state older than the stale window is forgotten: the next missing
	// incident starts again at 1m
	r.set(now.Add(3 * time.Hour))
	if err := r.apply(t, false, a); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.repairState(t, "app.example.test"); s.Attempts != 1 {
		t.Fatalf("stale state not restarted: %+v", s)
	}
}

// Without a state store for the backoff, repair is refused (never unbounded).
func TestDNSExecRepairWithoutStateStoreRefused(t *testing.T) {
	fs := &failingOwnStore{}
	r := newClockRig(t, func(c *DNSExecutorConfig) { fs.OwnershipStore = c.Store; c.Store = fs })
	r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:app")
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, repairOf("app.example.test", ip1, "fake-gone", "docker:app")); !errors.Is(err, ErrDNSRefused) {
		t.Fatalf("err %v", err)
	}
	if got := ops(r.fk, skip); len(got) != 0 {
		t.Fatalf("calls %v", got)
	}
}

func TestDNSExecRepairDryRun(t *testing.T) {
	r := newClockRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:app")
	if err := r.apply(t, true, repairOf("app.example.test", ip1, "fake-gone", "docker:app")); err != nil {
		t.Fatal(err)
	}
	if len(r.fk.Calls()) != 0 || !strings.Contains(r.act.messages(), "would re-create") {
		t.Fatalf("calls %v activity %q", r.fk.Calls(), r.act.messages())
	}
}

// ---- end to end ----

// lagging hides a record from the next n ListRecords calls (an eventually
// consistent listing). Each cycle lists once to gather and, when it repairs,
// once more in the executor.
type lagging struct {
	*fake.Fake
	mu   sync.Mutex
	hide map[string]int // name -> listings still to hide it from
}

func (l *lagging) ListRecords(ctx context.Context, z string) ([]dns.Record, error) {
	rs, err := l.Fake.ListRecords(ctx, z)
	l.mu.Lock()
	defer l.mu.Unlock()
	out := rs[:0:0]
	for _, r := range rs {
		if l.hide[r.Name] == 0 {
			out = append(out, r)
		}
	}
	for n, c := range l.hide {
		if c > 0 {
			l.hide[n] = c - 1
		}
	}
	return out, err
}

func (l *lagging) setHide(name string, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hide == nil {
		l.hide = map[string]int{}
	}
	l.hide[name] = n
}

func (w *world) hasRecord(name, value string) bool {
	for _, r := range w.records() {
		if r.Name == name && r.Type == "A" && r.Value == value {
			return true
		}
	}
	return false
}

// A crash between the provider delete and the row delete leaves a due row
// whose record is gone; when the owner returns the record is re-created.
func TestDNSE2ECrashBetweenDeleteAndRowDeleteOwnerReturns(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	w.mustCycle(t0.Add(time.Minute)) // absent: route and record scheduled
	rows := w.rows()
	if len(rows) != 1 || rows[0].RemovedAfter == nil {
		t.Fatalf("rows %+v", rows)
	}
	// the "crash": the provider delete happened, the row delete did not
	if err := w.fk.DeleteRecord(context.Background(), dz, dns.Record{ID: rows[0].ProviderRecordID}); err != nil {
		t.Fatal(err)
	}
	// the owner is back (within grace)
	w.mustCycle(t0.Add(2*time.Minute), app)
	rows = w.rows()
	if !w.hasRecord("app.example.test", ip1) || len(rows) != 1 || rows[0].RemovedAfter != nil {
		t.Fatalf("not repaired: records %+v rows %+v", w.records(), rows)
	}
	if rs := w.records(); rows[0].ProviderRecordID != rs[0].ID {
		t.Fatalf("row id %q, record %+v", rows[0].ProviderRecordID, rs)
	}
}

// Same crash, but past grace: the (missing) record's row is deleted later
// without trouble, and a returning owner then creates it as new.
func TestDNSE2EManualDeletionRepairedNextCycle(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	id := w.rows()[0].ProviderRecordID
	if err := w.fk.DeleteRecord(context.Background(), dz, dns.Record{ID: id}); err != nil { // out of band
		t.Fatal(err)
	}
	acts := w.mustCycle(t0.Add(time.Minute), app)
	if r := repairs(acts); len(r) != 1 {
		t.Fatalf("plan %v", sums(acts))
	}
	if !w.hasRecord("app.example.test", ip1) || w.rows()[0].ProviderRecordID == id {
		t.Fatalf("records %+v rows %+v", w.records(), w.rows())
	}
	// converged: no more writes
	n := len(w.fk.Calls())
	w.mustCycle(t0.Add(2*time.Minute), app)
	if got := w.writes(n); len(got) != 0 {
		t.Fatalf("writes %v", got)
	}
}

func TestDNSE2EForeignRecordAtRepairedNameIsConflict(t *testing.T) {
	for _, typ := range []string{"CNAME", "A"} {
		t.Run(typ, func(t *testing.T) {
			w := newWorld(t, "per-host")
			app := pub("docker:app", "app", dz, 80)
			w.mustCycle(t0, app)
			id := w.rows()[0].ProviderRecordID
			ctx := context.Background()
			_ = w.fk.DeleteRecord(ctx, dz, dns.Record{ID: id})
			if _, err := w.fk.CreateRecord(ctx, dz, dns.Record{Name: "app.example.test", Type: typ, Value: ipFX}); err != nil {
				t.Fatal(err)
			}
			n := len(w.fk.Calls())
			acts, _ := w.cycle(t0.Add(time.Minute), app)
			if got := w.writes(n); len(got) != 0 {
				t.Fatalf("wrote over a foreign record: %v (plan %v)", got, sums(acts))
			}
			if len(ofKind(acts, Conflict))+len(ofKind(acts, Skip)) == 0 {
				t.Fatalf("not reported: %v", sums(acts))
			}
		})
	}
}

func TestDNSE2EListingFailureNoRepair(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	_ = w.fk.DeleteRecord(context.Background(), dz, dns.Record{ID: w.rows()[0].ProviderRecordID})
	w.fk.FailNext("ListRecords", errors.New("down"))
	n := len(w.fk.Calls())
	acts, _ := w.cycle(t0.Add(time.Minute), app)
	if len(repairs(acts)) != 0 || len(w.writes(n)) != 0 {
		t.Fatalf("repaired without a listing: %v", sums(acts))
	}
	w.mustCycle(t0.Add(2*time.Minute), app)
	if !w.hasRecord("app.example.test", ip1) {
		t.Fatal("not repaired once the listing is back")
	}
}

// An unconfirmed create that never landed is repaired the next cycle.
func TestDNSE2EUnconfirmedCreateNeverLandedIsRepaired(t *testing.T) {
	var u *unconf
	w := newWorldWith(t, "per-host", func(f *fake.Fake) dns.Provider { u = &unconf{Fake: f}; return u })
	u.push("CreateRecord", unconfStep{apply: false, record: true})
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	if rows := w.rows(); len(rows) != 1 || len(w.records()) != 0 {
		t.Fatalf("rows %+v records %+v", rows, w.records())
	}
	w.mustCycle(t0.Add(time.Minute), app)
	if rows := w.rows(); !w.hasRecord("app.example.test", ip1) || rows[0].ProviderRecordID != w.records()[0].ID {
		t.Fatalf("rows %+v records %+v", rows, w.records())
	}
}

// An unconfirmed create that landed, with a listing that lags: the repair is
// planned, the provider's idempotent create returns the existing record (no
// duplicate), within the backoff nothing is written, and once the executor's
// own listing shows the record the repair is a no-op that resets the counter.
func TestDNSE2EUnconfirmedLandedNoopAndReset(t *testing.T) {
	var l *lagging
	var u *unconf
	w := newWorldWith(t, "per-host", func(f *fake.Fake) dns.Provider {
		l = &lagging{Fake: f}
		u = &unconf{Fake: f}
		return struct {
			*unconf
			lister
		}{u, l}
	})
	u.push("CreateRecord", unconfStep{apply: true, record: true})
	app := pub("docker:app", "app", dz, 80)
	l.setHide("app.example.test", 2) // this gather and the next
	w.mustCycle(t0, app)
	if rows := w.rows(); len(rows) != 1 || len(w.records()) != 1 || rows[0].ProviderRecordID != w.records()[0].ID {
		t.Fatalf("rows %+v records %+v", rows, w.records())
	}
	// cycle 2: gather lags (missing), executor listing too: the guarded
	// create is idempotent; one attempt is counted
	l.setHide("app.example.test", 2)
	n := len(w.fk.Calls())
	acts := w.mustCycle(t0.Add(time.Minute), app)
	if len(repairs(acts)) != 1 || len(w.records()) != 1 {
		t.Fatalf("plan %v records %+v", sums(acts), w.records())
	}
	if got := strings.Join(w.writes(n), ","); !strings.Contains(got, "CreateRecord") {
		t.Fatalf("writes %s", got)
	}
	key := repairKey(dzp, dz, "app.example.test", "A")
	if v, ok, _ := w.st.GetSetting(context.Background(), key); !ok || !strings.Contains(v, `"attempts":1`) {
		t.Fatalf("state %q %v", v, ok)
	}
	// cycle 3, within the backoff: the gather lags again; no provider call
	l.setHide("app.example.test", 1)
	n = len(w.fk.Calls())
	acts = w.mustCycle(t0.Add(time.Minute+30*time.Second), app)
	if len(repairs(acts)) != 1 || len(w.writes(n)) != 0 {
		t.Fatalf("plan %v writes %v", sums(acts), w.writes(n))
	}
	// cycle 4, due: the gather lags, the executor's listing sees it: no-op,
	// state reset
	l.setHide("app.example.test", 1)
	n = len(w.fk.Calls())
	acts = w.mustCycle(t0.Add(3*time.Minute), app)
	if len(repairs(acts)) != 1 || len(w.writes(n)) != 0 {
		t.Fatalf("plan %v writes %v", sums(acts), w.writes(n))
	}
	if _, ok, _ := w.st.GetSetting(context.Background(), key); ok {
		t.Fatal("backoff state not reset")
	}
}

// lister is the listing half of a provider (to compose test wrappers).
type lister interface {
	ListRecords(ctx context.Context, z string) ([]dns.Record, error)
}

// The desired value changed AND the record was changed out of band to a third
// value: never overwritten. Listed with the desired value (our own
// unconfirmed update that landed) the update is repeated.
func TestPlanDriftedOwnedRecordWithNewDesiredValue(t *testing.T) {
	row := owned("example.test", "app.example.test", "A", "192.0.2.77", "docker:app")
	k := OwnedRowKey(row.Provider, row.Zone, row.Name, row.Type)
	for _, c := range []struct {
		listed string
		update bool
	}{{ipFX, false}, {target, true}} {
		obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row},
			OwnedDrifted: map[string][]dns.Record{k: {{ID: row.ProviderRecordID, Name: row.Name, Type: "A", Value: c.listed}}}}
		got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)
		if e := ofKind(got, DNSEnsure); (len(e) == 1) != c.update || len(e) == 1 && e[0].Repair {
			t.Fatalf("listed %s: plan %v", c.listed, sums(got))
		}
		if !c.update && len(ofKind(got, Skip)) != 1 {
			t.Fatalf("listed %s: plan %v", c.listed, sums(got))
		}
	}
}

// A zone whose listing is unknown this cycle is never repaired, even when the
// caller (inconsistently) marks a row missing.
func TestPlanNoRepairWithoutListing(t *testing.T) {
	row := owned("example.test", "app.example.test", "A", target, "docker:app")
	obs := Observed{Owned: []store.DNSRecord{row}, OwnedMissing: missing(row)}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, phCfg(), t0)
	if r := repairs(got); len(r) != 0 {
		t.Fatalf("repairs %v", r)
	}
}

// sideEffect runs after once a CreateRecord of name (another writer acting
// concurrently with this batch).
type sideEffect struct {
	*fake.Fake
	name  string
	after func()
}

func (s *sideEffect) CreateRecord(ctx context.Context, z string, r dns.Record) (dns.Record, error) {
	got, err := s.Fake.CreateRecord(ctx, z, r)
	if r.Name == s.name && s.after != nil {
		f := s.after
		s.after = nil
		f()
	}
	return got, err
}

// The repair re-lists the zone instead of trusting the batch's listing: a
// record identical to ours created by someone else after an earlier action
// listed the zone is not adopted by the idempotent create.
func TestDNSExecRepairRelistsZone(t *testing.T) {
	var se *sideEffect
	r := newClockRig(t, func(c *DNSExecutorConfig) {
		se = &sideEffect{Fake: c.Providers[dzp].(*fake.Fake), name: "web.example.test"}
		c.Providers = map[string]dns.Provider{dzp: se}
	})
	r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:app")
	var foreign dns.Record
	se.after = func() { foreign = r.seed(t, "app.example.test", "A", ip1) }
	err := r.apply(t, false, ensure("web.example.test", ip1, "docker:web"), repairOf("app.example.test", ip1, "fake-gone", "docker:app"))
	if !errors.Is(err, ErrForeignRecord) {
		t.Fatalf("err %v", err)
	}
	if rows := r.rows(t); rows[0].Name != "app.example.test" || rows[0].ProviderRecordID != "fake-gone" || foreign.ID == "" {
		t.Fatalf("adopted the foreign record: rows %+v foreign %+v", rows, foreign)
	}
}
