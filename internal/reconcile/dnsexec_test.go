package reconcile

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
	"github.com/ajthom90/doorwarden/internal/store"
)

var (
	_ OwnershipStore = (*store.Store)(nil)
	_ ActivitySink   = (*store.Store)(nil)
	_ Executor       = (*DNSExecutor)(nil)
)

const (
	dz   = "example.test"
	dzp  = "dnsp"
	ip1  = "192.0.2.10"
	ip2  = "192.0.2.20"
	ipFX = "198.51.100.99"
)

// dnsZoneCfg is a zone without a certificate issuer, so Plan emits no
// CertEnsure and DNS/route executors suffice.
func dnsZoneCfg(name, mode string) config.Zone {
	return config.Zone{Name: name, TargetIP: ip1, Records: config.Records{Provider: dzp, Mode: mode}}
}

func dnsCfg(zs ...config.Zone) *config.Config {
	return &config.Config{Zones: zs, Settings: config.Settings{GracePeriod: 24 * time.Hour}}
}

// activitySink collects activity entries.
type activitySink struct {
	mu  sync.Mutex
	got []store.ActivityEntry
}

func (s *activitySink) AppendActivity(_ context.Context, e store.ActivityEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, e)
	return nil
}

func (s *activitySink) messages() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b []string
	for _, e := range s.got {
		b = append(b, e.Level+" "+e.Message)
	}
	return strings.Join(b, "\n")
}

type dnsRig struct {
	exec *DNSExecutor
	fk   *fake.Fake
	st   *store.Store
	act  *activitySink
}

func newDNSRig(t *testing.T, cfg *config.Config, mod ...func(*DNSExecutorConfig)) *dnsRig {
	t.Helper()
	r := &dnsRig{fk: fake.New(true), st: openStore(t), act: &activitySink{}}
	c := DNSExecutorConfig{Config: cfg, Providers: map[string]dns.Provider{dzp: r.fk}, Store: r.st,
		Activity: r.act, Now: fixedNow(t0)}
	for _, m := range mod {
		m(&c)
	}
	e, err := NewDNSExecutor(c)
	if err != nil {
		t.Fatal(err)
	}
	r.exec = e
	return r
}

func perHostRig(t *testing.T, mod ...func(*DNSExecutorConfig)) *dnsRig {
	return newDNSRig(t, dnsCfg(dnsZoneCfg(dz, "per-host")), mod...)
}

func (r *dnsRig) apply(t *testing.T, dry bool, as ...Action) error {
	t.Helper()
	return r.exec.Apply(context.Background(), as, dry)
}

func (r *dnsRig) rows(t *testing.T) []store.DNSRecord {
	t.Helper()
	rs, err := r.st.ListOwnedRecords(context.Background(), dzp, dz)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func (r *dnsRig) addRow(t *testing.T, name, typ, value, id, owner string) {
	t.Helper()
	if err := r.st.AddOwnedRecord(context.Background(), store.DNSRecord{Provider: dzp, Zone: dz, Name: name, Type: typ,
		Value: value, ProviderRecordID: id, OwnerKey: owner, CreatedAt: t0.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

// seed creates a record directly in the fake (as a user would) and returns it.
func (r *dnsRig) seed(t *testing.T, name, typ, value string) dns.Record {
	t.Helper()
	got, err := r.fk.CreateRecord(context.Background(), dz, dns.Record{Name: name, Type: typ, Value: value})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (r *dnsRig) zoneRecords(t *testing.T) []dns.Record {
	t.Helper()
	rs, err := r.fk.ListRecords(context.Background(), dz)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// ops returns the fake's mutating/listing operations after skip calls.
func ops(f *fake.Fake, skip int) []string {
	var out []string
	for _, c := range f.Calls()[skip:] {
		out = append(out, c.Op)
	}
	return out
}

func ensure(name, value, owner string) Action {
	return Action{Kind: DNSEnsure, Zone: dz, Host: name, Key: owner, Provider: dzp, Owner: owner,
		Record: &dns.Record{Name: name, Type: "A", Value: value}}
}

func del(name, value, id, owner string) Action {
	return Action{Kind: DNSDelete, Zone: dz, Host: name, Key: owner, Provider: dzp, Owner: owner,
		Record: &dns.Record{ID: id, Name: name, Type: "A", Value: value}}
}

// ---- construction ----

func TestDNSExecNewRejectsWildcardWithoutInstanceCap(t *testing.T) {
	st := openStore(t)
	_, err := NewDNSExecutor(DNSExecutorConfig{Config: dnsCfg(dnsZoneCfg(dz, "wildcard")),
		Providers: map[string]dns.Provider{dzp: fake.New(false)}, Store: st})
	if err == nil || !strings.Contains(err.Error(), dzp) || !strings.Contains(err.Error(), dz) {
		t.Fatalf("want loud error naming provider and zone, got %v", err)
	}
	// per-host does not need WildcardA
	if _, err := NewDNSExecutor(DNSExecutorConfig{Config: dnsCfg(dnsZoneCfg(dz, "per-host")),
		Providers: map[string]dns.Provider{dzp: fake.New(false)}, Store: st}); err != nil {
		t.Fatal(err)
	}
}

func TestDNSExecNewRejectsMissingProviderAndNils(t *testing.T) {
	st := openStore(t)
	if _, err := NewDNSExecutor(DNSExecutorConfig{Config: dnsCfg(dnsZoneCfg(dz, "per-host")),
		Providers: map[string]dns.Provider{}, Store: st}); err == nil || !strings.Contains(err.Error(), dzp) {
		t.Fatalf("missing provider: %v", err)
	}
	if _, err := NewDNSExecutor(DNSExecutorConfig{Config: dnsCfg(dnsZoneCfg(dz, "per-host")),
		Providers: map[string]dns.Provider{dzp: fake.New(true)}}); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewDNSExecutor(DNSExecutorConfig{Providers: map[string]dns.Provider{}, Store: st}); err == nil {
		t.Fatal("nil config accepted")
	}
	// records off: provider need not exist
	if _, err := NewDNSExecutor(DNSExecutorConfig{Config: dnsCfg(dnsZoneCfg(dz, "off")),
		Providers: map[string]dns.Provider{}, Store: st}); err != nil {
		t.Fatal(err)
	}
}

// ---- ensure ----

func TestDNSExecEnsureCreatesAndOwns(t *testing.T) {
	r := perHostRig(t)
	a := ensure("App.Example.Test.", ip1, "docker:app")
	a.Record.TTL = 120
	if err := r.apply(t, false, a); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(ops(r.fk, 0), ",")
	if got != "ListRecords,CreateRecord" {
		t.Fatalf("calls %s", got)
	}
	c := r.fk.Calls()[1]
	if c.Zone != dz || c.Record.Name != "app.example.test" || c.Record.Type != "A" || c.Record.Value != ip1 || c.Record.TTL != 120 || c.Record.ID != "" {
		t.Fatalf("create call %+v", c)
	}
	rows := r.rows(t)
	if len(rows) != 1 || rows[0].Name != "app.example.test" || rows[0].OwnerKey != "docker:app" ||
		rows[0].ProviderRecordID != "fake-1" || rows[0].Value != ip1 || !rows[0].CreatedAt.Equal(t0) {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSExecEnsureIdempotentNoProviderCall(t *testing.T) {
	r := perHostRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-9", "docker:app")
	if err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if n := len(r.fk.Calls()); n != 0 {
		t.Fatalf("provider called %d times", n)
	}
}

func TestDNSExecEnsureUpdatesByStoredID(t *testing.T) {
	r := perHostRig(t)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	skip := len(r.fk.Calls())
	a := ensure("app.example.test", ip2, "docker:app")
	a.Record.ID = "bogus-from-action" // the stored ID wins
	if err := r.apply(t, false, a); err != nil {
		t.Fatal(err)
	}
	cs := r.fk.Calls()[skip:]
	if len(cs) != 1 || cs[0].Op != "UpdateRecord" || cs[0].Record.ID != rec.ID || cs[0].Record.Value != ip2 {
		t.Fatalf("calls %+v", cs)
	}
	rows := r.rows(t)
	if len(rows) != 1 || rows[0].Value != ip2 || rows[0].ProviderRecordID != rec.ID || rows[0].OwnerKey != "docker:app" ||
		!rows[0].CreatedAt.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSExecEnsureUpdateNotFoundRecreatesAfterCheck(t *testing.T) {
	r := perHostRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "gone-id", "docker:app") // record deleted out of band
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ops(r.fk, 0), ","); got != "UpdateRecord,ListRecords,CreateRecord" {
		t.Fatalf("calls %s", got)
	}
	rows := r.rows(t)
	if len(rows) != 1 || rows[0].ProviderRecordID != "fake-1" || rows[0].Value != ip2 {
		t.Fatalf("rows %+v", rows)
	}

	// ... but a foreign record that appeared meanwhile blocks the re-create
	r2 := perHostRig(t)
	r2.addRow(t, "app.example.test", "A", ip1, "gone-id", "docker:app")
	r2.seed(t, "app.example.test", "A", ipFX)
	skip := len(r2.fk.Calls())
	err := r2.apply(t, false, ensure("app.example.test", ip2, "docker:app"))
	if !errors.Is(err, ErrForeignRecord) {
		t.Fatalf("want ErrForeignRecord, got %v", err)
	}
	if got := strings.Join(ops(r2.fk, skip), ","); got != "UpdateRecord,ListRecords" {
		t.Fatalf("calls %s", got)
	}
	if recs := r2.zoneRecords(t); len(recs) != 1 || recs[0].Value != ipFX {
		t.Fatalf("foreign record touched: %+v", recs)
	}
}

// noUpdate narrows the fake's instance capabilities.
type noUpdate struct{ *fake.Fake }

func (n noUpdate) Capabilities() dns.Capabilities {
	c := n.Fake.Capabilities()
	c.Update = false
	return c
}

func TestDNSExecEnsureWithoutUpdateCapReplacesOwnRecord(t *testing.T) {
	r := perHostRig(t, func(c *DNSExecutorConfig) { c.Providers[dzp] = noUpdate{c.Providers[dzp].(*fake.Fake)} })
	other := r.seed(t, "other.example.test", "A", ipFX)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatal(err)
	}
	cs := r.fk.Calls()[skip:]
	if got := strings.Join(ops(r.fk, skip), ","); got != "DeleteRecord,ListRecords,CreateRecord" || cs[0].Record.ID != rec.ID {
		t.Fatalf("calls %+v", cs)
	}
	rows := r.rows(t)
	if len(rows) != 1 || rows[0].Value != ip2 || rows[0].ProviderRecordID == rec.ID {
		t.Fatalf("rows %+v", rows)
	}
	recs := r.zoneRecords(t)
	if len(recs) != 2 || recs[0].ID != other.ID {
		t.Fatalf("zone %+v", recs)
	}
}

func TestDNSExecEnsureOtherOwnerConflictNoProviderCall(t *testing.T) {
	r := perHostRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-9", "static:app")
	err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app"))
	if !errors.Is(err, ErrOwnerConflict) || !errors.Is(err, store.ErrOwnerConflict) {
		t.Fatalf("want ErrOwnerConflict, got %v", err)
	}
	if !strings.Contains(err.Error(), "DNSEnsure dnsp/example.test app.example.test A") {
		t.Fatalf("error not prefixed: %v", err)
	}
	if n := len(r.fk.Calls()); n != 0 {
		t.Fatalf("provider called %d times", n)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].OwnerKey != "static:app" || rows[0].Value != ip1 {
		t.Fatalf("rows %+v", rows)
	}
	if m := r.act.messages(); !strings.Contains(m, "owned by static:app") || !strings.Contains(strings.ToLower(m), "conflict") {
		t.Fatalf("activity %q", m)
	}
}

func TestDNSExecEnsureRefusesForeignRecord(t *testing.T) {
	for _, tc := range []struct{ name, typ, value string }{
		{"identical value", "A", ip1}, // Create would be idempotent and adopt it: must refuse
		{"other value", "A", ipFX},
		{"cname", "CNAME", "elsewhere.example.test"},
		{"mixed case name", "A", ip1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := perHostRig(t)
			name := "app.example.test"
			fr := r.seed(t, name, tc.typ, tc.value)
			skip := len(r.fk.Calls())
			if tc.name == "mixed case name" {
				name = "APP.Example.Test." // the action spells the same name differently
			}
			err := r.apply(t, false, ensure(name, ip1, "docker:app"))
			if !errors.Is(err, ErrForeignRecord) {
				t.Fatalf("want ErrForeignRecord, got %v", err)
			}
			if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords" {
				t.Fatalf("calls %s", got)
			}
			if rows := r.rows(t); len(rows) != 0 {
				t.Fatalf("ownership written: %+v", rows)
			}
			if recs := r.zoneRecords(t); len(recs) != 1 || recs[0] != fr {
				t.Fatalf("zone %+v", recs)
			}
			if m := r.act.messages(); !strings.Contains(strings.ToLower(m), "conflict") {
				t.Fatalf("activity %q", m)
			}
		})
	}
}

func TestDNSExecEnsureListingFailureNeverCreatesBlind(t *testing.T) {
	r := perHostRig(t)
	r.fk.FailNext("ListRecords", errors.New("boom"))
	err := r.apply(t, false, ensure("a.example.test", ip1, "docker:a"), ensure("b.example.test", ip1, "docker:b"))
	if !errors.Is(err, ErrListingUnavailable) {
		t.Fatalf("want ErrListingUnavailable, got %v", err)
	}
	// the failure is cached for the batch: one listing, no create
	if got := strings.Join(ops(r.fk, 0), ","); got != "ListRecords" {
		t.Fatalf("calls %s", got)
	}
	if rows := r.rows(t); len(rows) != 0 {
		t.Fatalf("rows %+v", rows)
	}
	// next batch lists again
	if err := r.apply(t, false, ensure("a.example.test", ip1, "docker:a")); err != nil {
		t.Fatal(err)
	}
}

func TestDNSExecListingCachedPerBatch(t *testing.T) {
	r := perHostRig(t)
	if err := r.apply(t, false, ensure("a.example.test", ip1, "docker:a"), ensure("b.example.test", ip1, "docker:b")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ops(r.fk, 0), ","); got != "ListRecords,CreateRecord,CreateRecord" {
		t.Fatalf("calls %s", got)
	}
	if err := r.apply(t, false, ensure("c.example.test", ip1, "docker:c")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ops(r.fk, 3), ","); got != "ListRecords,CreateRecord" {
		t.Fatalf("second batch calls %s", got)
	}
	if n := len(r.rows(t)); n != 3 {
		t.Fatalf("rows %d", n)
	}
}

func TestDNSExecEnsureRecordExistsRaceIsConflict(t *testing.T) {
	r := perHostRig(t)
	r.fk.FailNext("CreateRecord", dns.ErrRecordExists)
	err := r.apply(t, false, ensure("a.example.test", ip1, "docker:a"))
	if !errors.Is(err, ErrForeignRecord) {
		t.Fatalf("want ErrForeignRecord, got %v", err)
	}
	if rows := r.rows(t); len(rows) != 0 {
		t.Fatalf("rows %+v", rows)
	}
	if m := r.act.messages(); !strings.Contains(strings.ToLower(m), "conflict") {
		t.Fatalf("activity %q", m)
	}
}

// failingOwnStore fails AddOwnedRecord n times (and optionally ListOwnedRecords
// after the first call).
type failingOwnStore struct {
	OwnershipStore
	mu       sync.Mutex
	addFails int
	adds     int
}

func (f *failingOwnStore) AddOwnedRecord(ctx context.Context, r store.DNSRecord) error {
	f.mu.Lock()
	f.adds++
	fail := f.addFails > 0
	if fail {
		f.addFails--
	}
	f.mu.Unlock()
	if fail {
		return errors.New("disk full")
	}
	return f.OwnershipStore.AddOwnedRecord(ctx, r)
}

func TestDNSExecRollbackWhenOwnershipCannotBeRecorded(t *testing.T) {
	fs := &failingOwnStore{addFails: 2}
	r := perHostRig(t, func(c *DNSExecutorConfig) { fs.OwnershipStore = c.Store; c.Store = fs })
	keep := r.seed(t, "other.example.test", "A", ipFX)
	skip := len(r.fk.Calls())
	err := r.apply(t, false, ensure("a.example.test", ip1, "docker:a"))
	if err == nil || !strings.Contains(err.Error(), "a.example.test") || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err %v", err)
	}
	if fs.adds != 2 {
		t.Fatalf("AddOwnedRecord attempts %d, want 2 (one retry)", fs.adds)
	}
	cs := r.fk.Calls()[skip:]
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords,CreateRecord,DeleteRecord" {
		t.Fatalf("calls %s", got)
	}
	if cs[2].Record.ID != "fake-2" {
		t.Fatalf("rollback must target the created ID only: %+v", cs[2])
	}
	if recs := r.zoneRecords(t); len(recs) != 1 || recs[0] != keep {
		t.Fatalf("zone %+v", recs)
	}
	if m := r.act.messages(); !strings.Contains(m, "error") {
		t.Fatalf("activity not loud: %q", m)
	}
}

func TestDNSExecRetrySucceedsNoRollback(t *testing.T) {
	fs := &failingOwnStore{addFails: 1}
	r := perHostRig(t, func(c *DNSExecutorConfig) { fs.OwnershipStore = c.Store; c.Store = fs })
	if err := r.apply(t, false, ensure("a.example.test", ip1, "docker:a")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ops(r.fk, 0), ","); got != "ListRecords,CreateRecord" {
		t.Fatalf("calls %s", got)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].ProviderRecordID != "fake-1" {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSExecRollbackFailureNamesRecord(t *testing.T) {
	fs := &failingOwnStore{addFails: 2}
	r := perHostRig(t, func(c *DNSExecutorConfig) { fs.OwnershipStore = c.Store; c.Store = fs })
	r.fk.FailNext("DeleteRecord", errors.New("api down"))
	err := r.apply(t, false, ensure("a.example.test", ip1, "docker:a"))
	if err == nil || !strings.Contains(err.Error(), "a.example.test") || !strings.Contains(err.Error(), "fake-1") ||
		!strings.Contains(err.Error(), "api down") {
		t.Fatalf("err %v", err)
	}
	if recs := r.zoneRecords(t); len(recs) != 1 {
		t.Fatalf("zone %+v", recs)
	}
}

// ---- delete ----

func TestDNSExecDeleteOwnedByStoredIDAndValue(t *testing.T) {
	r := perHostRig(t)
	keep := r.seed(t, "other.example.test", "A", ipFX)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	skip := len(r.fk.Calls())
	// the action's ID/value are wrong on purpose: the stored row is used
	if err := r.apply(t, false, del("app.example.test", ipFX, keep.ID, "docker:app")); err != nil {
		t.Fatal(err)
	}
	cs := r.fk.Calls()[skip:]
	if len(cs) != 1 || cs[0].Op != "DeleteRecord" || cs[0].Record.ID != rec.ID || cs[0].Record.Value != ip1 ||
		cs[0].Record.Name != "app.example.test" || cs[0].Record.Type != "A" {
		t.Fatalf("calls %+v", cs)
	}
	if rows := r.rows(t); len(rows) != 0 {
		t.Fatalf("rows %+v", rows)
	}
	if recs := r.zoneRecords(t); len(recs) != 1 || recs[0] != keep {
		t.Fatalf("zone %+v", recs)
	}
}

func TestDNSExecDeleteEmptyStoredIDUsesStoredValue(t *testing.T) {
	r := perHostRig(t)
	// the user replaced our record with their own value; we only know our value
	theirs := r.seed(t, "app.example.test", "A", ipFX)
	r.addRow(t, "app.example.test", "A", ip1, "", "docker:app")
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, del("app.example.test", ipFX, "", "docker:app")); err != nil {
		t.Fatal(err)
	}
	cs := r.fk.Calls()[skip:]
	if len(cs) != 1 || cs[0].Record.Value != ip1 || cs[0].Record.ID != "" {
		t.Fatalf("calls %+v", cs)
	}
	if recs := r.zoneRecords(t); len(recs) != 1 || recs[0] != theirs {
		t.Fatalf("their record deleted: %+v", recs)
	}
}

func TestDNSExecDeleteOwnerMismatchRefused(t *testing.T) {
	r := perHostRig(t)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "static:app")
	skip := len(r.fk.Calls())
	err := r.apply(t, false, del("app.example.test", ip1, rec.ID, "docker:app"))
	if !errors.Is(err, ErrOwnerConflict) {
		t.Fatalf("want ErrOwnerConflict, got %v", err)
	}
	if n := len(r.fk.Calls()) - skip; n != 0 {
		t.Fatalf("provider called %d times", n)
	}
	if rows := r.rows(t); len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	// empty owner on the action is refused too
	if err := r.apply(t, false, del("app.example.test", ip1, rec.ID, "")); err == nil {
		t.Fatal("empty owner accepted")
	}
}

func TestDNSExecDeleteWithoutRowIsNoop(t *testing.T) {
	r := perHostRig(t)
	r.seed(t, "app.example.test", "A", ip1) // foreign, not owned
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, del("app.example.test", ip1, "fake-1", "docker:app")); err != nil {
		t.Fatal(err)
	}
	if n := len(r.fk.Calls()) - skip; n != 0 {
		t.Fatalf("provider called %d times", n)
	}
	if len(r.zoneRecords(t)) != 1 {
		t.Fatal("foreign record deleted")
	}
}

func TestDNSExecNeverDeletesWildcard(t *testing.T) {
	r := newDNSRig(t, dnsCfg(dnsZoneCfg(dz, "wildcard")))
	rec := r.seed(t, "*.example.test", "A", ip1)
	r.addRow(t, "*.example.test", "A", ip1, rec.ID, WildcardOwnerKey(dz))
	skip := len(r.fk.Calls())
	err := r.apply(t, false, del("*.example.test", ip1, rec.ID, WildcardOwnerKey(dz)))
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("want refusal, got %v", err)
	}
	if n := len(r.fk.Calls()) - skip; n != 0 {
		t.Fatalf("provider called %d times", n)
	}
	if rows := r.rows(t); len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSExecDeleteProviderFailureKeepsRow(t *testing.T) {
	r := perHostRig(t)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	r.fk.FailNext("DeleteRecord", errors.New("api down"))
	if err := r.apply(t, false, del("app.example.test", ip1, rec.ID, "docker:app")); err == nil {
		t.Fatal("want error")
	}
	if rows := r.rows(t); len(rows) != 1 {
		t.Fatalf("row dropped: %+v", rows)
	}
	// already gone at the provider: the row is forgotten
	r.fk.FailNext("DeleteRecord", dns.ErrNotFound)
	if err := r.apply(t, false, del("app.example.test", ip1, rec.ID, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if rows := r.rows(t); len(rows) != 0 {
		t.Fatalf("rows %+v", rows)
	}
}

// ---- scope guards ----

func TestDNSExecRefusesOutOfScopeActions(t *testing.T) {
	r := perHostRig(t)
	cases := map[string]Action{
		"name outside zone": ensure("app.example.invalid", ip1, "docker:app"),
		"suffix trick":      ensure("appexample.test", ip1, "docker:app"),
		"unknown provider": func() Action {
			a := ensure("app.example.test", ip1, "docker:app")
			a.Provider = "other"
			return a
		}(),
		"unknown zone": func() Action {
			a := ensure("app.other.test", ip1, "docker:app")
			a.Zone = "other.test"
			return a
		}(),
		"no record":                   {Kind: DNSEnsure, Zone: dz, Provider: dzp, Owner: "docker:app"},
		"no owner":                    ensure("app.example.test", ip1, ""),
		"no value":                    ensure("app.example.test", "", "docker:app"),
		"zone owner for another zone": ensure("*.example.test", ip1, WildcardOwnerKey("other.test")),
	}
	for n, a := range cases {
		t.Run(n, func(t *testing.T) {
			if err := r.apply(t, false, a); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if n := len(r.fk.Calls()); n != 0 {
		t.Fatalf("provider called %d times", n)
	}
	// records off: no actions accepted
	r2 := newDNSRig(t, dnsCfg(dnsZoneCfg(dz, "off")))
	if err := r2.apply(t, false, ensure("app.example.test", ip1, "docker:app")); err == nil || len(r2.fk.Calls()) != 0 {
		t.Fatalf("records-off zone accepted: %v", err)
	}
}

func TestDNSExecNormalizesConfigZone(t *testing.T) {
	r := newDNSRig(t, dnsCfg(dnsZoneCfg("Example.Test.", "per-host")))
	if err := r.apply(t, false, ensure("App.Example.Test", ip1, "docker:app")); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.fk.Calls() {
		if c.Zone != dz {
			t.Fatalf("provider zone %q", c.Zone)
		}
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].Zone != dz {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSExecIgnoresOtherKinds(t *testing.T) {
	r := perHostRig(t)
	if err := r.apply(t, false, Action{Kind: RouteWrite, Key: "x"}, Action{Kind: Conflict}); err != nil {
		t.Fatal(err)
	}
	if len(r.fk.Calls()) != 0 {
		t.Fatal("provider called")
	}
}

// ---- batching ----

func TestDNSExecFailureDoesNotStopBatch(t *testing.T) {
	r := perHostRig(t)
	r.fk.FailNext("CreateRecord", errors.New("rate limited"))
	err := r.apply(t, false, ensure("a.example.test", ip1, "docker:a"), ensure("b.example.test", ip1, "docker:b"))
	if err == nil || !strings.Contains(err.Error(), "DNSEnsure dnsp/example.test a.example.test A") ||
		!strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("err %v", err)
	}
	rows := r.rows(t)
	if len(rows) != 1 || rows[0].Name != "b.example.test" {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSExecStopsOnCancel(t *testing.T) {
	r := perHostRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.exec.Apply(ctx, []Action{ensure("a.example.test", ip1, "docker:a")}, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if len(r.fk.Calls()) != 0 {
		t.Fatal("provider called")
	}
}

// hangingList blocks ListRecords until its ctx is done.
type hangingList struct {
	*fake.Fake
	sawDeadline bool
}

func (h *hangingList) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	_, h.sawDeadline = ctx.Deadline()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second): // a missing timeout fails, not hangs
		return nil, errors.New("hangingList: call was never timed out")
	}
}

func TestDNSExecPerCallTimeout(t *testing.T) {
	h := &hangingList{Fake: fake.New(true)}
	r := perHostRig(t, func(c *DNSExecutorConfig) { c.Providers[dzp] = h; c.CallTimeout = 20 * time.Millisecond })
	start := time.Now()
	err := r.apply(t, false, ensure("a.example.test", ip1, "docker:a"))
	if !errors.Is(err, ErrListingUnavailable) || !errors.Is(err, context.DeadlineExceeded) || !h.sawDeadline {
		t.Fatalf("err %v deadline %v", err, h.sawDeadline)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not applied")
	}
}

// ---- dry run ----

func TestDNSExecDryRunWritesNothing(t *testing.T) {
	r := perHostRig(t)
	rec := r.seed(t, "old.example.test", "A", ip1)
	r.addRow(t, "old.example.test", "A", ip1, rec.ID, "docker:old")
	r.addRow(t, "upd.example.test", "A", ip1, "fake-77", "docker:upd")
	skip := len(r.fk.Calls())
	err := r.apply(t, true,
		ensure("new.example.test", ip1, "docker:new"),
		ensure("upd.example.test", ip2, "docker:upd"),
		del("old.example.test", ip1, rec.ID, "docker:old"))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(r.fk.Calls()) - skip; n != 0 {
		t.Fatalf("dry run called the provider %d times", n)
	}
	rows := r.rows(t)
	if len(rows) != 2 || rows[1].Value != ip1 {
		t.Fatalf("rows changed: %+v", rows)
	}
	m := r.act.messages()
	for _, want := range []string{"would create", "not performed", "would update", "would delete"} {
		if !strings.Contains(m, want) {
			t.Fatalf("activity missing %q: %q", want, m)
		}
	}
}

// ---- GatherObserved ----

func TestGatherObserved(t *testing.T) {
	st := openStore(t)
	f1, f2 := fake.New(true), fake.New(true)
	ctx := context.Background()
	mine, _ := f1.CreateRecord(ctx, dz, dns.Record{Name: "app.example.test", Type: "A", Value: ip1})
	theirs, _ := f1.CreateRecord(ctx, dz, dns.Record{Name: "nas.example.test", Type: "A", Value: ipFX})
	txt, _ := f1.CreateRecord(ctx, dz, dns.Record{Name: "app.example.test", Type: "TXT", Value: "v=x"})
	if err := st.AddOwnedRecord(ctx, store.DNSRecord{Provider: dzp, Zone: dz, Name: "App.Example.Test", Type: "a",
		Value: ip1, ProviderRecordID: mine.ID, OwnerKey: "docker:app", CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	f2.FailNext("ListRecords", errors.New("unreachable"))
	provs := map[string]dns.Provider{dzp: f1, "p2": f2}
	zones := []ZoneRef{{dzp, "Example.Test."}, {dzp, dz}, {"p2", "other.test"}, {"p3", "third.test"}}
	owned, foreign, errs := GatherObserved(ctx, provs, st, zones, 0)
	if len(owned) != 1 || owned[0].OwnerKey != "docker:app" {
		t.Fatalf("owned %+v", owned)
	}
	got, ok := foreign[dzp+"/"+dz]
	if !ok || len(got) != 2 || got[0] != theirs || got[1] != txt {
		t.Fatalf("foreign %+v", foreign)
	}
	if _, ok := foreign["p2/other.test"]; ok {
		t.Fatal("failed listing must leave the key absent")
	}
	if _, ok := foreign["p3/third.test"]; ok {
		t.Fatal("missing provider must leave the key absent")
	}
	if len(errs) != 2 {
		t.Fatalf("errs %v", errs)
	}
	if n := len(f1.Calls()); n != 4 { // 3 creates + 1 deduped listing
		t.Fatalf("f1 calls %d", n)
	}

	// an empty successful listing is present and empty
	_, foreign, errs = GatherObserved(ctx, map[string]dns.Provider{"p2": f2}, st, []ZoneRef{{"p2", "other.test"}}, 0)
	if v, ok := foreign["p2/other.test"]; !ok || len(v) != 0 || len(errs) != 0 {
		t.Fatalf("foreign %+v errs %v", foreign, errs)
	}
}

func TestDNSZoneRefs(t *testing.T) {
	cfg := dnsCfg(dnsZoneCfg("B.test.", "per-host"), dnsZoneCfg("a.test", "wildcard"), dnsZoneCfg("off.test", "off"),
		dnsZoneCfg("unset.test", ""))
	got := DNSZoneRefs(cfg)
	if len(got) != 2 || got[0] != (ZoneRef{dzp, "a.test"}) || got[1] != (ZoneRef{dzp, "b.test"}) {
		t.Fatalf("%+v", got)
	}
}
