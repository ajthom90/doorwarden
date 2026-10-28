package reconcile

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
	"github.com/ajthom90/doorwarden/internal/store"
)

// idless is a provider that never reports record IDs (Update/Delete then
// target (name, type) / exact (name, type, value)). extra records are added
// to every listing (to model an RRset with several values).
type idless struct {
	*fake.Fake
	extra []dns.Record
}

func (p *idless) CreateRecord(ctx context.Context, z string, r dns.Record) (dns.Record, error) {
	got, err := p.Fake.CreateRecord(ctx, z, r)
	got.ID = ""
	return got, err
}

func (p *idless) UpdateRecord(ctx context.Context, z string, r dns.Record) (dns.Record, error) {
	got, err := p.Fake.UpdateRecord(ctx, z, r)
	got.ID = ""
	return got, err
}

func (p *idless) ListRecords(ctx context.Context, z string) ([]dns.Record, error) {
	rs, err := p.Fake.ListRecords(ctx, z)
	if err != nil {
		return nil, err
	}
	rs = append(rs, p.extra...)
	for i := range rs {
		rs[i].ID = ""
	}
	return rs, nil
}

func idlessRig(t *testing.T) (*dnsRig, *idless) {
	var p *idless
	r := perHostRig(t, func(c *DNSExecutorConfig) {
		p = &idless{Fake: c.Providers[dzp].(*fake.Fake)}
		c.Providers[dzp] = p
	})
	return r, p
}

func noUpdateRig(t *testing.T) *dnsRig {
	return perHostRig(t, func(c *DNSExecutorConfig) { c.Providers[dzp] = noUpdate{c.Providers[dzp].(*fake.Fake)} })
}

func countOps(f *fake.Fake, skip int, op string) int {
	n := 0
	for _, o := range ops(f, skip) {
		if o == op {
			n++
		}
	}
	return n
}

// ---- item 1: never UpdateRecord without a stored ID ----

// The reproduction: our ID-less row, our record vanished, the user created
// their own A at the name. Must be a Conflict that changes nothing.
func TestDNSExecEmptyStoredIDNeverOverwritesForeign(t *testing.T) {
	for _, mk := range []struct {
		name string
		rig  func(*testing.T) *dnsRig
	}{
		{"update-capable fake", func(t *testing.T) *dnsRig { return perHostRig(t) }},
		{"id-less provider", func(t *testing.T) *dnsRig { r, _ := idlessRig(t); return r }},
	} {
		t.Run(mk.name, func(t *testing.T) {
			r := mk.rig(t)
			r.addRow(t, "app.example.test", "A", ip1, "", "docker:app")
			theirs := r.seed(t, "app.example.test", "A", ipFX)
			skip := len(r.fk.Calls())
			err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app"))
			if !errors.Is(err, ErrForeignRecord) {
				t.Fatalf("want ErrForeignRecord, got %v", err)
			}
			if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords" {
				t.Fatalf("calls %s", got)
			}
			if recs := r.zoneRecords(t); len(recs) != 1 || recs[0] != theirs {
				t.Fatalf("their record touched: %+v", recs)
			}
			if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip1 || rows[0].ProviderRecordID != "" {
				t.Fatalf("row changed: %+v", rows)
			}
			if m := r.act.messages(); !strings.Contains(strings.ToLower(m), "conflict") {
				t.Fatalf("activity %q", m)
			}
		})
	}
}

func TestDNSExecEmptyStoredIDReplacesOwnRecord(t *testing.T) {
	r, _ := idlessRig(t)
	r.seed(t, "app.example.test", "A", ip1) // ours
	r.addRow(t, "app.example.test", "A", ip1, "", "docker:app")
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatal(err)
	}
	cs := r.fk.Calls()[skip:]
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords,DeleteRecord,CreateRecord" {
		t.Fatalf("calls %s", got)
	}
	if cs[1].Record.Value != ip1 || cs[1].Record.ID != "" || cs[2].Record.Value != ip2 {
		t.Fatalf("calls %+v", cs)
	}
	if recs := r.zoneRecords(t); len(recs) != 1 || recs[0].Value != ip2 {
		t.Fatalf("zone %+v", recs)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip2 || rows[0].OwnerKey != "docker:app" {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSExecEmptyStoredIDVanishedIsRecreated(t *testing.T) {
	r, _ := idlessRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "", "docker:app")
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if n := countOps(r.fk, 0, "UpdateRecord"); n != 0 {
		t.Fatal("UpdateRecord called without an ID")
	}
	if n := countOps(r.fk, 0, "CreateRecord"); n != 1 {
		t.Fatalf("creates %d", n)
	}
	if recs := r.zoneRecords(t); len(recs) != 1 || recs[0].Value != ip2 {
		t.Fatalf("zone %+v", recs)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip2 {
		t.Fatalf("rows %+v", rows)
	}
}

// A second value next to ours (the user extended the RRset): replacing would
// destroy theirs or adopt it; Conflict.
func TestDNSExecEmptyStoredIDSecondValueIsConflict(t *testing.T) {
	r, p := idlessRig(t)
	r.seed(t, "app.example.test", "A", ip1)
	p.extra = []dns.Record{{Name: "app.example.test", Type: "A", Value: ipFX}}
	r.addRow(t, "app.example.test", "A", ip1, "", "docker:app")
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); !errors.Is(err, ErrForeignRecord) {
		t.Fatalf("want ErrForeignRecord, got %v", err)
	}
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords" {
		t.Fatalf("calls %s", got)
	}
	if rows := r.rows(t); rows[0].Value != ip1 {
		t.Fatalf("rows %+v", rows)
	}
}

// ---- item 2: pre-checks before any delete; restore on create failure ----

func TestDNSExecReplaceListingFailureChangesNothing(t *testing.T) {
	for _, mk := range []struct {
		name string
		rig  func(*testing.T) *dnsRig
		id   bool
	}{
		{"no update capability", noUpdateRig, true},
		{"empty stored id", func(t *testing.T) *dnsRig { r, _ := idlessRig(t); return r }, false},
	} {
		t.Run(mk.name, func(t *testing.T) {
			r := mk.rig(t)
			rec := r.seed(t, "app.example.test", "A", ip1)
			id := ""
			if mk.id {
				id = rec.ID
			}
			r.addRow(t, "app.example.test", "A", ip1, id, "docker:app")
			r.fk.FailNext("ListRecords", errors.New("unreachable"))
			skip := len(r.fk.Calls())
			if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); !errors.Is(err, ErrListingUnavailable) {
				t.Fatalf("want ErrListingUnavailable, got %v", err)
			}
			if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords" {
				t.Fatalf("calls %s", got)
			}
			if recs := r.zoneRecords(t); len(recs) != 1 || recs[0].Value != ip1 {
				t.Fatalf("zone %+v", recs)
			}
			if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip1 || rows[0].ProviderRecordID != id {
				t.Fatalf("rows %+v", rows)
			}
		})
	}
}

func TestDNSExecReplaceForeignBlockerChangesNothing(t *testing.T) {
	r := noUpdateRig(t)
	rec := r.seed(t, "app.example.test", "A", ip1)
	cn := r.seed(t, "app.example.test", "CNAME", "elsewhere.example.test")
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); !errors.Is(err, ErrForeignRecord) {
		t.Fatalf("want ErrForeignRecord, got %v", err)
	}
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords" {
		t.Fatalf("calls %s", got)
	}
	if recs := r.zoneRecords(t); len(recs) != 2 || recs[0] != rec || recs[1] != cn {
		t.Fatalf("zone %+v", recs)
	}
}

func TestDNSExecReplaceRestoresOldValueWhenCreateFails(t *testing.T) {
	r := noUpdateRig(t)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	r.fk.FailNext("CreateRecord", errors.New("rate limited"))
	skip := len(r.fk.Calls())
	err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app"))
	if err == nil || !strings.Contains(err.Error(), "rate limited") || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("err %v", err)
	}
	cs := r.fk.Calls()[skip:]
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords,DeleteRecord,CreateRecord,CreateRecord" ||
		cs[2].Record.Value != ip2 || cs[3].Record.Value != ip1 {
		t.Fatalf("calls %+v", cs)
	}
	recs := r.zoneRecords(t)
	if len(recs) != 1 || recs[0].Value != ip1 {
		t.Fatalf("zone %+v", recs)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip1 || rows[0].ProviderRecordID != recs[0].ID {
		t.Fatalf("row must point at the restored record: %+v", rows)
	}
	if m := r.act.messages(); !strings.Contains(m, "error") {
		t.Fatalf("not loud: %q", m)
	}
}

func TestDNSExecReplaceRestoreFailureReported(t *testing.T) {
	r := noUpdateRig(t)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	r.fk.FailNext("CreateRecord", errors.New("rate limited"))
	r.fk.FailNext("CreateRecord", errors.New("still limited"))
	err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app"))
	if err == nil || !strings.Contains(err.Error(), "still limited") || !strings.Contains(err.Error(), "app.example.test") {
		t.Fatalf("err %v", err)
	}
	// the row is kept (stale): the next cycle re-creates through the guarded path
	if rows := r.rows(t); len(rows) != 1 || rows[0].OwnerKey != "docker:app" {
		t.Fatalf("rows %+v", rows)
	}
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if recs := r.zoneRecords(t); len(recs) != 1 || recs[0].Value != ip2 {
		t.Fatalf("zone %+v", recs)
	}
}

// ---- item 3: providers that rotate IDs on update ----

// rotating replaces the record on UpdateRecord (new ID); with hideID it
// returns no ID at all.
type rotating struct {
	*fake.Fake
	hideID bool
}

func (p *rotating) UpdateRecord(ctx context.Context, z string, r dns.Record) (dns.Record, error) {
	if err := p.Fake.DeleteRecord(ctx, z, dns.Record{ID: r.ID}); err != nil {
		return dns.Record{}, err
	}
	r.ID = ""
	got, err := p.Fake.CreateRecord(ctx, z, r)
	if p.hideID {
		got.ID = ""
	}
	return got, err
}

func rotatingRig(t *testing.T, hide bool) *dnsRig {
	return perHostRig(t, func(c *DNSExecutorConfig) {
		c.Providers[dzp] = &rotating{Fake: c.Providers[dzp].(*fake.Fake), hideID: hide}
	})
}

func TestDNSExecRotatedIDIsStored(t *testing.T) {
	for _, hide := range []bool{false, true} {
		r := rotatingRig(t, hide)
		rec := r.seed(t, "app.example.test", "A", ip1)
		r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
		if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
			t.Fatal(err)
		}
		recs := r.zoneRecords(t)
		if rows := r.rows(t); len(rows) != 1 || rows[0].ProviderRecordID != recs[0].ID || recs[0].ID == rec.ID {
			t.Fatalf("hide=%v rows %+v zone %+v", hide, rows, recs)
		}
		// the next update targets the current ID
		if err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app")); err != nil {
			t.Fatalf("hide=%v: %v", hide, err)
		}
	}
}

func TestDNSExecUndeterminableIDStoredEmptyWithWarning(t *testing.T) {
	r := rotatingRig(t, true)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	r.fk.FailNext("ListRecords", errors.New("unreachable")) // the re-list fails
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].ProviderRecordID != "" || rows[0].Value != ip2 {
		t.Fatalf("rows %+v", rows)
	}
	if m := r.act.messages(); !strings.Contains(m, "warn") || !strings.Contains(m, "id") {
		t.Fatalf("no warning: %q", m)
	}
	// the empty-ID row now takes the replace path (never a blind update)
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if countOps(r.fk, skip, "UpdateRecord") != 0 {
		t.Fatal("blind UpdateRecord")
	}
	if recs := r.zoneRecords(t); len(recs) != 1 || recs[0].Value != ip1 {
		t.Fatalf("zone %+v", recs)
	}
}

func TestDNSExecUpdatePersistFailureNamesNewID(t *testing.T) {
	fs := &failingOwnStore{}
	r := perHostRig(t, func(c *DNSExecutorConfig) {
		fs.OwnershipStore = c.Store
		c.Store = fs
		c.Providers[dzp] = &rotating{Fake: c.Providers[dzp].(*fake.Fake)}
	})
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	fs.addFails = 2
	err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app"))
	if err == nil || !strings.Contains(err.Error(), "app.example.test") || !strings.Contains(err.Error(), "fake-2") {
		t.Fatalf("err %v", err)
	}
	if fs.adds != 2 {
		t.Fatalf("adds %d", fs.adds)
	}
}

// ---- item 4 ----

// In-batch staleness: a record created earlier in the batch blocks a later
// conflicting create (remember), and one deleted earlier frees the name
// (forget).
func TestDNSExecBatchListingTracksOwnWrites(t *testing.T) {
	r := perHostRig(t)
	cname := Action{Kind: DNSEnsure, Zone: dz, Provider: dzp, Owner: "docker:b",
		Record: &dns.Record{Name: "app.example.test", Type: "CNAME", Value: "elsewhere.example.test"}}
	err := r.apply(t, false, ensure("app.example.test", ip1, "docker:a"), cname)
	if !errors.Is(err, ErrForeignRecord) {
		t.Fatalf("want ErrForeignRecord for the CNAME, got %v", err)
	}
	if n := countOps(r.fk, 0, "CreateRecord"); n != 1 {
		t.Fatalf("creates %d", n)
	}

	r2 := perHostRig(t)
	rec := r2.seed(t, "app.example.test", "A", ip1)
	r2.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:a")
	// the first create caches the listing (which still shows app) before the delete
	if err := r2.apply(t, false, ensure("x.example.test", ip1, "docker:x"), del("app.example.test", ip1, rec.ID, "docker:a"),
		ensure("app.example.test", ip2, "docker:b")); err != nil {
		t.Fatal(err)
	}
	if rows := r2.rows(t); len(rows) != 2 || rows[0].OwnerKey != "docker:b" || rows[0].Value != ip2 {
		t.Fatalf("rows %+v", rows)
	}
}

// interloperStore fails AddOwnedRecord once after another owner's row for the
// same name was written (as a concurrent UI adopt would).
type interloperStore struct {
	OwnershipStore
	once sync.Once
}

func (s *interloperStore) AddOwnedRecord(ctx context.Context, r store.DNSRecord) error {
	var err error
	s.once.Do(func() {
		o := r
		o.OwnerKey = "static:app"
		if e := s.OwnershipStore.AddOwnedRecord(ctx, o); e != nil {
			panic(e)
		}
		err = errors.New("disk full")
	})
	if err != nil {
		return err
	}
	return s.OwnershipStore.AddOwnedRecord(ctx, r)
}

func TestDNSExecRollbackLeavesRecordAnotherRowReferences(t *testing.T) {
	is := &interloperStore{}
	r := perHostRig(t, func(c *DNSExecutorConfig) { is.OwnershipStore = c.Store; c.Store = is })
	err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app"))
	if err == nil || !strings.Contains(err.Error(), "left in place") || !strings.Contains(err.Error(), "static:app") {
		t.Fatalf("err %v", err)
	}
	if n := countOps(r.fk, 0, "DeleteRecord"); n != 0 {
		t.Fatal("deleted a record another ownership row references")
	}
	if len(r.zoneRecords(t)) != 1 {
		t.Fatal("record gone")
	}
}

// cancelAfterCreate cancels the Apply context right after a successful
// CreateRecord.
type cancelAfterCreate struct {
	*fake.Fake
	cancel context.CancelFunc
}

func (p *cancelAfterCreate) CreateRecord(ctx context.Context, z string, r dns.Record) (dns.Record, error) {
	got, err := p.Fake.CreateRecord(ctx, z, r)
	p.cancel()
	return got, err
}

func TestDNSExecOwnershipWrittenEvenIfCancelledAfterCreate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := perHostRig(t, func(c *DNSExecutorConfig) {
		c.Providers[dzp] = &cancelAfterCreate{Fake: c.Providers[dzp].(*fake.Fake), cancel: cancel}
	})
	_ = r.exec.Apply(ctx, []Action{ensure("app.example.test", ip1, "docker:app")}, false)
	if rows := r.rows(t); len(rows) != 1 || rows[0].ProviderRecordID != "fake-1" {
		t.Fatalf("ownership not recorded: %+v", rows)
	}
	if len(r.zoneRecords(t)) != 1 {
		t.Fatal("record rolled back")
	}
}

func TestDNSExecOwnerKeyRules(t *testing.T) {
	r := newDNSRig(t, dnsCfg(dnsZoneCfg(dz, "wildcard")))
	for name, a := range map[string]Action{
		"zone prefix other case":        ensure("*.example.test", ip1, "Zone:example.test"),
		"wildcard with service owner":   ensure("*.example.test", ip1, "docker:app"),
		"zone owner on per-host name":   ensure("app.example.test", ip1, WildcardOwnerKey(dz)),
		"upper-case zone owner, delete": del("app.example.test", ip1, "", "ZONE:example.test"),
		"upper-case zone owner, ensure": ensure("app.example.test", ip1, "ZONE:example.test"),
	} {
		if err := r.apply(t, false, a); !errors.Is(err, ErrDNSRefused) {
			t.Fatalf("%s: want ErrDNSRefused, got %v", name, err)
		}
	}
	if len(r.fk.Calls()) != 0 {
		t.Fatal("provider called")
	}
	if err := r.apply(t, false, ensure("*.example.test", ip1, WildcardOwnerKey(dz))); err != nil {
		t.Fatal(err)
	}
}
