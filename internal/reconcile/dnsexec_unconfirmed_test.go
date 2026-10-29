package reconcile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
)

// unconfStep is one injected ErrUnconfirmed outcome.
type unconfStep struct {
	apply  bool   // the write really happens (it "landed")
	record bool   // the provider returns the Record that was written
	name   string // overrides the returned Record's Name (a provider bug)
	id     string // overrides the returned Record's ID (a rotated ID)
	value  string // overrides the returned Record's Value (a provider bug)
}

// unconf wraps the fake and makes queued Create/Update/Delete calls return an
// error wrapping dns.ErrUnconfirmed, applying the write or not.
type unconf struct {
	*fake.Fake
	noUpdate bool
	mu       sync.Mutex
	q        map[string][]unconfStep
}

func (u *unconf) next(op string) (unconfStep, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.q[op]) == 0 {
		return unconfStep{}, false
	}
	s := u.q[op][0]
	u.q[op] = u.q[op][1:]
	return s, true
}

func (u *unconf) push(op string, s unconfStep) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.q == nil {
		u.q = map[string][]unconfStep{}
	}
	u.q[op] = append(u.q[op], s)
}

var errUnconf = fmt.Errorf("verify window elapsed: %w", dns.ErrUnconfirmed)

func (u *unconf) Capabilities() dns.Capabilities {
	c := u.Fake.Capabilities()
	c.Update = !u.noUpdate
	return c
}

func (u *unconf) write(op string, r dns.Record, f func() (dns.Record, error)) (dns.Record, error) {
	s, ok := u.next(op)
	if !ok {
		return f()
	}
	got := r
	if s.apply {
		var err error
		if got, err = f(); err != nil {
			return dns.Record{}, err
		}
	} else {
		got.ID = "" // never landed: no ID to report
	}
	if !s.record {
		return dns.Record{}, errUnconf
	}
	if s.name != "" {
		got.Name = s.name
	}
	if s.id != "" {
		got.ID = s.id
	}
	if s.value != "" {
		got.Value = s.value
	}
	return got, errUnconf
}

func (u *unconf) CreateRecord(ctx context.Context, z string, r dns.Record) (dns.Record, error) {
	return u.write("CreateRecord", r, func() (dns.Record, error) { return u.Fake.CreateRecord(ctx, z, r) })
}

func (u *unconf) UpdateRecord(ctx context.Context, z string, r dns.Record) (dns.Record, error) {
	return u.write("UpdateRecord", r, func() (dns.Record, error) { return u.Fake.UpdateRecord(ctx, z, r) })
}

func (u *unconf) DeleteRecord(ctx context.Context, z string, r dns.Record) error {
	_, err := u.write("DeleteRecord", r, func() (dns.Record, error) { return r, u.Fake.DeleteRecord(ctx, z, r) })
	return err
}

func unconfRig(t *testing.T, noUpdate bool) (*dnsRig, *unconf) {
	var u *unconf
	r := perHostRig(t, func(c *DNSExecutorConfig) {
		u = &unconf{Fake: c.Providers[dzp].(*fake.Fake), noUpdate: noUpdate}
		c.Providers[dzp] = u
	})
	return r, u
}

func warned(t *testing.T, r *dnsRig, n int) {
	t.Helper()
	if w := r.exec.LastWarnings(); len(w) != n {
		t.Fatalf("warnings %+v, want %d", w, n)
	}
	if n > 0 && !strings.Contains(r.act.messages(), "warn") || n > 0 && !strings.Contains(r.act.messages(), "unconfirmed") {
		t.Fatalf("no unconfirmed warn activity: %q", r.act.messages())
	}
}

// An unconfirmed create that returns the record is a create: the row is
// written (provider ID as returned, possibly empty), the action succeeds
// and a typed warning plus a warn activity say it is unverified.
func TestDNSExecCreateUnconfirmedWithRecordWritesRow(t *testing.T) {
	for _, landed := range []bool{true, false} {
		t.Run(fmt.Sprintf("landed=%v", landed), func(t *testing.T) {
			r, u := unconfRig(t, false)
			u.push("CreateRecord", unconfStep{apply: landed, record: true})
			if err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app")); err != nil {
				t.Fatalf("unconfirmed create with a record must not fail the action: %v", err)
			}
			rows := r.rows(t)
			if len(rows) != 1 || rows[0].Value != ip1 || rows[0].OwnerKey != "docker:app" || rows[0].Name != "app.example.test" {
				t.Fatalf("rows %+v", rows)
			}
			wantID := ""
			if landed {
				wantID = r.zoneRecords(t)[0].ID
			}
			if rows[0].ProviderRecordID != wantID {
				t.Fatalf("row id %q, want %q", rows[0].ProviderRecordID, wantID)
			}
			warned(t, r, 1)
			if w := r.exec.LastWarnings()[0]; w.Op != "create" || w.Name != "app.example.test" || w.Value != ip1 {
				t.Fatalf("warning %+v", w)
			}
			// the next (clean) batch clears the warnings
			if err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app")); err != nil {
				t.Fatal(err)
			}
			warned(t, r, 0)
		})
	}
}

// Without a returned record (or with a record naming something else) the
// outcome is ambiguous: an error, no row, a loud activity.
func TestDNSExecCreateUnconfirmedWithoutRecordWritesNoRow(t *testing.T) {
	for _, step := range []unconfStep{{apply: true}, {apply: false}, {apply: true, record: true, name: "other.example.test"}} {
		t.Run(fmt.Sprintf("%+v", step), func(t *testing.T) {
			r, u := unconfRig(t, false)
			u.push("CreateRecord", step)
			err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app"))
			if !errors.Is(err, dns.ErrUnconfirmed) {
				t.Fatalf("err %v", err)
			}
			if rows := r.rows(t); len(rows) != 0 {
				t.Fatalf("no row may be written: %+v", rows)
			}
			if m := r.act.messages(); !strings.Contains(m, "error") || !strings.Contains(m, "app.example.test") {
				t.Fatalf("not loud: %q", m)
			}
			if len(r.exec.LastWarnings()) != 0 {
				t.Fatal("an ambiguous failure is an error, not a warning")
			}
		})
	}
}

// An unconfirmed update that returns the record keeps the row's OLD value
// (with the returned provider ID): the next cycle sends the same update
// again, which is idempotent if it landed and completes it if it did not.
func TestDNSExecUpdateUnconfirmed(t *testing.T) {
	for _, landed := range []bool{true, false} {
		t.Run(fmt.Sprintf("landed=%v", landed), func(t *testing.T) {
			r, u := unconfRig(t, false)
			rec := r.seed(t, "app.example.test", "A", ip1)
			r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
			u.push("UpdateRecord", unconfStep{apply: landed, record: true})
			if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
				t.Fatal(err)
			}
			if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip1 || rows[0].ProviderRecordID != rec.ID {
				t.Fatalf("row must keep the old value and the id: %+v", rows)
			}
			warned(t, r, 1)
			skip := len(r.fk.Calls())
			if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(ops(r.fk, skip), ","); got != "UpdateRecord" {
				t.Fatalf("calls %s", got)
			}
			recs, rows := r.zoneRecords(t), r.rows(t)
			if len(recs) != 1 || recs[0].Value != ip2 || len(rows) != 1 || rows[0].Value != ip2 || rows[0].ProviderRecordID != recs[0].ID {
				t.Fatalf("records %+v rows %+v", recs, rows)
			}
		})
	}
}

func TestDNSExecUpdateUnconfirmedWithoutRecordKeepsRow(t *testing.T) {
	r, u := unconfRig(t, false)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	u.push("UpdateRecord", unconfStep{apply: true})
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); !errors.Is(err, dns.ErrUnconfirmed) {
		t.Fatalf("err %v", err)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip1 || rows[0].ProviderRecordID != rec.ID {
		t.Fatalf("rows %+v", rows)
	}
}

// An unconfirmed delete keeps the row and its schedule; the next DNSDelete
// runs again.
func TestDNSExecDeleteUnconfirmedKeepsRow(t *testing.T) {
	for _, landed := range []bool{true, false} {
		t.Run(fmt.Sprintf("landed=%v", landed), func(t *testing.T) {
			r, u := unconfRig(t, false)
			rec := r.seed(t, "app.example.test", "A", ip1)
			r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
			r.due(t, "app.example.test", "docker:app")
			u.push("DeleteRecord", unconfStep{apply: landed})
			err := r.apply(t, false, del("app.example.test", ip1, rec.ID, "docker:app"))
			if !errors.Is(err, dns.ErrUnconfirmed) {
				t.Fatalf("err %v", err)
			}
			rows := r.rows(t)
			if len(rows) != 1 || rows[0].Value != ip1 || rows[0].ProviderRecordID != rec.ID || rows[0].RemovedAfter == nil ||
				!rows[0].RemovedAfter.Equal(dueRA) {
				t.Fatalf("row and schedule must be kept: %+v", rows)
			}
			if err := r.apply(t, false, del("app.example.test", ip1, rec.ID, "docker:app")); err != nil {
				t.Fatal(err)
			}
			if rows, recs := r.rows(t), r.zoneRecords(t); len(rows) != 0 || len(recs) != 0 {
				t.Fatalf("rows %+v records %+v", rows, recs)
			}
		})
	}
}

// Replace path (no Update capability): an unconfirmed create of the new
// value with a record is the replacement; without one nothing is restored
// (the new value may exist) and the row is left for the next cycle.
func TestDNSExecReplaceCreateUnconfirmed(t *testing.T) {
	t.Run("with record", func(t *testing.T) {
		r, u := unconfRig(t, true)
		rec := r.seed(t, "app.example.test", "A", ip1)
		r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
		u.push("CreateRecord", unconfStep{apply: true, record: true})
		if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
			t.Fatal(err)
		}
		recs, rows := r.zoneRecords(t), r.rows(t)
		if len(recs) != 1 || recs[0].Value != ip2 || len(rows) != 1 || rows[0].Value != ip2 || rows[0].ProviderRecordID != recs[0].ID {
			t.Fatalf("records %+v rows %+v", recs, rows)
		}
		warned(t, r, 1)
	})
	t.Run("without record", func(t *testing.T) {
		r, u := unconfRig(t, true)
		rec := r.seed(t, "app.example.test", "A", ip1)
		r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
		u.push("CreateRecord", unconfStep{apply: true})
		skip := len(r.fk.Calls())
		err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app"))
		if !errors.Is(err, dns.ErrUnconfirmed) {
			t.Fatalf("err %v", err)
		}
		if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords,DeleteRecord,CreateRecord" {
			t.Fatalf("no restore after an ambiguous create: %s", got)
		}
		if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip1 || rows[0].ProviderRecordID != rec.ID {
			t.Fatalf("row %+v", rows)
		}
	})
}

// A restore create that is unconfirmed with a record counts as restored.
func TestDNSExecRestoreUnconfirmedCountsAsRestored(t *testing.T) {
	r, u := unconfRig(t, true)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	r.fk.FailNext("CreateRecord", errors.New("rate limited"))     // the new value: a definitive failure
	u.push("CreateRecord", unconfStep{apply: true, record: true}) // passes the fake's failure through
	u.push("CreateRecord", unconfStep{apply: true, record: true}) // the restore: applied, unconfirmed
	err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app"))
	if err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("err %v", err)
	}
	recs, rows := r.zoneRecords(t), r.rows(t)
	if len(recs) != 1 || recs[0].Value != ip1 || len(rows) != 1 || rows[0].Value != ip1 || rows[0].ProviderRecordID != recs[0].ID {
		t.Fatalf("records %+v rows %+v", recs, rows)
	}
	if !strings.Contains(r.act.messages(), "unconfirmed") {
		t.Fatalf("activity %q", r.act.messages())
	}
}

// An unconfirmed create whose row cannot be written is rolled back; a
// rollback delete that is itself unconfirmed says the record may remain and
// never claims it was rolled back.
func TestDNSExecRollbackDeleteUnconfirmed(t *testing.T) {
	fs := &failingOwnStore{addFails: 2}
	var u *unconf
	r := perHostRig(t, func(c *DNSExecutorConfig) {
		u = &unconf{Fake: c.Providers[dzp].(*fake.Fake)}
		c.Providers[dzp] = u
		fs.OwnershipStore = c.Store
		c.Store = fs
	})
	u.push("CreateRecord", unconfStep{apply: true, record: true})
	u.push("DeleteRecord", unconfStep{apply: false})
	err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app"))
	if !errors.Is(err, dns.ErrUnconfirmed) || strings.Contains(err.Error(), "rolled back") || !strings.Contains(err.Error(), "app.example.test") {
		t.Fatalf("err %v", err)
	}
	if !strings.Contains(r.act.messages(), "may still exist") {
		t.Fatalf("activity %q", r.act.messages())
	}
	if len(r.zoneRecords(t)) != 1 {
		t.Fatal("record should still be there (rollback never landed)")
	}
}

// A re-create (UpdateRecord ErrNotFound) whose create is unconfirmed with a
// record keeps the row's CreatedAt and schedule and refreshes value and ID.
func TestDNSExecRecreateUnconfirmedKeepsRowMetadata(t *testing.T) {
	r, u := unconfRig(t, false)
	r.addRow(t, "app.example.test", "A", ip1, "gone-id", "docker:app")
	before := r.rows(t)[0]
	u.push("CreateRecord", unconfStep{apply: false, record: true})
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatal(err)
	}
	rows := r.rows(t)
	if len(rows) != 1 || rows[0].Value != ip2 || rows[0].ProviderRecordID != "" || !rows[0].CreatedAt.Equal(before.CreatedAt) {
		t.Fatalf("rows %+v", rows)
	}
}
