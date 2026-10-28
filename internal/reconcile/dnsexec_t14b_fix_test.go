package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
)

// dueDeleteFailStore fails DeleteOwnedRecordIfDue the first fails times.
type dueDeleteFailStore struct {
	OwnershipStore
	fails int
}

func (s *dueDeleteFailStore) DeleteOwnedRecordIfDue(ctx context.Context, provider, zone, name, typ, owner string, notAfter time.Time) (bool, error) {
	if s.fails > 0 {
		s.fails--
		return false, errors.New("database is locked")
	}
	return s.OwnershipStore.DeleteOwnedRecordIfDue(ctx, provider, zone, name, typ, owner, notAfter)
}

// A store error between the provider delete and the row delete blanks the
// row (like a row that changed meanwhile): the record is gone, so the row
// must not keep claiming its value and provider ID. The next due DNSDelete
// then forgets the row without any provider call, and an owner that returns
// instead re-creates the record through the guarded create.
func TestDNSExecDeleteStoreErrorBlanksRow(t *testing.T) {
	for _, ownerReturns := range []bool{false, true} {
		t.Run(map[bool]string{false: "row forgotten", true: "owner returns"}[ownerReturns], func(t *testing.T) {
			fs := &dueDeleteFailStore{fails: 1}
			r := perHostRig(t, func(c *DNSExecutorConfig) { fs.OwnershipStore = c.Store; c.Store = fs })
			rec := r.seed(t, "app.example.test", "A", ip1)
			r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
			r.due(t, "app.example.test", "docker:app")
			err := r.apply(t, false, del("app.example.test", ip1, rec.ID, "docker:app"))
			if err == nil || !strings.Contains(err.Error(), "could not forget") {
				t.Fatalf("err %v", err)
			}
			rows := r.rows(t)
			if len(rows) != 1 || rows[0].Value != "" || rows[0].ProviderRecordID != "" || rows[0].RemovedAfter == nil {
				t.Fatalf("row not blanked (schedule kept): %+v", rows)
			}
			if len(r.zoneRecords(t)) != 0 {
				t.Fatal("record not deleted")
			}
			if !strings.Contains(r.act.messages(), "error") {
				t.Fatalf("not loud: %q", r.act.messages())
			}
			skip := len(r.fk.Calls())
			if ownerReturns {
				if err := r.apply(t, false, Action{Kind: DNSCancelRemoval, Zone: dz, Host: "app.example.test", Key: "docker:app",
					Provider: dzp, Owner: "docker:app", Record: &dns.Record{Name: "app.example.test", Type: "A"}}); err != nil {
					t.Fatal(err)
				}
				if err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app")); err != nil {
					t.Fatal(err)
				}
				rows, recs := r.rows(t), r.zoneRecords(t)
				if len(rows) != 1 || rows[0].Value != ip1 || len(recs) != 1 || recs[0].ID != rows[0].ProviderRecordID {
					t.Fatalf("not re-created: rows %+v records %+v", rows, recs)
				}
				return
			}
			// the next cycle's DNSDelete carries the blank stored row
			a := del("app.example.test", "", "", "docker:app")
			if err := r.apply(t, false, a); err != nil {
				t.Fatal(err)
			}
			if got := ops(r.fk, skip); len(got) != 0 {
				t.Fatalf("a blank row must not reach the provider: %v", got)
			}
			if rows := r.rows(t); len(rows) != 0 {
				t.Fatalf("blank row not forgotten: %+v", rows)
			}
		})
	}
}
