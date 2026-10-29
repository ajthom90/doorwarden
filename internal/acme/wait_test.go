package acme

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/reconcile"
)

// An order that outlives its caller's context is tracked: Wait blocks until
// it has stored its result (so the store can be closed safely afterwards),
// and Wait is bounded by its own context.
func TestManagerWaitTracksBackgroundOrders(t *testing.T) {
	cfg := testConfig()
	cfg.ACME.IssueTimeout = 50 * time.Millisecond
	h := newHarness(t, cfg, nil)
	block := make(chan struct{})
	h.ca.block = block
	e := NewCertExecutor(h.m)
	if err := e.Apply(ctx, []reconcile.Action{certEnsure("example.test", "*.example.test", "example.test")}, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.m.Wait(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait with a slow order running: %v", err)
	}
	close(block)
	long, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if err := h.m.Wait(long); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if rows, _ := h.st.ListCerts(ctx); len(rows) != 1 || rows[0].Status != StatusValid {
		t.Fatalf("result not stored before Wait returned: %+v", rows)
	}
}

// Wait with nothing running returns at once.
func TestManagerWaitIdle(t *testing.T) {
	h := newHarness(t, nil, nil)
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.m.Wait(c); err != nil {
		t.Fatal(err)
	}
}
