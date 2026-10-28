package acme

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/reconcile"
)

func certEnsure(zone string, names ...string) reconcile.Action {
	return reconcile.Action{Kind: reconcile.CertEnsure, Zone: zone, Host: names[0], Names: names, Issuer: "le"}
}

func TestExecutorDryRunIssuesNothing(t *testing.T) {
	h := newHarness(t, nil, nil)
	e := NewCertExecutor(h.m)
	if err := e.Apply(ctx, []reconcile.Action{certEnsure("example.test", "*.example.test", "example.test")}, true); err != nil {
		t.Fatal(err)
	}
	if h.ca.count() != 0 {
		t.Fatal("dry run issued")
	}
	if rows, _ := h.st.ListCerts(ctx); len(rows) != 0 {
		t.Fatal("dry run persisted")
	}
	if !contains(h.logs.String(), "dry run") {
		t.Fatal("dry run not logged")
	}
}

func TestExecutorIssuesAndUsesZoneStrategy(t *testing.T) {
	h := newHarness(t, nil, nil)
	e := NewCertExecutor(h.m)
	err := e.Apply(ctx, []reconcile.Action{
		certEnsure("example.test", "*.example.test", "example.test"),
		certEnsure("other.test", "a.other.test", "b.other.test"), // per-host zone
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if h.ca.count() != 3 {
		t.Fatalf("%d orders, want 1 wildcard + 2 per-host", h.ca.count())
	}
}

func TestExecutorErrorsPerActionAndDeferred(t *testing.T) {
	h := newHarness(t, nil, nil)
	e := NewCertExecutor(h.m)
	h.ca.setFail(errTest("dns problem"))
	acts := []reconcile.Action{
		certEnsure("example.test", "*.example.test", "example.test"),
		{Kind: reconcile.DNSEnsure, Zone: "example.test"},
		certEnsure("other.test", "a.other.test"),
	}
	err := e.Apply(ctx, acts, false)
	if err == nil || !contains(err.Error(), "dns problem") || !contains(err.Error(), "cannot apply DNSEnsure") {
		t.Fatalf("%v", err)
	}
	if h.ca.count() != 2 {
		t.Fatalf("one failure stopped the rest: %d orders", h.ca.count())
	}
	// Next cycle: both deferred by backoff, CA untouched.
	err = e.Apply(ctx, acts[:1], false)
	if !errors.Is(err, ErrDeferred) || h.ca.count() != 2 {
		t.Fatalf("%v (%d orders)", err, h.ca.count())
	}
}

func TestExecutorRecoversPanic(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.m.obtain = func(context.Context, order) (obtained, error) { panic("lego exploded") }
	e := NewCertExecutor(h.m)
	err := e.Apply(ctx, []reconcile.Action{certEnsure("example.test", "*.example.test", "example.test")}, false)
	if err == nil || !contains(err.Error(), "lego exploded") {
		t.Fatalf("%v", err)
	}
}

func TestExecutorTimeoutDoesNotBlockLoop(t *testing.T) {
	cfg := testConfig()
	cfg.ACME.IssueTimeout = 50 * time.Millisecond
	h := newHarness(t, cfg, nil)
	block := make(chan struct{})
	h.ca.block = block
	defer close(block)
	e := NewCertExecutor(h.m)
	start := time.Now()
	err := e.Apply(ctx, []reconcile.Action{certEnsure("example.test", "*.example.test", "example.test")}, false)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("blocked")
	}
}

func TestFailureNotifies(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.ca.setFail(errTest("boom"))
	h.m.Issue(ctx, wildcardReq())
	evs := h.evs.list()
	if len(evs) != 1 || evs[0].Kind != EventFailure || !contains(evs[0].Message, "boom") {
		t.Fatalf("%+v", evs)
	}
}
