package acme

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// abandonOrder starts a wildcard order that blocks in the CA, cancels the
// caller once the order is placed and leaves the order running (as a crash
// mid-order would leave its state). Cleanup lets it finish as a failure.
func abandonOrder(t *testing.T, h *harness) {
	t.Helper()
	block := make(chan struct{})
	h.ca.block = block
	t.Cleanup(func() {
		h.ca.setFail(errors.New("abandoned"))
		close(block)
		select {
		case issueSem <- struct{}{}:
			<-issueSem
		case <-time.After(5 * time.Second):
		}
	})
	cctx, cancel := context.WithCancel(ctx)
	go func() { _, _ = h.m.Issue(cctx, wildcardReq()) }()
	for h.ca.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
}

// N1: a crash during a first issuance (no row yet) leaves an attempt record
// with a future NextAttempt; the next process's Renew must not prune it.
func TestPruneKeepsCrashRecordOfFirstIssuance(t *testing.T) {
	h := newHarness(t, nil, nil)
	abandonOrder(t, h)
	m2 := h.reopen(t)
	_ = m2.Renew(ctx)
	id := certID("example.test", []string{"*.example.test", "example.test"})
	if derr := m2.guard(ctx, "le", id, []string{"*.example.test", "example.test"}, false); derr == nil {
		t.Errorf("crash record erased by pruneState; guard allows immediate re-order")
	}
}

// N1: an expired attempt record with no row is kept while its issuer still
// has a pending order event for the set, and pruned once neither holds.
func TestPruneKeepsAttemptWithPendingOrder(t *testing.T) {
	h := newHarness(t, nil, nil)
	id := "example-test-gone"
	now := h.clock.Now()
	if err := h.m.kv.putJSON(ctx, attemptKey(id), attemptState{Failures: 1, NextAttempt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := h.m.kv.putJSON(ctx, ordersKey("le"), []orderEvent{{T: now.Add(-2 * time.Hour).Unix(), Set: id, Pending: true}}); err != nil {
		t.Fatal(err)
	}
	h.m.Renew(ctx)
	if ok, _ := h.m.kv.getJSON(ctx, attemptKey(id), &attemptState{}); !ok {
		t.Fatal("attempt record with a pending order event pruned")
	}
	if err := h.m.kv.putJSON(ctx, ordersKey("le"), []orderEvent{{T: now.Add(-2 * time.Hour).Unix(), Set: id}}); err != nil {
		t.Fatal(err)
	}
	h.m.Renew(ctx)
	if ok, _ := h.m.kv.getJSON(ctx, attemptKey(id), &attemptState{}); ok {
		t.Fatal("expired attempt record without row or pending order kept")
	}
	// A record still backing off is kept.
	if err := h.m.kv.putJSON(ctx, attemptKey(id), attemptState{Failures: 1, NextAttempt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	h.m.Renew(ctx)
	if ok, _ := h.m.kv.getJSON(ctx, attemptKey(id), &attemptState{}); !ok {
		t.Fatal("attempt record still backing off pruned")
	}
	// A parked record is kept while parked.
	if err := h.m.kv.putJSON(ctx, attemptKey(id), attemptState{Failures: 1, ParkedUntil: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	h.m.Renew(ctx)
	if ok, _ := h.m.kv.getJSON(ctx, attemptKey(id), &attemptState{}); !ok {
		t.Fatal("parked attempt record pruned")
	}
}

// N2: backoff runs from the failure, not from the order start: a failure
// slower than its backoff step still defers the next attempt.
func TestBackoffMeasuredFromFailure(t *testing.T) {
	h := newHarness(t, nil, nil)
	block := make(chan struct{})
	h.ca.block = block
	h.ca.setFail(errors.New("propagation timeout"))
	done := make(chan error, 1)
	go func() { _, err := h.m.Issue(ctx, wildcardReq()); done <- err }()
	for h.ca.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	h.clock.Add(3 * time.Minute)
	close(block)
	<-done
	h.ca.mu.Lock()
	h.ca.block = nil
	h.ca.mu.Unlock()
	if _, err := h.m.Issue(ctx, wildcardReq()); !errors.Is(err, ErrDeferred) {
		t.Errorf("immediately retried after a failure: %v", err)
	}
	a := h.attempt(t, certID("example.test", []string{"*.example.test", "example.test"}))
	if want := h.clock.Now().Add(backoffDelay(1, 0)); a.Failures != 1 || !a.NextAttempt.Equal(want) {
		t.Errorf("attempt %+v, want 1 failure and next attempt %v", a, want)
	}
}

// failingSets wraps the store with SetSetting failing.
type failingSets struct {
	settingsBackend
	err error
}

func (f failingSets) SetSetting(context.Context, string, string) error { return f.err }

// N3: when the attempt record cannot be persisted the CA is never
// contacted, the result is deferred, and this process does not retry at
// once even though nothing was stored.
func TestUnwritableStateStoreNeverContactsCA(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.m.kv = kvStore{failingSets{settingsBackend: h.st, err: errors.New("disk full at /var/lib/x token=sekrit-value-1")}}
	h.m.red.add("sekrit-value-1")
	_, err := h.m.Issue(ctx, wildcardReq())
	if !errors.Is(err, ErrDeferred) || !strings.Contains(err.Error(), "state store unwritable") {
		t.Fatalf("want deferred (state store unwritable), got %v", err)
	}
	// errors.As hands out the *DeferredError itself: its Reason must
	// already be redacted.
	var de *DeferredError
	if !errors.As(err, &de) || strings.Contains(de.Reason+de.LastError, "sekrit-value-1") || strings.Contains(err.Error(), "sekrit-value-1") {
		t.Fatalf("store error not redacted: %v / %+v", err, de)
	}
	if h.ca.count() != 0 {
		t.Fatalf("CA contacted %d times with an unwritable store", h.ca.count())
	}
	_, err = h.m.Issue(ctx, wildcardReq())
	if !errors.Is(err, ErrDeferred) || h.ca.count() != 0 {
		t.Fatalf("second attempt: %v (orders %d)", err, h.ca.count())
	}
	// Even once the store is writable again, the in-memory backoff holds
	// (nothing was stored to defer on).
	h.m.kv = kvStore{h.st}
	if _, err := h.m.Issue(ctx, wildcardReq()); !errors.Is(err, ErrDeferred) || h.ca.count() != 0 {
		t.Fatalf("in-memory backoff not applied: %v (orders %d)", err, h.ca.count())
	}
	// The in-memory backoff also covers a failure whose record could not be
	// stored after a real order.
	h.clock.Add(time.Hour)
	h.m.kv = kvStore{h.st}
	h.ca.setFail(errors.New("boom"))
	ok := false
	h.m.kv = kvStore{&failAfterAttempt{settingsBackend: h.st, okKey: attemptKey(certID("example.test", []string{"*.example.test", "example.test"})), first: &ok}}
	// The order takes longer than the 1m backoff step, so the stored start
	// record has expired by the time it fails.
	h.m.obtain = func(c context.Context, o order) (obtained, error) {
		h.clock.Add(3 * time.Minute)
		return h.ca.obtain(c, o)
	}
	if _, err := h.m.Issue(ctx, wildcardReq()); err == nil || errors.Is(err, ErrDeferred) {
		t.Fatalf("want a real failure, got %v", err)
	}
	n := h.ca.count()
	h.m.kv = kvStore{h.st} // writable again: only the in-memory backoff defers
	if _, err := h.m.Issue(ctx, wildcardReq()); !errors.Is(err, ErrDeferred) || h.ca.count() != n {
		t.Fatalf("retried at once after a failure that could not be persisted: %v", err)
	}
}

// failAfterAttempt lets exactly one write of okKey through (the attempt
// start) and fails every later write.
type failAfterAttempt struct {
	settingsBackend
	okKey string
	first *bool
}

func (f *failAfterAttempt) SetSetting(ctx context.Context, k, v string) error {
	if k == f.okKey && !*f.first {
		*f.first = true
		return f.settingsBackend.SetSetting(ctx, k, v)
	}
	if strings.HasPrefix(k, "acme/orders/") {
		return f.settingsBackend.SetSetting(ctx, k, v)
	}
	return errors.New("read-only database")
}

// A stale pending order event (a crash) for a set is resolved by the next
// order of that set.
func TestStalePendingResolvedByNextOrder(t *testing.T) {
	h := newHarness(t, nil, nil)
	id := certID("example.test", []string{"*.example.test", "example.test"})
	if err := h.m.kv.putJSON(ctx, ordersKey("le"), []orderEvent{{T: h.clock.Now().Add(-time.Hour).Unix(), Set: id, Pending: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Issue(ctx, wildcardReq()); err != nil {
		t.Fatal(err)
	}
	for _, e := range h.orders(t, "le") {
		if e.Pending {
			t.Fatalf("pending event left after a successful order: %+v", h.orders(t, "le"))
		}
		if !e.OK {
			t.Fatalf("an earlier possibly-issued order must keep counting: %+v", h.orders(t, "le"))
		}
	}
}

type failingGets struct {
	settingsBackend
	err error
}

func (f failingGets) GetSetting(context.Context, string) (string, bool, error) {
	return "", false, f.err
}

// A DeferredError built from a store error carries redacted text (errors.As
// hands it out as is).
func TestDeferredReasonFromStoreErrorRedacted(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.m.red.add("sekrit-value-2")
	h.m.kv = kvStore{failingGets{settingsBackend: h.st, err: errors.New("cannot read: password=sekrit-value-2")}}
	_, err := h.m.Issue(ctx, wildcardReq())
	var de *DeferredError
	if !errors.As(err, &de) || !strings.Contains(de.Reason, "state unreadable") {
		t.Fatalf("want deferred (state unreadable): %v", err)
	}
	if strings.Contains(de.Reason, "sekrit-value-2") {
		t.Fatalf("reason not redacted: %q", de.Reason)
	}
}

// A backward clock jump (or a corrupt record) cannot defer a set for longer
// than the caps: the backoff cap without a park, the longest park with one.
func TestGuardClampsFarFutureState(t *testing.T) {
	h := newHarness(t, nil, nil)
	id := certID("example.test", []string{"*.example.test", "example.test"})
	names := []string{"*.example.test", "example.test"}
	now := h.clock.Now()
	must(t, h.m.kv.putJSON(ctx, attemptKey(id), attemptState{Failures: 3, NextAttempt: now.Add(400 * 24 * time.Hour)}))
	if d := h.m.guard(ctx, "le", id, names, false); d == nil || d.Until.After(now.Add(backoffCap)) {
		t.Fatalf("backoff not clamped: %+v", d)
	}
	// The clamped value is stored, so the wait ends at the cap.
	h.clock.Add(backoffCap + time.Minute)
	if d := h.m.guard(ctx, "le", id, names, false); d != nil {
		t.Fatalf("backoff clamp not persisted: %+v", d)
	}
	now = h.clock.Now()
	must(t, h.m.kv.putJSON(ctx, attemptKey(id), attemptState{Failures: 3, NextAttempt: now.Add(400 * 24 * time.Hour), ParkedUntil: now.Add(400 * 24 * time.Hour)}))
	if d := h.m.guard(ctx, "le", id, names, false); d == nil || d.Until.After(now.Add(maxRateLimitPark)) {
		t.Fatalf("park not clamped: %+v", d)
	}
	must(t, h.m.kv.putJSON(ctx, attemptKey(id), attemptState{}))
	must(t, h.m.kv.putJSON(ctx, accountParkKey("le"), now.Add(400*24*time.Hour)))
	if d := h.m.guard(ctx, "le", id, names, false); d == nil || d.Until.After(now.Add(maxRateLimitPark)) {
		t.Fatalf("account park not clamped: %+v", d)
	}
	h.clock.Add(maxRateLimitPark + time.Minute)
	if d := h.m.guard(ctx, "le", id, names, false); d != nil {
		t.Fatalf("still deferred after the cap: %+v", d)
	}
}

// An order aborted because the state store is unwritable is reported to
// the notifier.
func TestUnwritableStoreNotifies(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.m.kv = kvStore{failingSets{settingsBackend: h.st, err: errors.New("disk full")}}
	if _, err := h.m.Issue(ctx, wildcardReq()); !errors.Is(err, ErrDeferred) {
		t.Fatal(err)
	}
	evs := h.evs.list()
	if len(evs) != 1 || evs[0].Kind != EventFailure || !strings.Contains(evs[0].Message, "state store unwritable") || evs[0].NextAttempt.IsZero() {
		t.Fatalf("events %+v", evs)
	}
}
