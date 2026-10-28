package acme

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/ajthom90/doorwarden/internal/config"
)

func (h *harness) orders(t *testing.T, issuer string) []orderEvent {
	t.Helper()
	var evs []orderEvent
	if _, err := h.m.kv.getJSON(ctx, ordersKey(issuer), &evs); err != nil {
		t.Fatal(err)
	}
	return evs
}

func (h *harness) attempt(t *testing.T, id string) attemptState {
	t.Helper()
	var a attemptState
	if _, err := h.m.kv.getJSON(ctx, attemptKey(id), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

// The attempt is persisted before the order is placed: if the process dies
// mid-order, the next process sees a failure with backoff and a pending
// order that counts toward the order guards.
func TestAttemptStartPersistedBeforeOrder(t *testing.T) {
	h := newHarness(t, nil, nil)
	id := certID("example.test", []string{"*.example.test", "example.test"})
	block := make(chan struct{})
	h.ca.block = block
	t.Cleanup(func() {
		h.ca.setFail(errors.New("abandoned"))
		close(block)
		// Wait for the abandoned order to release the process-wide slot.
		select {
		case issueSem <- struct{}{}:
			<-issueSem
		case <-time.After(5 * time.Second):
			t.Error("abandoned order kept the issue slot")
		}
	})
	cctx, cancel := context.WithCancel(ctx)
	go func() { _, _ = h.m.Issue(cctx, wildcardReq()) }()
	for h.ca.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	// While the order is blocked: attempt and pending order already stored.
	a := h.attempt(t, id)
	if a.Failures != 1 || !a.NextAttempt.After(h.clock.Now()) {
		t.Fatalf("attempt not recorded before the order: %+v", a)
	}
	evs := h.orders(t, "le")
	if len(evs) != 1 || evs[0].OK || !evs[0].Pending || evs[0].Set != id {
		t.Fatalf("pending order not recorded: %+v", evs)
	}
	// "Restart": a new manager over the same store defers the set.
	m2 := h.reopen(t)
	n := h.ca.count()
	if _, err := m2.Issue(ctx, wildcardReq()); !errors.Is(err, ErrDeferred) || h.ca.count() != n {
		t.Fatalf("restarted manager did not defer: %v", err)
	}
}

// Success flips the pending order to OK and resets the attempt; a normal
// failure keeps the start record without counting the failure twice.
func TestAttemptStartResolvedOnce(t *testing.T) {
	h := newHarness(t, nil, nil)
	id := certID("example.test", []string{"*.example.test", "example.test"})
	if _, err := h.m.Issue(ctx, wildcardReq()); err != nil {
		t.Fatal(err)
	}
	if evs := h.orders(t, "le"); len(evs) != 1 || !evs[0].OK || evs[0].Pending {
		t.Fatalf("%+v", evs)
	}
	if a := h.attempt(t, id); a.Failures != 0 || !a.NextAttempt.IsZero() {
		t.Fatalf("not reset: %+v", a)
	}
	h.ca.setFail(errors.New("boom"))
	h.clock.Add(time.Hour)
	res := h.m.RenewNow(ctx, id)
	if res.Err == nil {
		t.Fatal("want failure")
	}
	a := h.attempt(t, id)
	if a.Failures != 1 || !a.NextAttempt.Equal(h.clock.Now().Add(backoffDelay(1, 0))) {
		t.Fatalf("failure counted wrong: %+v", a)
	}
	evs := h.orders(t, "le")
	if len(evs) != 2 || evs[1].OK || evs[1].Pending {
		t.Fatalf("%+v", evs)
	}
}

// Pending (possibly issued) orders count toward the duplicate guard.
func TestPendingOrdersCountAsDuplicates(t *testing.T) {
	h := newHarness(t, nil, nil)
	id := certID("example.test", []string{"*.example.test", "example.test"})
	now := h.clock.Now().Unix()
	var evs []orderEvent
	for i := range maxDuplicateOrders {
		evs = append(evs, orderEvent{T: now - int64(i), Set: id, Pending: true})
	}
	if err := h.m.kv.putJSON(ctx, ordersKey("le"), evs); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Issue(ctx, wildcardReq()); !errors.Is(err, ErrDeferred) || !strings.Contains(err.Error(), "exact name set") {
		t.Fatalf("%v", err)
	}
}

// A rate-limit park is recorded for the issuer account too: other sets of
// the same issuer are deferred without contacting the CA.
func TestRateLimitParksAccount(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.ca.setFail(&legoacme.RateLimitedError{RetryAfter: "600", ProblemDetails: &legoacme.ProblemDetails{Type: legoacme.RateLimitedErr, HTTPStatus: 429}})
	if _, err := h.m.Issue(ctx, wildcardReq()); err == nil {
		t.Fatal("want failure")
	}
	h.ca.setFail(nil)
	n := h.ca.count()
	res := h.m.IssueAll(ctx, IssueRequest{Zone: "other.test", Names: []string{"a.other.test"}})
	if !errors.Is(res[0].Err, ErrDeferred) || h.ca.count() != n || !strings.Contains(res[0].Err.Error(), "account") {
		t.Fatalf("sibling not parked: %v", res[0].Err)
	}
	h.clock.Add(11 * time.Minute)
	if res := h.m.IssueAll(ctx, IssueRequest{Zone: "other.test", Names: []string{"a.other.test"}}); res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
}

// The notifier is never called while the process-wide issue slot is held.
func TestNotifierCalledAfterSlotReleased(t *testing.T) {
	var held atomic.Int32
	var calls atomic.Int32
	h := newHarness(t, nil, func(mc *ManagerConfig) {
		mc.Notifier = NotifierFunc(func(context.Context, Event) {
			calls.Add(1)
			select {
			case issueSem <- struct{}{}:
				<-issueSem
			default:
				held.Add(1)
			}
		})
	})
	h.ca.setFail(errors.New("boom"))
	if _, err := h.m.Issue(ctx, wildcardReq()); err == nil {
		t.Fatal("want failure")
	}
	if calls.Load() != 1 || held.Load() != 0 {
		t.Fatalf("calls=%d while held=%d", calls.Load(), held.Load())
	}
}

// Ids that cannot be stored are refused before any order.
func TestOverlongIDRefusedBeforeOrder(t *testing.T) {
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".test"
	cfg := testConfig()
	cfg.Zones = append(cfg.Zones, cfgZone(long))
	h := newHarness(t, cfg, nil)
	_, err := h.m.Issue(ctx, IssueRequest{Zone: long})
	if err == nil || !strings.Contains(err.Error(), "id") || h.ca.count() != 0 {
		t.Fatalf("%v (orders %d)", err, h.ca.count())
	}
}

func cfgZone(name string) config.Zone {
	return config.Zone{Name: name, TargetIP: "192.0.2.10",
		Certificate: config.Certificate{Issuer: "le", Strategy: "wildcard", Challenge: "dns-01", DNSProvider: "cf"}}
}
