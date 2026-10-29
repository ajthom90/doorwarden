package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/reconcile"
)

// In dry run, certificate renewal, the production switch and adopting a DNS
// conflict are refused with 409 and a clear message, and nothing is done.
func TestDryRunRefusesSideEffects(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	ctx := context.Background()
	if err := e.st.UpsertCert(ctx, storeCert("example.test")); err != nil {
		t.Fatal(err)
	}
	e.addService("docker/app")
	e.ctl.plan = Plan{At: e.now, Actions: []reconcile.Action{conflictAction("A")}}
	e.ctl.dry = true

	for _, tc := range []struct {
		label, method, path string
		body                any
	}{
		{"renew", "POST", "/api/v1/certs/example.test/renew", nil},
		{"switch", "POST", "/api/v1/certs/switch-production", map[string]any{"issuer": "le", "confirm": true}},
		{"adopt", "POST", "/api/v1/dns/conflicts/" + ConflictID(conflictAction("A")) + "/adopt", nil},
	} {
		w := c.do(tc.method, tc.path, tc.body)
		if w.Code != http.StatusConflict || !strings.Contains(strings.ToLower(w.Body.String()), "dry run") {
			t.Fatalf("%s: %d %s", tc.label, w.Code, w.Body)
		}
	}
	time.Sleep(50 * time.Millisecond)
	e.ctl.mu.Lock()
	renewed, switched := len(e.ctl.renewed), len(e.ctl.switched)
	e.ctl.mu.Unlock()
	if renewed != 0 || switched != 0 {
		t.Fatalf("renewed %d switched %d in dry run", renewed, switched)
	}
	if rows, _ := e.st.ListAllOwnedRecords(ctx); len(rows) != 0 {
		t.Fatalf("ownership row written in dry run: %+v", rows)
	}
	// skipping a conflict only hides it, so it stays allowed
	if w := c.do("POST", "/api/v1/dns/conflicts/"+ConflictID(conflictAction("A"))+"/skip", nil); w.Code != 200 {
		t.Fatalf("skip: %d", w.Code)
	}
}

// Server.Close waits for a running async job (a renewal) before returning,
// so the caller can drain ACME and close the store afterwards; it is safe
// to call twice.
func TestServerCloseWaitsForAsyncJobs(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	if err := e.st.UpsertCert(context.Background(), storeCert("example.test")); err != nil {
		t.Fatal(err)
	}
	e.ctl.renewWait = make(chan struct{})
	if w := c.do("POST", "/api/v1/certs/example.test/renew", nil); w.Code != http.StatusAccepted {
		t.Fatalf("renew: %d %s", w.Code, w.Body)
	}
	done := make(chan struct{})
	go func() { e.srv.Close(); close(done) }()
	select {
	case <-done:
		t.Fatal("Close returned while a renewal was running")
	case <-time.After(100 * time.Millisecond):
	}
	close(e.ctl.renewWait)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	e.srv.Close()
}
