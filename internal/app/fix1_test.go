package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
)

// An unset truenas approval is "approve": discovered apps stay pending and
// nothing is published.
func TestTrueNASUnsetApprovalPublishesNothing(t *testing.T) {
	e := newEnv(t, testYAML+`
sources:
  truenas: {url: "https://192.0.2.20", api_key: k}
`)
	specs := BuildSources(e.cfg, &SecretStore{KV: e.st})
	var mode approval.Mode
	for _, sp := range specs {
		if sp.name() == "truenas" {
			mode = sp.Mode
			if sp.Source != nil {
				if c, ok := sp.Source.(interface{ Close() error }); ok {
					_ = c.Close()
				}
			}
		}
	}
	if mode != approval.ModeApprove {
		t.Fatalf("truenas mode = %q", mode)
	}
	src := &fakeSource{name: "truenas"}
	src.set(nil, svc("truenas", "plex"))
	a := e.app(func(o *Options) { o.Sources = []SourceSpec{{Source: src, Mode: mode}} })
	ctx := context.Background()
	if res := a.RunOnce(ctx); res.Err != nil {
		t.Fatal(res.Err)
	}
	for _, s := range a.Services() {
		if s.State != model.StatePending {
			t.Fatalf("service not pending: %+v", s)
		}
	}
	if routes, _ := e.st.ListRoutes(ctx); len(routes) != 0 {
		t.Fatalf("published: %+v", routes)
	}
	if w := writes(e.fk); len(w) != 0 {
		t.Fatalf("dns writes: %+v", w)
	}
	if b, err := os.ReadFile(filepath.Join(e.dir, traefik.RoutesFile)); err == nil && strings.Contains(string(b), "plex") {
		t.Fatalf("plex in Traefik routes:\n%s", b)
	}
}

// Live cycles never clobber the services table's overrides or scheduled
// removal.
func TestCyclesKeepServiceOverrides(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"))
	a := e.app()
	ctx := context.Background()
	a.RunOnce(ctx)
	got, _ := e.st.ListServices(ctx)
	if len(got) != 1 {
		t.Fatalf("services = %+v", got)
	}
	v := got[0]
	v.OverridesJSON = `{"rename":"web"}`
	ra := v.LastSeen.Add(72 * time.Hour)
	v.RemovedAfter = &ra
	if err := e.st.UpsertService(ctx, v); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	a.RunOnce(ctx)
	got, _ = e.st.ListServices(ctx)
	if got[0].OverridesJSON != `{"rename":"web"}` || got[0].RemovedAfter == nil {
		t.Fatalf("overrides clobbered: %+v", got[0])
	}
}

// The next-expiry re-render is computed from the cert rows every cycle
// (dry run included) and the cert timer is never armed below
// MinCertRearm, so a dry run or a failing write cannot spin the loop.
func TestCertTimerNeverSpins(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	clock := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	if err := e.st.UpsertCert(ctx, store.Cert{ID: "c1", Zone: "example.test", DomainsJSON: `["*.example.test"]`,
		Issuer: "imported", Status: "imported", NotAfter: clock.Add(time.Second), Path: "c1/v1"}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var armed []time.Duration
	a := e.app(func(o *Options) { o.Now = func() time.Time { return clock } })
	a.onCertArm = func(d time.Duration) { mu.Lock(); armed = append(armed, d); mu.Unlock() }
	if err := a.SetDryRun(ctx, true); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	if !a.nextCert.Equal(clock.Add(time.Second)) {
		t.Fatalf("dry cycle next cert = %v", a.nextCert)
	}

	rctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- a.Run(rctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(armed)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(armed) == 0 {
		t.Fatal("cert timer never armed")
	}
	for _, d := range armed {
		if d < MinCertRearm {
			t.Fatalf("cert timer armed for %v (< %v)", d, MinCertRearm)
		}
	}
	if c := e.src.calls.Load(); c > 2 {
		t.Fatalf("%d cycles in 200ms", c)
	}

	if got := certDelay(clock.Add(3*time.Hour), clock); got != 3*time.Hour+time.Second {
		t.Fatalf("certDelay = %v", got)
	}
	if got := certDelay(clock.Add(-time.Hour), clock); got != MinCertRearm {
		t.Fatalf("certDelay past = %v", got)
	}
}
