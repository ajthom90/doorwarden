package acme

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v4/challenge"
)

// With DeferStartupCleanup (dry run), NewManager leaves the certificate
// directory and the issuer switches alone; StartupCleanup runs them later.
func TestDeferStartupCleanup(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	chain, key := h.ca.ca.leaf(t, []string{"*.example.test", "example.test"}, t0)
	if _, err := writeCertVersion(h.dir, b.ID, chain, key); err != nil {
		t.Fatal(err)
	}
	if err := h.st.SetSetting(ctx, overrideKeyPrefix+"gone"+overrideKeySuffix, "production from x"); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(ManagerConfig{Config: h.m.cfg, Store: h.st, Box: h.box, CertsDir: h.dir, Now: h.clock.Now,
		ProviderByName:      func(name string) (challenge.Provider, error) { return fakeDNSProvider{name}, nil },
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		DeferStartupCleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := dirNames(t, filepath.Join(h.dir, b.ID)); got != "v1,v2" {
		t.Fatalf("deferred cleanup touched the certs dir: %s", got)
	}
	if _, ok, _ := h.st.GetSetting(ctx, overrideKeyPrefix+"gone"+overrideKeySuffix); !ok {
		t.Fatal("deferred cleanup cleared the issuer switch")
	}
	m.StartupCleanup(ctx)
	m.StartupCleanup(ctx) // once only; harmless
	if got := dirNames(t, filepath.Join(h.dir, b.ID)); got != "v1" {
		t.Fatalf("after StartupCleanup: %s", got)
	}
	if _, ok, _ := h.st.GetSetting(ctx, overrideKeyPrefix+"gone"+overrideKeySuffix); ok {
		t.Fatal("stale issuer switch kept")
	}
}
