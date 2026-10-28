package acme

import (
	"crypto/tls"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/challenge"
)

// reopen builds a second Manager over h's store and certs dir, as after a
// process restart.
func (h *harness) reopen(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(ManagerConfig{Config: h.m.cfg, Store: h.st, Box: h.box, CertsDir: h.dir, Now: h.clock.Now,
		Jitter:         func() float64 { return 0 },
		ProviderByName: func(name string) (challenge.Provider, error) { return fakeDNSProvider{name}, nil },
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	m.obtain = h.ca.obtain
	return m
}

func dirNames(t *testing.T, dir string) string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var ns []string
	for _, e := range ents {
		ns = append(ns, e.Name())
	}
	return strings.Join(ns, ",")
}

// A crash after a new version's files were written but before the row was
// updated leaves an unrecorded version: the row keeps pointing at the old
// one, and the next start removes the orphan (and staging leftovers, and
// directories of ids without a row) but keeps every recorded version.
func TestCrashBetweenFilesAndRowIsCleanedUp(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Add(70 * 24 * 3600e9)
	if r := h.m.RenewNow(ctx, b.ID); r.Err != nil {
		t.Fatal(r.Err)
	}
	// "Crash": v3 written, row never updated; a staging dir left over; an
	// id directory whose first issuance never got a row.
	chain, key := h.ca.ca.leaf(t, []string{"*.example.test", "example.test"}, t0)
	if p, err := writeCertVersion(h.dir, b.ID, chain, key); err != nil || p != b.ID+"/v3" {
		t.Fatal(p, err)
	}
	if err := os.Mkdir(filepath.Join(h.dir, b.ID, ".tmp-v-123"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := writeCertVersion(h.dir, "example_test-000000000000", chain, key); err != nil {
		t.Fatal(err)
	}
	if h.row(t, b.ID).Path != b.ID+"/v2" {
		t.Fatal("row moved")
	}
	h.reopen(t)
	if got := dirNames(t, filepath.Join(h.dir, b.ID)); got != "v1,v2" {
		t.Fatalf("after restart: %s", got)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "example_test-000000000000")); !os.IsNotExist(err) {
		t.Fatalf("row-less id dir kept: %v", err)
	}
	// The next issuance takes v3 again and prunes v1.
	h.clock.Add(70 * 24 * 3600e9)
	if r := h.m.RenewNow(ctx, b.ID); r.Err != nil {
		t.Fatal(r.Err)
	}
	if got := dirNames(t, filepath.Join(h.dir, b.ID)); got != "v2,v3" || h.row(t, b.ID).Path != b.ID+"/v3" {
		t.Fatalf("after renewal: %s %s", got, h.row(t, b.ID).Path)
	}
}

// Every published version holds a matching pair: the row's Path and the
// kept previous version both load as a key pair after each renewal.
func TestNoMixedCertificatePair(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		h.clock.Add(70 * 24 * 3600e9)
		if r := h.m.RenewNow(ctx, b.ID); r.Err != nil {
			t.Fatal(r.Err)
		}
		for _, v := range certVersions(h.dir, b.ID) {
			vd := filepath.Join(h.dir, b.ID, "v"+itoa(v))
			if _, err := tls.LoadX509KeyPair(filepath.Join(vd, FullchainFile), filepath.Join(vd, PrivkeyFile)); err != nil {
				t.Fatalf("v%d: %v", v, err)
			}
		}
	}
}

// A failed write publishes nothing: no version directory and no staging
// leftovers.
func TestFailedVersionWritePublishesNothing(t *testing.T) {
	root := t.TempDir()
	if _, err := writeCertVersion(root, "x", []byte("c"), nil); err == nil {
		t.Fatal("empty key accepted")
	}
	if _, err := writeCertVersion(root, "../x", []byte("c"), []byte("k")); err == nil {
		t.Fatal("bad id accepted")
	}
	if err := os.MkdirAll(filepath.Join(root, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	// v1 exists as a file: the rename onto it fails.
	if err := os.WriteFile(filepath.Join(root, "x", "v1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeCertVersion(root, "x", []byte("c"), []byte("k")); err == nil {
		t.Fatal("publish over a file succeeded")
	}
	if got := dirNames(t, filepath.Join(root, "x")); got != "v1" {
		t.Fatalf("leftovers: %s", got)
	}
}

func itoa(n int) string { return fmtS("%d", n) }
