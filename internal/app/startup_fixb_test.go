package app

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/acme"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func runWithUntil(t *testing.T, yml string, until func(log, dir string) bool) (logs, dir, db string) {
	t.Helper()
	return runWithSeed(t, yml, nil, until)
}

// runWithSeed is runWithUntil with seed(db, certsDir) run before start.
func runWithSeed(t *testing.T, yml string, seed func(db, certs string), until func(log, dir string) bool) (logs, dir, db string) {
	t.Helper()
	path, dir, certs := writeConfig(t, yml)
	db = filepath.Join(t.TempDir(), "dw.db")
	if seed != nil {
		seed(db, certs)
	}
	var buf syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunWith(ctx, Flags{Config: path, DB: db}, func(string) (string, bool) { return "", false },
			slog.New(slog.NewTextHandler(&buf, nil)))
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !until(buf.String(), dir) {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("condition not reached; log:\n%s", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunWith did not return")
	}
	return buf.String(), dir, db
}

// Starting with dry_run says so in one line.
func TestStartupLogsDryRun(t *testing.T) {
	logs, _, _ := runWithUntil(t, strings.Replace(testYAML, "settings: {", "settings: {dry_run: true, ", 1),
		func(l, _ string) bool { return strings.Contains(l, "doorwarden started") })
	if !strings.Contains(logs, "DRY RUN") || !strings.Contains(logs, "settings.dry_run is true") || !strings.Contains(logs, "dry_run=true") {
		t.Fatalf("no dry-run line:\n%s", logs)
	}
	logs, _, _ = runWithUntil(t, testYAML, func(l, _ string) bool { return strings.Contains(l, "doorwarden started") })
	if strings.Contains(logs, "DRY RUN") {
		t.Fatalf("dry-run line without dry run:\n%s", logs)
	}
}

// sharedFake backs the test-only "fixbshared" provider type, so a test can
// read the call log of the provider RunWith built.
var (
	sharedMu   sync.Mutex
	sharedFake *fake.Fake
)

type sharedProvider struct{ *fake.Fake }

func (sharedProvider) Type() string { return "fixbshared" }

func init() {
	dns.Register("fixbshared", func(map[string]any, dns.SecretResolver) (dns.Provider, error) {
		sharedMu.Lock()
		defer sharedMu.Unlock()
		return sharedProvider{sharedFake}, nil
	}, dns.ConfigSchema{}, dns.Capabilities{WildcardA: true, MultiZone: true, Update: true, TTL: true})
}

func hasCall(calls []fake.Call, op string) bool {
	for _, c := range calls {
		if c.Op == op {
			return true
		}
	}
	return false
}

// Shutdown deletes nothing: after a live cycle published a route (DNS
// record created), the routes, Traefik's files, the DNS records and the
// certificate rows and files all survive the shutdown, and the provider
// never saw a delete.
func TestShutdownDeletesNothing(t *testing.T) {
	f := fake.New(true)
	sharedMu.Lock()
	sharedFake = f
	sharedMu.Unlock()
	yml := strings.Replace(testYAML, "fk: {type: fake}", "fk: {type: fixbshared}", 1) +
		"static:\n  - {name: web, host: 198.51.100.7, port: 80}\n"
	ctx := context.Background()
	cert := store.Cert{ID: "imported-example_test-0123456789ab", Zone: "example.test", DomainsJSON: `["*.example.test"]`,
		NotAfter: time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second), Status: acme.StatusImported,
		LastResult: "imported", Path: "imported-example_test-0123456789ab/v1"}
	var certFiles map[string][]byte
	seed := func(db, certs string) {
		st, err := store.Open(db)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.UpsertCert(ctx, cert); err != nil {
			t.Fatal(err)
		}
		v := filepath.Join(certs, cert.Path)
		if err := os.MkdirAll(v, 0o700); err != nil {
			t.Fatal(err)
		}
		certFiles = map[string][]byte{
			filepath.Join(v, acme.FullchainFile): []byte("placeholder chain\n"),
			filepath.Join(v, acme.PrivkeyFile):   []byte("placeholder key\n"),
		}
		for p, b := range certFiles {
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, dir, db := runWithSeed(t, yml, seed, func(_, dir string) bool {
		b, err := os.ReadFile(filepath.Join(dir, traefik.RoutesFile))
		return err == nil && strings.Contains(string(b), "web.example.test") && hasCall(f.Calls(), "CreateRecord")
	})
	b, err := os.ReadFile(filepath.Join(dir, traefik.RoutesFile))
	if err != nil || !strings.Contains(string(b), "web.example.test") {
		t.Fatalf("routes file after shutdown: %v", err)
	}
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	routes, err := st.ListRoutes(ctx)
	if err != nil || len(routes) != 1 {
		t.Fatalf("routes after shutdown: %+v %v", routes, err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Op, "Delete") {
			t.Fatalf("provider saw %s %s %+v", c.Op, c.Zone, c.Record)
		}
	}
	recs, err := f.ListRecords(ctx, "example.test")
	if err != nil || len(recs) == 0 {
		t.Fatalf("DNS records after shutdown: %+v %v", recs, err)
	}
	certs, err := st.ListCerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range certs {
		if c.ID == cert.ID {
			found = c.Path == cert.Path
		}
	}
	if !found {
		t.Fatalf("certificate row after shutdown: %+v", certs)
	}
	for p, want := range certFiles {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("certificate file %s after shutdown: %v", p, err)
		}
	}
}
