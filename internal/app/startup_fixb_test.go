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
	path, dir, _ := writeConfig(t, yml)
	db = filepath.Join(t.TempDir(), "dw.db")
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

// Shutdown deletes nothing: after a live cycle published a route, the
// routes and Traefik's files survive the shutdown.
func TestShutdownDeletesNothing(t *testing.T) {
	yml := testYAML + "static:\n  - {name: web, host: 198.51.100.7, port: 80}\n"
	_, dir, db := runWithUntil(t, yml, func(_, dir string) bool {
		b, err := os.ReadFile(filepath.Join(dir, traefik.RoutesFile))
		return err == nil && strings.Contains(string(b), "web.example.test")
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
	routes, err := st.ListRoutes(context.Background())
	if err != nil || len(routes) != 1 {
		t.Fatalf("routes after shutdown: %+v %v", routes, err)
	}
}
