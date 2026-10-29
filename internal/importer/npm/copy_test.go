package npm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func budget() *int64 { b := int64(1 << 30); return &b }

// A symlink (even one pointing to /dev/zero) is refused, not followed.
func TestCopyFileRefusesSymlinkToDevZero(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "database.sqlite")
	if err := os.Symlink("/dev/zero", src); err != nil {
		t.Fatal(err)
	}
	err := copyFile(context.Background(), src, filepath.Join(dir, "out"), false, budget())
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); err == nil {
		t.Fatal("destination created")
	}
}

// An optional sidecar that is a symlink is refused too (not skipped).
func TestCopyFileRefusesOptionalSymlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "database.sqlite-wal")
	if err := os.Symlink("/dev/zero", src); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(context.Background(), src, filepath.Join(dir, "out"), true, budget()); err == nil {
		t.Fatal("optional symlink accepted")
	}
}

// A FIFO is refused promptly (no blocking open/read).
func TestCopyFileRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "database.sqlite-wal")
	if err := syscall.Mkfifo(src, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- copyFile(context.Background(), src, filepath.Join(dir, "out"), true, budget()) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("copy of a FIFO hung")
	}
}

// Per-file and aggregate byte limits.
func TestCopyFileByteLimits(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "db")
	if err := os.WriteFile(src, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	old := maxFileBytes
	maxFileBytes = 1024
	err := copyFile(context.Background(), src, filepath.Join(dir, "a"), false, budget())
	maxFileBytes = old
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("per-file limit: %v", err)
	}
	b := int64(2048)
	if err := copyFile(context.Background(), src, filepath.Join(dir, "b"), false, &b); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("aggregate limit: %v", err)
	}
	b = 10000
	if err := copyFile(context.Background(), src, filepath.Join(dir, "c"), false, &b); err != nil || b != 10000-4096 {
		t.Fatalf("within limits: %v, budget %d", err, b)
	}
}

// The aggregate limit applies across the database and its sidecars, and an
// oversized snapshot leaves no temp directory behind.
func TestSnapshotAggregateLimit(t *testing.T) {
	path := newDB(t)
	tmp := emptyTmp(t)
	old := maxSnapshotBytes
	maxSnapshotBytes = mustSize(t, path) - 1
	t.Cleanup(func() { maxSnapshotBytes = old })
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v", err)
	}
	assertNoTemp(t, tmp)
}

// A cancelled context stops the copy.
func TestCopyFileCancelled(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "db")
	if err := os.WriteFile(src, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyFile(ctx, src, filepath.Join(dir, "out"), false, budget()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
