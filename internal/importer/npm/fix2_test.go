package npm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// seams replaces the copy/sleep seams for one test.
func seams(t *testing.T, cp func(src, dst string, optional bool) error) *[]time.Duration {
	t.Helper()
	oc, os_ := copyFileFn, sleepFn
	var sleeps []time.Duration
	copyFileFn = cp
	sleepFn = func(d time.Duration) { sleeps = append(sleeps, d) }
	t.Cleanup(func() { copyFileFn, sleepFn = oc, os_ })
	return &sleeps
}

func emptyTmp(t *testing.T) string {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	return tmp
}

func assertNoTemp(t *testing.T, tmp string) {
	t.Helper()
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("temp dirs left behind: %v", ents)
	}
}

func TestSnapshotRetriesWhenSourceChangesDuringCopy(t *testing.T) {
	path := newDB(t)
	tmp := emptyTmp(t)
	calls := 0 // main-file copies = attempts
	sleeps := seams(t, func(src, dst string, optional bool) error {
		err := copyFile(src, dst, optional)
		if src == path {
			calls++
			if calls < 3 { // source "checkpoints" mid-copy on attempts 1 and 2
				f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				f.Write([]byte{0})
				f.Close()
				os.Truncate(path, mustSize(t, path)-1)
				os.Chtimes(path, time.Now(), time.Now().Add(time.Duration(calls)*time.Second))
			}
		}
		return err
	})
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || len(*sleeps) != 2 {
		t.Fatalf("attempts=%d sleeps=%v", calls, *sleeps)
	}
	if _, err := r.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Close()
	assertNoTemp(t, tmp)
}

func mustSize(t *testing.T, p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func TestSnapshotGivesUpAfterThreeAttempts(t *testing.T) {
	path := newDB(t)
	tmp := emptyTmp(t)
	n := 0
	seams(t, func(src, dst string, optional bool) error {
		err := copyFile(src, dst, optional)
		if src == path {
			n++
			os.Chtimes(path, time.Now(), time.Now().Add(time.Duration(n)*time.Minute))
		}
		return err
	})
	_, err := Open(path)
	if err == nil || !strings.Contains(err.Error(), "kept changing or is corrupt") || n != 3 {
		t.Fatalf("attempts=%d err=%v", n, err)
	}
	assertNoTemp(t, tmp)
}

func TestSnapshotCorruptCopyRetried(t *testing.T) {
	path := newDB(t)
	tmp := emptyTmp(t)
	n := 0
	seams(t, func(src, dst string, optional bool) error {
		err := copyFile(src, dst, optional)
		if src == path {
			n++
			if n == 1 { // garble the copy only
				b, _ := os.ReadFile(dst)
				for i := 100; i < len(b); i++ {
					b[i] = 0xAB
				}
				os.WriteFile(dst, b, 0o600)
			}
		}
		return err
	})
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if n != 2 {
		t.Fatalf("attempts=%d, want 2", n)
	}
	_ = tmp
}

func TestSnapshotCancelledMidCopyRemovesTempDir(t *testing.T) {
	path := newDB(t)
	tmp := emptyTmp(t)
	ctx, cancel := context.WithCancel(context.Background())
	seams(t, func(src, dst string, optional bool) error {
		err := copyFile(src, dst, optional)
		cancel() // interrupt after the first file is written
		return err
	})
	if _, err := Open(path, Options{Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancellation error, got %v", err)
	}
	assertNoTemp(t, tmp)
}

func R(rs ...rune) string { return string(rs) }

func TestCleanStripsBidiAndZeroWidth(t *testing.T) {
	evil := "a" + R(0x202e) + "b" + R(0x200b) + "c" + R(0x200d, 0xfeff) + "d" + R(0x2066) + "e" + R(0x2069) + "f" + R(0xad) + "g" + R(0x2028) + "h"
	got := clean(evil)
	if got != "a?b?c??d?e?f?g?h" {
		t.Fatalf("clean = %q", got)
	}
	bad := R(0x202e, 0x200b)
	snap := &Snapshot{ProxyHosts: []ProxyHost{{ID: 1, Domains: []string{"evil" + R(0x202e) + "gnp.example.test" + R(0x200b)}, Scheme: "http", Host: "192.0.2.5", Port: 80, AccessListID: 1, SSLForced: true, Enabled: true}}}
	ms := Plan(snap, nil, testCfg())
	var tbl, y bytes.Buffer
	Render(&tbl, ms)
	_ = RenderYAML(&y, ms)
	for _, o := range []string{tbl.String(), y.String()} {
		if strings.ContainsAny(o, bad) {
			t.Fatalf("format chars leaked: %q", o)
		}
	}
	if !strings.Contains(y.String(), "# SKIPPED evil?gnp.example.test?:") {
		t.Fatalf("%q", y.String())
	}
}
