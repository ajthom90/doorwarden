package acme

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// keyBody returns the base64 body of a PEM key (what a leak would show).
func keyBody(key []byte) string {
	lines := strings.Split(strings.TrimSpace(string(key)), "\n")
	return strings.Join(lines[1:len(lines)-1], "")
}

func TestImportPEM(t *testing.T) {
	h := newHarness(t, nil, nil)
	chain, key := h.ca.ca.leaf(t, []string{"*.example.test", "example.test"}, t0.Add(60*24*time.Hour))
	ir, err := h.m.ImportPEM(ctx, "Example.Test.", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	if ir.Expired || ir.Bundle.Managed || !strings.HasPrefix(ir.Bundle.ID, "imported-") {
		t.Fatalf("%+v", ir)
	}
	r := h.row(t, ir.Bundle.ID)
	if r.DomainsJSON != `["*.example.test","example.test"]` || !r.NotAfter.Equal(t0.Add(60*24*time.Hour)) || r.Path != ir.Bundle.ID || r.Zone != "example.test" {
		t.Fatalf("row %+v", r)
	}
	st, _ := os.Stat(filepath.Join(h.dir, ir.Bundle.ID, PrivkeyFile))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	// Idempotent.
	ir2, err := h.m.ImportPEM(ctx, "example.test", chain, key)
	if err != nil || ir2.Bundle.ID != ir.Bundle.ID {
		t.Fatal(ir2, err)
	}
}

func TestImportRejectsMismatchedKey(t *testing.T) {
	h := newHarness(t, nil, nil)
	chain, _ := h.ca.ca.leaf(t, []string{"a.example.test"}, t0.Add(60*24*time.Hour))
	_, otherKey := h.ca.ca.leaf(t, []string{"b.example.test"}, t0.Add(60*24*time.Hour))
	_, err := h.m.ImportPEM(ctx, "example.test", chain, otherKey)
	if err == nil || !contains(err.Error(), "does not match") {
		t.Fatalf("want mismatch error, got %v", err)
	}
	if contains(err.Error(), keyBody(otherKey)[:40]) || contains(err.Error(), "PRIVATE KEY") {
		t.Fatal("key material in error")
	}
	rows, _ := h.st.ListCerts(ctx)
	if len(rows) != 0 {
		t.Fatal("row stored for rejected import")
	}
	if ents, _ := os.ReadDir(h.dir); len(ents) != 0 {
		t.Fatal("files written for rejected import")
	}
}

func TestImportRejectsOutOfZoneAndGarbage(t *testing.T) {
	h := newHarness(t, nil, nil)
	chain, key := h.ca.ca.leaf(t, []string{"a.example.org"}, t0.Add(60*24*time.Hour))
	if _, err := h.m.ImportPEM(ctx, "example.test", chain, key); err == nil || !contains(err.Error(), "outside zone") {
		t.Fatalf("%v", err)
	}
	if _, err := h.m.ImportPEM(ctx, "example.test", []byte("garbage"), key); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := h.m.ImportPEM(ctx, "nozone.test", chain, key); err == nil {
		t.Fatal("unknown zone accepted")
	}
}

func TestImportExpiredAllowedButFlagged(t *testing.T) {
	h := newHarness(t, nil, nil)
	chain, key := h.ca.ca.leaf(t, []string{"old.example.test"}, t0.Add(-24*time.Hour))
	ir, err := h.m.ImportPEM(ctx, "example.test", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	if !ir.Expired {
		t.Fatal("not flagged expired")
	}
	if r := h.row(t, ir.Bundle.ID); !contains(r.LastError, "expired") {
		t.Fatalf("row %+v", r)
	}
}

func TestImportNPMDir(t *testing.T) {
	h := newHarness(t, nil, nil)
	live := filepath.Join(t.TempDir(), "live")
	write := func(dir string, names []string) {
		chain, key := h.ca.ca.leaf(t, names, t0.Add(50*24*time.Hour))
		os.MkdirAll(filepath.Join(live, dir), 0o755)
		os.WriteFile(filepath.Join(live, dir, FullchainFile), chain, 0o644)
		os.WriteFile(filepath.Join(live, dir, PrivkeyFile), key, 0o600)
	}
	write("npm-1", []string{"*.example.test", "example.test"})
	write("npm-2", []string{"app.other.test"})
	write("npm-3", []string{"app.elsewhere.test"})
	os.MkdirAll(filepath.Join(live, "README"), 0o755)
	res, err := h.m.ImportNPMDir(ctx, live)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("%d results", len(res))
	}
	if res[0].Err != nil || res[0].Bundle.Zone != "example.test" || res[1].Err != nil || res[1].Bundle.Zone != "other.test" {
		t.Fatalf("%+v %+v", res[0], res[1])
	}
	if res[2].Err == nil || !contains(res[2].Err.Error(), "no configured zone") {
		t.Fatalf("npm-3: %v", res[2].Err)
	}
	// A single npm-N directory works too.
	one, err := h.m.ImportNPMDir(ctx, filepath.Join(live, "npm-2"))
	if err != nil || len(one) != 1 || one[0].Err != nil {
		t.Fatal(one, err)
	}
	rows, _ := h.st.ListCerts(ctx)
	for _, r := range rows {
		if r.Managed {
			t.Fatalf("imported row managed: %+v", r)
		}
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows", len(rows))
	}
}

func TestBundleRedactsKey(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	body := keyBody([]byte(b.Key.Reveal()))
	if len(body) < 40 {
		t.Fatal("no key")
	}
	js, _ := json.Marshal(b)
	jsv, _ := json.Marshal(*b)
	var sb strings.Builder
	slog.New(slog.NewJSONHandler(&sb, nil)).Info("x", "bundle", b, "value", *b)
	outs := []string{
		b.String(), fmtS("%v", b), fmtS("%+v", b), fmtS("%#v", b), fmtS("%s", b),
		fmtS("%v", *b), fmtS("%+v", *b), fmtS("%#v", *b), string(js), string(jsv), sb.String(),
	}
	for i, o := range outs {
		if contains(o, body[:40]) || contains(o, "PRIVATE KEY") {
			t.Errorf("output %d leaks the key: %s", i, o)
		}
	}
}

// Logs and errors produced while issuing, failing, renewing and importing
// never contain key material.
func TestNoKeyMaterialInLogsOrErrors(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{keyBody([]byte(b.Key.Reveal()))}
	var errs []string
	h.ca.setFail(errTest("validation failed"))
	h.clock.Add(70 * 24 * time.Hour)
	for _, r := range h.m.Renew(ctx) {
		if r.Err != nil {
			errs = append(errs, r.Err.Error())
		}
	}
	chain, key := h.ca.ca.leaf(t, []string{"imp.example.test"}, t0.Add(100*24*time.Hour))
	keys = append(keys, keyBody(key))
	if _, err := h.m.ImportPEM(ctx, "example.test", chain, key); err != nil {
		t.Fatal(err)
	}
	_, other := h.ca.ca.leaf(t, []string{"x.example.test"}, t0)
	keys = append(keys, keyBody(other))
	if _, err := h.m.ImportPEM(ctx, "example.test", chain, other); err != nil {
		errs = append(errs, err.Error())
	}
	// A write failure (certs dir is a file) must not echo the key either.
	h.ca.setFail(nil)
	os.RemoveAll(h.dir)
	os.WriteFile(h.dir, []byte("x"), 0o600)
	h.clock.Add(time.Hour)
	if r := h.m.RenewNow(ctx, b.ID); r.Err != nil {
		errs = append(errs, r.Err.Error())
	} else {
		t.Fatal("write into a file succeeded")
	}
	h.ca.mu.Lock()
	keys = append(keys, keyBody(h.ca.lastKey))
	h.ca.mu.Unlock()
	all := h.logs.String() + strings.Join(errs, "\n")
	for _, ev := range h.evs.list() {
		all += fmtS("%+v", ev)
	}
	if len(errs) < 3 {
		t.Fatalf("expected errors, got %v", errs)
	}
	for _, k := range keys {
		if contains(all, k[:40]) {
			t.Fatalf("key material leaked:\n%s", all)
		}
	}
	if contains(all, "PRIVATE KEY") {
		t.Fatal("PEM key header leaked")
	}
}
