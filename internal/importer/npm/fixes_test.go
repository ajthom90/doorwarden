package npm

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/model"
)

func listing(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		fi, _ := e.Info()
		out = append(out, fmt.Sprintf("%s %d %d", e.Name(), fi.Size(), fi.ModTime().UnixNano()))
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// walDB creates a WAL-mode database whose newest row lives only in the -wal
// file (the writer connection stays open so SQLite does not checkpoint).
func walDB(t *testing.T) (string, func()) {
	t.Helper()
	path := newDB(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	for _, s := range []string{
		`PRAGMA journal_mode=WAL`, `PRAGMA wal_autocheckpoint=0`,
		`INSERT INTO proxy_host VALUES(9,'["walrow.example.test"]','http','192.0.2.50',80,0,0,0,1,'',1,0,'{}')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + "-wal"); err != nil {
		t.Fatalf("no wal file: %v", err)
	}
	return path, func() { db.Close() }
}

func TestDefaultCopyReadsWALAndLeavesDirUntouched(t *testing.T) {
	path, closeW := walDB(t)
	defer closeW()
	dir := filepath.Dir(path)
	before := listing(t, dir)
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	found := false
	for _, h := range snap.ProxyHosts {
		found = found || h.ID == 9
	}
	if !found {
		t.Fatal("row that only lives in the WAL was not read")
	}
	if after := listing(t, dir); after != before {
		t.Fatalf("original directory changed:\n%s\n--- after ---\n%s", before, after)
	}
}

func TestNoCopyRefusedWithSidecarsOrReadOnlyDir(t *testing.T) {
	path, closeW := walDB(t)
	defer closeW()
	if _, err := Open(path, Options{NoCopy: true}); err == nil || !strings.Contains(err.Error(), "refusing --no-copy") {
		t.Fatalf("want refusal with WAL sidecars, got %v", err)
	}
	// Default still works on a read-only directory.
	plain := newDB(t)
	dir := filepath.Dir(plain)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if os.Geteuid() != 0 {
		if _, err := Open(plain, Options{NoCopy: true}); err == nil {
			t.Fatal("--no-copy must be refused on a read-only directory")
		}
	}
	r, err := Open(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Read(context.Background()); err != nil {
		t.Fatalf("default copy on read-only dir: %v", err)
	}
}

func TestCopyCleanedUpOnClose(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	r, err := Open(newDB(t))
	if err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(tmp)
	if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), TempPrefix) {
		t.Fatalf("temp dir: %v", ents)
	}
	if fi, _ := os.Stat(filepath.Join(tmp, ents[0].Name())); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode())
	}
	r.Close()
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("temp dir left behind: %v", ents)
	}
}

func TestYAMLSkipsAccessListDisabledAndCustomConfig(t *testing.T) {
	snap := &Snapshot{ProxyHosts: []ProxyHost{
		{ID: 1, Domains: []string{"acl.example.test"}, Scheme: "http", Host: "192.0.2.5", Port: 80, AccessListID: 3, SSLForced: true, Enabled: true},
		{ID: 2, Domains: []string{"off.example.test"}, Scheme: "http", Host: "192.0.2.5", Port: 80, SSLForced: true, Enabled: false},
		{ID: 3, Domains: []string{"adv.example.test"}, Scheme: "http", Host: "192.0.2.10", Port: 30001, AdvancedConfigLen: 40, SSLForced: true, Enabled: true},
	}}
	ms := Plan(snap, discovered(), testCfg())
	for _, m := range ms {
		if m.SuggestedStatic != nil || m.Skipped == "" {
			t.Errorf("%s: suggestion %v skipped %q", m.Domain, m.SuggestedStatic, m.Skipped)
		}
	}
	adv := byDomain(ms)["adv.example.test"]
	if adv.Class != ClassStatic || adv.MatchedService != "" {
		t.Fatalf("custom config host must be static, unmatched: %+v", adv)
	}
	var y bytes.Buffer
	if err := RenderYAML(&y, ms); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSpace(y.String()), "\n") {
		if !strings.HasPrefix(l, "#") {
			t.Errorf("non-comment line in YAML for skipped hosts: %q", l)
		}
	}
	for _, w := range []string{"# SKIPPED acl.example.test: NPM access list attached", "# SKIPPED off.example.test: disabled in NPM", "# SKIPPED adv.example.test"} {
		if !strings.Contains(y.String(), w) {
			t.Errorf("missing %q in\n%s", w, y.String())
		}
	}
}

func TestMatchedServiceOnlyForKnownKeys(t *testing.T) {
	snap := &Snapshot{ProxyHosts: []ProxyHost{{ID: 1, Domains: []string{"x.example.test"}, Scheme: "http", Host: "192.0.2.7", Port: 80, SSLForced: true, Enabled: true}}}
	d := []model.Service{{Key: "other:thing", Name: "t", Backend: model.Backend{Host: "192.0.2.7", Port: 80}}}
	if m := Plan(snap, d, testCfg())[0]; m.MatchedService != "" || m.Class != ClassStatic {
		t.Fatalf("%+v", m)
	}
}

func TestOutputSanitised(t *testing.T) {
	evil := "evil.example.test\n  - id: pwned\x1b[31m #\t"
	snap := &Snapshot{
		ProxyHosts:   []ProxyHost{{ID: 1, Domains: []string{evil}, Scheme: "http", Host: "192.0.2.5", Port: 80, AccessListID: 1, SSLForced: true, Enabled: true}},
		Certificates: []Certificate{{ID: 1, NiceName: "n\x1b]0;x\x07", Domains: []string{"*.example.test\n"}, IsWildcard: true}},
	}
	ms := Plan(snap, nil, testCfg())
	var tbl, y bytes.Buffer
	Render(&tbl, ms)
	if err := RenderYAML(&y, ms); err != nil {
		t.Fatal(err)
	}
	all := tbl.String() + y.String() + CertGuidance(snap)
	if strings.ContainsAny(all, "\x1b\x07 \t\x00") {
		t.Fatalf("control chars leaked: %q", all)
	}
	for _, l := range strings.Split(strings.TrimSpace(y.String()), "\n") {
		if !strings.HasPrefix(l, "#") {
			t.Fatalf("escaped the comment: %q", l)
		}
	}
	// table: header + one row only (newline in domain must not add rows)
	if n := strings.Count(strings.TrimSpace(tbl.String()), "\n"); n != 1 {
		t.Fatalf("table has %d extra lines: %q", n, tbl.String())
	}
}
