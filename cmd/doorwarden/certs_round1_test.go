package main

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/acme"
	"github.com/ajthom90/doorwarden/internal/traefik"
	"github.com/ajthom90/doorwarden/internal/traefikwire"
)

func treeSum(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			out[p] = sha256.Sum256(b)
		}
		return nil
	})
	return out
}

// Re-running the import after the server adopted the certificate (row
// managed, valid, later expiry) must not replace it: row, path and files
// stay; the run reports the skip and exits 0, and -dry-run says the same.
func TestCertsImportNPMSkipsAdopted(t *testing.T) {
	e := newCertsEnv(t)
	npm1 := filepath.Join(e.npm, "live", "npm-1")
	if c, out, errs := certsRun(t, "-npm-dir", npm1, "-config", e.cfg, "-db", e.db); c != 0 {
		t.Fatalf("first import: %d\n%s\n%s", c, out, errs)
	}
	st := openDB(t, e.db)
	ctx := context.Background()
	rows, _ := st.ListCerts(ctx)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	adopted := rows[0]
	adopted.Managed, adopted.Status, adopted.NotAfter = true, acme.StatusValid, e.wildNotAfter.Add(60*24*time.Hour)
	if err := st.UpsertCert(ctx, adopted); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.ListCerts(ctx)
	adopted = rows[0] // as stored (UTC, no monotonic reading)
	files := treeSum(t, e.certs)

	for _, dry := range []bool{true, false} {
		args := []string{"-npm-dir", npm1, "-config", e.cfg, "-db", e.db}
		if dry {
			args = append(args, "-dry-run")
		}
		c, out, errs := certsRun(t, args...)
		if c != 0 {
			t.Fatalf("dry=%v: exit %d\n%s\n%s", dry, c, out, errs)
		}
		want := "skipped"
		if dry {
			want = "would skip"
		}
		if !strings.Contains(out, want) || !strings.Contains(out, "already adopted") {
			t.Fatalf("dry=%v: no skip reported:\n%s", dry, out)
		}
		after, _ := st.ListCerts(ctx)
		if len(after) != 1 || after[0] != adopted {
			t.Fatalf("dry=%v: row changed: %+v", dry, after)
		}
		now := treeSum(t, e.certs)
		if len(now) != len(files) {
			t.Fatalf("dry=%v: files changed: %d -> %d", dry, len(files), len(now))
		}
		for p, s := range files {
			if now[p] != s {
				t.Fatalf("dry=%v: %s changed", dry, p)
			}
		}
	}
}

// An unset variable anywhere in acme.certs_dir is refused (dry run too)
// unless -certs-dir is given.
func TestCertsImportNPMPartialCertsDirVar(t *testing.T) {
	e := newCertsEnv(t)
	cfg := writeFile(t, "dw.yaml", strings.Replace(certsCfg, `"@CERTS@"`, `"${DATA_ROOT}/certs"`, 1))
	for _, extra := range [][]string{nil, {"-dry-run"}} {
		args := append([]string{"-npm-dir", filepath.Join(e.npm, "live", "npm-1"), "-config", cfg, "-db", e.db}, extra...)
		c, out, errs := certsRun(t, args...)
		if c == 0 || !strings.Contains(errs, "acme.certs_dir references unset variable(s) DATA_ROOT") {
			t.Fatalf("%v: exit %d\n%s\n%s", extra, c, out, errs)
		}
	}
	if c, out, errs := certsRun(t, "-npm-dir", filepath.Join(e.npm, "live", "npm-1"), "-config", cfg, "-db", e.db, "-certs-dir", e.certs); c != 0 {
		t.Fatalf("with -certs-dir: %d\n%s\n%s", c, out, errs)
	}
}

// The dry run writes no key material anywhere: it works with an
// unwritable temp directory and leaves it empty.
func TestCertsImportNPMDryRunNoTempKeys(t *testing.T) {
	e := newCertsEnv(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	if err := os.Chmod(tmp, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmp, 0o700) })
	c, out, errs := certsRun(t, "-npm-dir", filepath.Join(e.npm, "live", "npm-1"), "-config", e.cfg, "-db", e.db, "-dry-run")
	if c != 0 || !strings.Contains(out, "would import") {
		t.Fatalf("exit %d\n%s\n%s", c, out, errs)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("temp dir not empty: %v", ents)
	}
}

// An imported certificate is rendered into Traefik's TLS configuration.
func TestImportedCertRendered(t *testing.T) {
	e := newCertsEnv(t)
	if c, out, errs := certsRun(t, "-npm-dir", filepath.Join(e.npm, "live", "npm-1"), "-config", e.cfg, "-db", e.db); c != 0 {
		t.Fatalf("%d\n%s\n%s", c, out, errs)
	}
	rows, _ := openDB(t, e.db).ListCerts(context.Background())
	cfg, _, err := cliConfig(e.cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	opts, topts := traefikwire.Options(cfg)
	certs, _, probs := traefik.CertsFromRows(rows, topts, time.Now())
	if len(certs) != 1 || certs[0].ID != rows[0].ID {
		t.Fatalf("certs %+v problems %+v", certs, probs)
	}
	files, _, err := traefik.Render(nil, nil, certs, opts)
	if err != nil {
		t.Fatal(err)
	}
	if tls := string(files[traefik.TLSFile]); !strings.Contains(tls, rows[0].Path+"/"+acme.FullchainFile) {
		t.Fatalf("imported certificate not in the TLS file:\n%s", tls)
	}
}
