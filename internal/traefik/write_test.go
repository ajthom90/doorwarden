package traefik

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var past = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func ageAll(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if err := os.Chtimes(filepath.Join(dir, e.Name()), past, past); err != nil {
			t.Fatal(err)
		}
	}
}

func mtime(t *testing.T, p string) time.Time {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

func files(routes, tls string) Files {
	return Files{RoutesFile: []byte(Header + routes), TLSFile: []byte(Header + tls)}
}

func TestWriteCreatesAndSkipsIdentical(t *testing.T) {
	dir := t.TempDir()
	f := files("http: {}\n", "tls: {}\n")
	if err := Write(dir, f); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, RoutesFile)); got != string(f[RoutesFile]) {
		t.Fatalf("content %q", got)
	}
	fi, _ := os.Stat(filepath.Join(dir, RoutesFile))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v (middleware secrets: want 0600)", fi.Mode())
	}
	ageAll(t, dir)
	if err := Write(dir, f); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{RoutesFile, TLSFile} {
		if m := mtime(t, filepath.Join(dir, n)); !m.Equal(past) {
			t.Fatalf("%s rewritten (mtime %v)", n, m)
		}
	}
	// a change rewrites only the changed file
	f2 := files("http: {}\n", "tls:\n  certificates: []\n")
	if err := Write(dir, f2); err != nil {
		t.Fatal(err)
	}
	if !mtime(t, filepath.Join(dir, RoutesFile)).Equal(past) {
		t.Fatal("unchanged routes file rewritten")
	}
	if got := readFile(t, filepath.Join(dir, TLSFile)); got != string(f2[TLSFile]) {
		t.Fatalf("tls not updated: %q", got)
	}
	assertNoTemps(t, dir)
}

func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

func TestWriteCleanupScope(t *testing.T) {
	dir := t.TempDir()
	keep := map[string]string{
		"other.yml":                  "http: {}\n",
		"doorwarden-foreign.yml":     "# hand written\nhttp: {}\n", // no marker
		"my-doorwarden-x.yml":        Header + "http: {}\n",        // wrong prefix
		"doorwarden-notes.txt":       Header + "x\n",               // not a yml
		"doorwarden-marker-late.yml": "http: {}\n" + Header,        // marker not first
	}
	for n, c := range keep {
		writeFile(t, filepath.Join(dir, n), c)
	}
	stale := filepath.Join(dir, "doorwarden-old.yml")
	writeFile(t, stale, Header+"http: {}\n")
	staleYAML := filepath.Join(dir, "doorwarden-old2.yaml")
	writeFile(t, staleYAML, Header+"http: {}\n")
	if err := os.Mkdir(filepath.Join(dir, "doorwarden-dir.yml"), 0o755); err != nil {
		t.Fatal(err)
	}
	// a symlink named like ours, pointing at a marked file outside dir: neither
	// the link target nor anything outside dir may be touched
	outside := filepath.Join(t.TempDir(), "doorwarden-outside.yml")
	writeFile(t, outside, Header+"http: {}\n")
	link := filepath.Join(dir, "doorwarden-link.yml")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	ageAll(t, dir)

	if err := Write(dir, files("http: {}\n", "tls: {}\n")); err != nil {
		t.Fatal(err)
	}
	for n, c := range keep {
		p := filepath.Join(dir, n)
		if got := readFile(t, p); got != c || !mtime(t, p).Equal(past) {
			t.Fatalf("%s touched", n)
		}
	}
	for _, p := range []string{stale, staleYAML} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("stale %s not removed: %v", p, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, "doorwarden-dir.yml")); err != nil || !fi.IsDir() {
		t.Fatal("directory touched")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink removed: %v", err)
	}
	if got := readFile(t, outside); got != Header+"http: {}\n" {
		t.Fatal("outside file touched")
	}
}

func TestWriteReplacesSymlinkNotTarget(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "target.yml")
	writeFile(t, outside, "precious\n")
	if err := os.Symlink(outside, filepath.Join(dir, RoutesFile)); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, files("http: {}\n", "tls: {}\n")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, outside); got != "precious\n" {
		t.Fatalf("symlink target written: %q", got)
	}
	fi, err := os.Lstat(filepath.Join(dir, RoutesFile))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("routes file not a regular file: %v %v", fi, err)
	}
}

func TestWriteRejectsBadNamesAndContent(t *testing.T) {
	bad := []string{"../doorwarden-x.yml", "doorwarden-a/b.yml", "doorwarden-../../x.yml", "x.yml",
		"doorwarden-.yml", "doorwarden-X.yml", "doorwarden-x.yaml", "/abs/doorwarden-x.yml", "doorwarden-x.yml/"}
	for _, n := range bad {
		dir := t.TempDir()
		if err := Write(dir, Files{n: []byte(Header + "http: {}\n")}); err == nil {
			t.Fatalf("%q accepted", n)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Fatalf("%q: wrote %v", n, ents)
		}
	}
	dir := t.TempDir()
	if err := Write(dir, Files{RoutesFile: []byte("http: {}\n")}); err == nil {
		t.Fatal("content without marker accepted")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("wrote %v", ents)
	}
	if err := Write(filepath.Join(dir, "missing"), files("http: {}\n", "tls: {}\n")); err == nil {
		t.Fatal("missing dir accepted")
	}
}

// An existing non-regular entry at a target name (a directory) is an error,
// not something to delete.
func TestWriteTargetIsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, RoutesFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, files("http: {}\n", "tls: {}\n")); err == nil {
		t.Fatal("expected error")
	}
	if fi, err := os.Stat(filepath.Join(dir, RoutesFile)); err != nil || !fi.IsDir() {
		t.Fatal("directory replaced")
	}
	assertNoTemps(t, dir)
}

// Final-review M4: rendered files may hold middleware secrets (basic-auth
// hashes, forward-auth headers): 0600 by default, 0640 when configured; a
// pre-existing file with other permissions is corrected even when its
// content is unchanged (mtime kept); other modes are refused.
func TestWriteModeAndPermissionCorrection(t *testing.T) {
	dir := t.TempDir()
	f := files("http: {}\n", "tls: {}\n")
	p := filepath.Join(dir, RoutesFile)
	if err := os.WriteFile(p, f[RoutesFile], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	ageAll(t, dir)
	if err := Write(dir, f); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("pre-existing mode not corrected: %v", fi.Mode())
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("not a regular file: %v", fi.Mode())
	}
	if err := WriteMode(dir, f, 0o640); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{RoutesFile, TLSFile} {
		if fi, _ := os.Stat(filepath.Join(dir, n)); fi.Mode().Perm() != 0o640 {
			t.Fatalf("%s mode %v, want 0640", n, fi.Mode())
		}
	}
	if err := WriteMode(dir, f, 0o644); err == nil {
		t.Fatal("0644 accepted")
	}
}

// A symlink at the target pointing outside dir, with identical content and a
// different mode: the outside file's permissions and content are untouched
// (no chmod by path), the link is replaced by a regular 0600 file.
func TestWriteNeverChmodsThroughSymlink(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	f := files("http: {}\n", "tls: {}\n")
	ext := filepath.Join(outside, "victim.yml")
	if err := os.WriteFile(ext, f[RoutesFile], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ext, 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, RoutesFile)
	if err := os.Symlink(ext, p); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, f); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(ext); fi.Mode().Perm() != 0o644 {
		t.Fatalf("outside file chmodded to %v", fi.Mode())
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("target = %v, %v", fi, err)
	}
}

// The target swapped for a symlink to an outside file between the Lstat and
// the read (a race) is never followed: the outside file keeps its mode and
// the target ends up a regular 0600 file.
func TestWriteTargetSwappedAfterLstat(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	f := files("http: {}\n", "tls: {}\n")
	ext := filepath.Join(outside, "victim.yml")
	if err := os.WriteFile(ext, f[RoutesFile], 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(ext, 0o644)
	p := filepath.Join(dir, RoutesFile)
	if err := os.WriteFile(p, f[RoutesFile], 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0o644)
	afterLstat = func(target string) {
		if target == p {
			os.Remove(p)
			os.Symlink(ext, p)
		}
	}
	t.Cleanup(func() { afterLstat = func(string) {} })
	_ = Write(dir, f) // an error is fine; following the link is not
	if fi, _ := os.Stat(ext); fi.Mode().Perm() != 0o644 {
		t.Fatalf("outside file chmodded to %v", fi.Mode())
	}
	afterLstat = func(string) {}
	if err := Write(dir, f); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("target = %v, %v", fi, err)
	}
}
