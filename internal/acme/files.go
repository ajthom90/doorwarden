package acme

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// File names below certs/<id>/v<N>/.
const (
	FullchainFile = "fullchain.pem"
	PrivkeyFile   = "privkey.pem"
)

const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

// ensureDir creates dir (and parents) and forces mode 0700 on dir itself,
// whatever the umask or an earlier mode.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	return os.Chmod(dir, dirMode)
}

// writeTemp writes data to a new 0600 temp file next to path and fsyncs it.
func writeTemp(path string, data []byte) (tmp string, err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return "", err
	}
	tmp = f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(fileMode); err != nil {
		f.Close()
		return "", err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	return tmp, f.Close()
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// Certificate files are versioned: each issuance or import writes a new
// directory certs/<id>/v<N>/ holding fullchain.pem and privkey.pem, and the
// store row's Path points at "<id>/v<N>". Traefik's file provider reloads
// certificates only when its dynamic configuration file changes, not when a
// referenced PEM file is rewritten in place; a new path changes the dynamic
// file, so every renewal is picked up. The previous version is kept (Traefik
// may still be serving it until it reloads); older versions are removed
// after the next successful write. Version directories that are newer than
// the version recorded in the store (a crash between writing the files and
// updating the row) are removed at startup (cleanupCertDirs).

const versionPrefix = "v"

// certVersions lists the v<N> versions present under root/<id>, ascending.
func certVersions(root, id string) []int {
	ents, err := os.ReadDir(filepath.Join(root, id))
	if err != nil {
		return nil
	}
	var vs []int
	for _, e := range ents {
		if n, ok := parseVersion(e.Name()); ok && e.IsDir() {
			vs = append(vs, n)
		}
	}
	sort.Ints(vs)
	return vs
}

func parseVersion(name string) (int, bool) {
	d, ok := strings.CutPrefix(name, versionPrefix)
	if !ok || d == "" || len(d) > 9 || d[0] == '0' {
		return 0, false
	}
	n := 0
	for _, c := range d {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// versionPath is the row Path of version n of id.
func versionPath(id string, n int) string { return id + "/" + versionPrefix + strconv.Itoa(n) }

// pathVersion parses a row Path "<id>/v<N>"; ok is false for anything else.
func pathVersion(id, p string) (int, bool) {
	rest, ok := strings.CutPrefix(p, id+"/")
	if !ok {
		return 0, false
	}
	return parseVersion(rest)
}

// writeCertVersion stores a certificate as a new version root/<id>/v<N>/
// (N one above the highest present) and returns its row Path. Both files are
// written into a 0700 staging directory as fsynced 0600 files, the staging
// directory is fsynced and renamed to v<N> in one step, and the parent is
// fsynced: v<N> either does not exist or holds the complete, matching pair.
// Errors never contain key material.
func writeCertVersion(root, id string, chainPEM, keyPEM []byte) (string, error) {
	if !validID(id) {
		return "", fmt.Errorf("acme: invalid certificate id %q", id)
	}
	if len(chainPEM) == 0 || len(keyPEM) == 0 {
		return "", errors.New("acme: empty certificate or key")
	}
	if err := ensureDir(root); err != nil {
		return "", fmt.Errorf("acme: certs dir: %w", err)
	}
	dir := filepath.Join(root, id)
	if err := ensureDir(dir); err != nil {
		return "", fmt.Errorf("acme: cert dir: %w", err)
	}
	n := 1
	if vs := certVersions(root, id); len(vs) > 0 {
		n = vs[len(vs)-1] + 1
	}
	stage, err := os.MkdirTemp(dir, ".tmp-v-*")
	if err != nil {
		return "", fmt.Errorf("acme: cert dir: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := os.Chmod(stage, dirMode); err != nil {
		return "", fmt.Errorf("acme: cert dir: %w", err)
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{PrivkeyFile, keyPEM}, {FullchainFile, chainPEM}} {
		p := filepath.Join(stage, f.name)
		tmp, err := writeTemp(p, f.data)
		if err != nil {
			return "", fmt.Errorf("acme: write %s/%s: %w", id, f.name, err)
		}
		if err := os.Rename(tmp, p); err != nil {
			_ = os.Remove(tmp)
			return "", fmt.Errorf("acme: write %s/%s: %w", id, f.name, err)
		}
	}
	syncDir(stage)
	if err := os.Rename(stage, filepath.Join(dir, versionPrefix+strconv.Itoa(n))); err != nil {
		return "", fmt.Errorf("acme: publish %s: %w", versionPath(id, n), err)
	}
	ok = true
	syncDir(dir)
	return versionPath(id, n), nil
}

// pruneCertVersions removes, under root/<id>, every version below keep-1
// (the current version and the one before it stay) and every leftover
// staging directory.
func pruneCertVersions(root, id string, keep int) error {
	dir := filepath.Join(root, id)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		n, isV := parseVersion(e.Name())
		if (isV && n < keep-1) || strings.HasPrefix(e.Name(), ".tmp-") {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				errs = append(errs, err)
			}
		}
	}
	syncDir(dir)
	return errors.Join(errs...)
}

// removeVersionsAbove removes every version of id newer than current (and
// leftover staging directories): files written by an attempt whose store
// row was never updated. current 0 removes every version.
func removeVersionsAbove(root, id string, current int) error {
	dir := filepath.Join(root, id)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var errs []error
	for _, e := range ents {
		n, isV := parseVersion(e.Name())
		if (isV && n > current) || strings.HasPrefix(e.Name(), ".tmp-") {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				errs = append(errs, err)
			}
		}
	}
	syncDir(dir)
	return errors.Join(errs...)
}
