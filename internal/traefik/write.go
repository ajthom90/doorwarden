package traefik

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// fileNameRe is the only shape of file name Write creates: no separators,
// no dot segments, so nothing outside dir can be addressed.
var fileNameRe = regexp.MustCompile(`^doorwarden-[a-z0-9]+(-[a-z0-9]+)*\.yml$`)

// Write makes dir contain exactly files among the files doorwarden owns.
//
//   - Each file is replaced atomically: a temp file in dir (".doorwarden-*.tmp",
//     an extension Traefik's directory watcher does not load), fsync, chmod
//     0644 (Traefik usually runs as another user; the content holds no
//     secrets), rename over the target. A symlink at the target is replaced
//     by the rename; its target is never written.
//   - A file whose current content is byte-identical is not rewritten, so its
//     mtime is kept and Traefik does not reload.
//   - Stale owned files are removed: regular files in dir named
//     "doorwarden-*.yml" or "doorwarden-*.yaml" whose content starts with
//     Header and that are not in files. Nothing else in dir is touched.
//
// Every name must match doorwarden-[a-z0-9-].yml and every content must start
// with Header (so what Write creates is what it may later remove); otherwise
// nothing is written. dir must exist. Write is not safe for concurrent calls
// on the same dir.
func Write(dir string, files Files) error {
	names := make([]string, 0, len(files))
	for n, b := range files {
		if !fileNameRe.MatchString(n) {
			return fmt.Errorf("traefik: refusing file name %q", n)
		}
		if !bytes.HasPrefix(b, []byte(Header)) {
			return fmt.Errorf("traefik: content of %s lacks the doorwarden header", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	if fi, err := os.Stat(dir); err != nil {
		return fmt.Errorf("traefik: dynamic dir: %w", err)
	} else if !fi.IsDir() {
		return fmt.Errorf("traefik: dynamic dir %s is not a directory", dir)
	}

	var errs []error
	changed := false
	for _, n := range names {
		w, err := writeIfChanged(dir, n, files[n])
		if err != nil {
			errs = append(errs, err)
		}
		changed = changed || w
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		errs = append(errs, fmt.Errorf("traefik: list %s: %w", dir, err))
	}
	for _, e := range ents {
		n := e.Name()
		if _, keep := files[n]; keep || !strings.HasPrefix(n, "doorwarden-") ||
			(!strings.HasSuffix(n, ".yml") && !strings.HasSuffix(n, ".yaml")) {
			continue
		}
		p := filepath.Join(dir, n)
		owned, err := ownedFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !owned {
			continue
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("traefik: remove stale %s: %w", n, err))
			continue
		}
		changed = true
	}
	if changed {
		syncDir(dir)
	}
	return errors.Join(errs...)
}

// ownedFile reports whether p is a regular file (not a symlink) starting
// with Header.
func ownedFile(p string) (bool, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, nil
	}
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, len(Header))
	if _, err := io.ReadFull(f, buf); err != nil {
		return false, nil // shorter than the header: not ours
	}
	return string(buf) == Header, nil
}

func writeIfChanged(dir, name string, content []byte) (bool, error) {
	target := filepath.Join(dir, name)
	fi, err := os.Lstat(target)
	switch {
	case err == nil && fi.Mode().IsRegular():
		cur, err := os.ReadFile(target)
		if err != nil {
			return false, fmt.Errorf("traefik: read %s: %w", name, err)
		}
		if bytes.Equal(cur, content) {
			return false, nil
		}
	case err == nil && fi.Mode()&fs.ModeSymlink != 0:
		// replaced by the rename below; the link target is never opened
	case err == nil:
		return false, fmt.Errorf("traefik: %s exists and is not a regular file", target)
	case !errors.Is(err, fs.ErrNotExist):
		return false, fmt.Errorf("traefik: stat %s: %w", name, err)
	}

	tmp, err := os.CreateTemp(dir, ".doorwarden-*.tmp")
	if err != nil {
		return false, fmt.Errorf("traefik: temp for %s: %w", name, err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(content); err != nil {
		return false, fmt.Errorf("traefik: write %s: %w", name, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		return false, fmt.Errorf("traefik: chmod %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		return false, fmt.Errorf("traefik: sync %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("traefik: close %s: %w", name, err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return false, fmt.Errorf("traefik: rename %s: %w", name, err)
	}
	ok = true
	return true, nil
}

// syncDir makes renames and removals durable; best effort (not every
// platform supports fsync on a directory).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
