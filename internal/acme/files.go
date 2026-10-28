package acme

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// File names below certs/<id>/.
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

// writeCertFiles stores a certificate under root/<id>/. Both files are first
// written completely to 0600 temp files; only then is each renamed over its
// target (key first), so a failure before the renames leaves the previous
// pair untouched and a reader never sees a partial file. Errors never
// contain key material.
func writeCertFiles(root, id string, chainPEM, keyPEM []byte) error {
	if !validID(id) {
		return fmt.Errorf("acme: invalid certificate id %q", id)
	}
	if len(chainPEM) == 0 || len(keyPEM) == 0 {
		return errors.New("acme: empty certificate or key")
	}
	if err := ensureDir(root); err != nil {
		return fmt.Errorf("acme: certs dir: %w", err)
	}
	dir := filepath.Join(root, id)
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("acme: cert dir: %w", err)
	}
	keyPath, chainPath := filepath.Join(dir, PrivkeyFile), filepath.Join(dir, FullchainFile)
	keyTmp, err := writeTemp(keyPath, keyPEM)
	if err != nil {
		return fmt.Errorf("acme: write %s/%s: %w", id, PrivkeyFile, err)
	}
	chainTmp, err := writeTemp(chainPath, chainPEM)
	if err != nil {
		_ = os.Remove(keyTmp)
		return fmt.Errorf("acme: write %s/%s: %w", id, FullchainFile, err)
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		_ = os.Remove(keyTmp)
		_ = os.Remove(chainTmp)
		return fmt.Errorf("acme: replace %s/%s: %w", id, PrivkeyFile, err)
	}
	if err := os.Rename(chainTmp, chainPath); err != nil {
		_ = os.Remove(chainTmp)
		return fmt.Errorf("acme: replace %s/%s: %w", id, FullchainFile, err)
	}
	syncDir(dir)
	return nil
}
