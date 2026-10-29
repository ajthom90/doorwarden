package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/store"
)

// ImportResult describes one imported certificate.
type ImportResult struct {
	// Source is the directory imported from (ImportNPMDir) or "".
	Source string
	Bundle *Bundle
	// Expired is true when the certificate was already expired (it is still
	// imported; its row's last_error says so).
	Expired bool
	// Skipped is true when nothing was written because a row with the same
	// id already holds an adopted (managed) or newer certificate; SkipReason
	// says why. A skip is not an error.
	Skipped    bool
	SkipReason string
	// DryRun is true when the certificate was validated but not stored
	// (ImportDryRun); Bundle then carries no key.
	DryRun bool
	Err    error
}

// ImportOption changes how ImportPEM and ImportNPMDir behave.
type ImportOption func(*importOpts)

type importOpts struct{ dryRun bool }

// ImportDryRun validates certificates and reports what would be imported
// or skipped (using the store read-only) without writing files or rows.
func ImportDryRun() ImportOption { return func(o *importOpts) { o.dryRun = true } }

func importOptions(opts []ImportOption) importOpts {
	var o importOpts
	for _, f := range opts {
		f(&o)
	}
	return o
}

// maxPEMSize bounds an imported PEM file.
const maxPEMSize = 1 << 20

// ImportPEM stores an existing certificate for zone as an imported
// (managed=false) certificate. The key must match the leaf certificate and
// every certificate name must lie inside the zone. An expired certificate
// is imported but flagged (Expired, row last_error). Imported certificates
// are never renewed automatically; see RenewNow. Re-importing the same leaf
// is idempotent (same id). When a row with the same id is already managed
// (adopted), no longer imported, or holds a later expiry, nothing is
// written and the result is Skipped: a newer version is never replaced.
func (m *Manager) ImportPEM(ctx context.Context, zone string, fullchainPEM, keyPEM []byte, opts ...ImportOption) (*ImportResult, error) {
	ir, err := m.importPEM(ctx, zone, fullchainPEM, keyPEM, importOptions(opts))
	return ir, m.red.safeErr(err)
}

func (m *Manager) importPEM(ctx context.Context, zone string, fullchainPEM, keyPEM []byte, o importOpts) (*ImportResult, error) {
	z := normName(zone)
	if _, ok := m.zone(z); !ok {
		return nil, fmt.Errorf("acme: zone %q is not configured", zone)
	}
	if len(fullchainPEM) > maxPEMSize || len(keyPEM) > maxPEMSize {
		return nil, fmt.Errorf("acme: import: PEM input is larger than %d bytes", maxPEMSize)
	}
	certs, err := parseChainPEM(fullchainPEM)
	if err != nil {
		return nil, err
	}
	keyDER, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	// Store re-encoded material only: one CERTIFICATE block per certificate
	// and the key as a single PKCS#8 block, never the input bytes.
	var chainOut []byte
	for _, c := range certs {
		chainOut = append(chainOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := tls.X509KeyPair(chainOut, keyOut); err != nil {
		// Never wrap the parser error: keep the guarantee that nothing
		// derived from the key reaches callers.
		return nil, errors.New("acme: import: private key does not match the certificate")
	}
	leaf := certs[0]
	names := certNames(leaf)
	if len(names) == 0 {
		return nil, errors.New("acme: import: certificate has no DNS names")
	}
	for _, n := range names {
		if _, err := checkName(z, n); err != nil {
			return nil, fmt.Errorf("acme: import: %w", err)
		}
	}
	sum := sha256.Sum256(leaf.Raw)
	id := "imported-" + safeLabel(z) + "-" + hex.EncodeToString(sum[:6])
	now := m.now()
	expired := !leaf.NotAfter.After(now)
	dj, _ := json.Marshal(names)
	row := store.Cert{ID: id, Zone: z, DomainsJSON: string(dj), NotAfter: leaf.NotAfter, Status: StatusImported,
		LastResult: "imported", Managed: false}
	if expired {
		row.LastError = "imported certificate is expired"
	}
	rows, err := m.st.ListCerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("acme: import: read certificates: %w", err)
	}
	for _, prev := range rows {
		if prev.ID != id {
			continue
		}
		reason := ""
		switch {
		case prev.Managed || prev.Status != StatusImported:
			reason = fmt.Sprintf("already adopted: Doorwarden manages this certificate now (status %s)", prev.Status)
		case prev.NotAfter.After(leaf.NotAfter):
			reason = "a newer version is already stored"
		}
		if reason != "" {
			return &ImportResult{Skipped: true, SkipReason: reason, DryRun: o.dryRun, Bundle: &Bundle{ID: id, Zone: z, Names: names,
				NotAfter: prev.NotAfter, Dir: prev.Path, Managed: prev.Managed, ChainPEM: chainOut}}, nil
		}
	}
	if o.dryRun {
		return &ImportResult{Expired: expired, DryRun: true, Bundle: &Bundle{ID: id, Zone: z, Names: names, NotAfter: leaf.NotAfter,
			ChainPEM: chainOut}}, nil
	}
	row, err = m.storeVersion(ctx, row, chainOut, keyOut)
	if err != nil {
		return nil, fmt.Errorf("acme: import: %w", err)
	}
	m.log.Info("acme: certificate imported", "cert", id, "zone", z, "names", strings.Join(names, ","), "not_after", leaf.NotAfter, "expired", expired)
	m.changed()
	return &ImportResult{Expired: expired, Bundle: &Bundle{ID: id, Zone: z, Names: names, NotAfter: leaf.NotAfter,
		Dir: row.Path, ChainPEM: chainOut, Key: secrets.Secret(keyOut)}}, nil
}

// parseChainPEM parses a full chain: one or more CERTIFICATE blocks, the
// leaf first and then each issuer. Text before a block (certbot-style
// comments) is ignored; any other block type or non-whitespace after the
// last block is rejected. Only the order is checked (each certificate's
// issuer name is the next one's subject); signatures and trust are NOT
// verified: an imported chain is served as given.
func parseChainPEM(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := b
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		rest = r
		if blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
			return nil, fmt.Errorf("acme: import: unexpected PEM block %q in the certificate chain", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme: import: certificate %d does not parse", len(certs)+1)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("acme: import: certificate PEM does not parse")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("acme: import: trailing data after the last certificate")
	}
	for i := 0; i+1 < len(certs); i++ {
		if !bytes.Equal(certs[i].RawIssuer, certs[i+1].RawSubject) {
			return nil, fmt.Errorf("acme: import: certificate chain order: certificate %d was not issued by certificate %d (the leaf must come first, then each issuer)", i+1, i+2)
		}
	}
	return certs, nil
}

// parseKeyPEM parses exactly one unencrypted private key (PKCS#8, SEC 1 EC
// or PKCS#1 RSA; an "EC PARAMETERS" block is ignored) and returns it as
// PKCS#8 DER. Errors never contain anything derived from the key.
func parseKeyPEM(b []byte) ([]byte, error) {
	var key any
	n := 0
	rest := b
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		rest = r
		if blk.Type == "EC PARAMETERS" {
			continue
		}
		if blk.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(blk.Headers["Proc-Type"], "ENCRYPTED") {
			return nil, errors.New("acme: import: encrypted private keys are not supported; decrypt the key first")
		}
		n++
		if n > 1 {
			break
		}
		var err error
		switch blk.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(blk.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
		default:
			n = 2 // not a key block
		}
		if err != nil {
			return nil, errors.New("acme: import: private key does not parse")
		}
	}
	if n != 1 || key == nil {
		return nil, errors.New("acme: import: the key file must hold exactly one private key")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("acme: import: trailing data after the private key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("acme: import: unsupported private key type")
	}
	return der, nil
}

// certNames returns the leaf's DNS names (or its CN when it has none),
// normalized and sorted.
func certNames(c *x509.Certificate) []string {
	src := c.DNSNames
	if len(src) == 0 && c.Subject.CommonName != "" {
		src = []string{c.Subject.CommonName}
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range src {
		n = normName(n)
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// ImportNPMDir imports Nginx Proxy Manager certificates. dir is either one
// certificate directory (containing fullchain.pem and privkey.pem, e.g.
// live/npm-3) or a live/ directory whose npm-* subdirectories are each
// imported. The zone of each certificate is the longest configured zone
// containing all its names. One ImportResult per directory; a failing
// directory does not stop the others.
func (m *Manager) ImportNPMDir(ctx context.Context, dir string, opts ...ImportOption) ([]ImportResult, error) {
	rs, err := m.importNPMDir(ctx, dir, importOptions(opts))
	for i := range rs {
		rs[i].Err = m.red.safeErr(rs[i].Err)
	}
	return rs, m.red.safeErr(err)
}

func (m *Manager) importNPMDir(ctx context.Context, dir string, o importOpts) ([]ImportResult, error) {
	rd, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("acme: import: %w", err)
	}
	if rd, err = filepath.Abs(rd); err != nil {
		return nil, fmt.Errorf("acme: import: %w", err)
	}
	root := importRoot(rd)
	if _, err := os.Lstat(filepath.Join(rd, FullchainFile)); err == nil {
		return []ImportResult{m.importDir(ctx, root, rd, dir, o)}, nil
	}
	ents, err := os.ReadDir(rd)
	if err != nil {
		return nil, fmt.Errorf("acme: import: %w", err)
	}
	var out []ImportResult
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "npm-") {
			continue
		}
		p := filepath.Join(rd, e.Name())
		if st, err := os.Stat(p); err != nil || !st.IsDir() { // a symlinked npm-N dir is followed
			continue
		}
		out = append(out, m.importDir(ctx, root, p, filepath.Join(dir, e.Name()), o))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("acme: import: no npm-* certificate directories in %s", dir)
	}
	return out, nil
}

// importRoot is the tree that imported files must resolve into: the parent
// of the nearest "live" directory in dir's (resolved) path, so that certbot
// and NPM live/<name>/*.pem -> ../../archive/<name>/*N.pem links work, or
// dir itself when no ancestor is named "live".
func importRoot(dir string) string {
	for d := dir; ; {
		if filepath.Base(d) == "live" {
			return filepath.Dir(d)
		}
		p := filepath.Dir(d)
		if p == d {
			return dir
		}
		d = p
	}
}

// readConfined reads the regular file p after resolving every symlink,
// requiring the result to lie inside root and to be at most maxPEMSize
// bytes. Non-regular files (devices, FIFOs, directories) are rejected
// before they are opened; the open is non-blocking and the opened file is
// checked again, so a swapped-in FIFO cannot hang the import.
func readConfined(root, p string) ([]byte, error) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil, err
	}
	if real, err = filepath.Abs(real); err != nil {
		return nil, err
	}
	if rel, err := filepath.Rel(root, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("%s resolves to %s, outside %s", filepath.Base(p), real, root)
	}
	st, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(p))
	}
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fst, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fst.Mode().IsRegular() || !os.SameFile(st, fst) {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(p))
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPEMSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxPEMSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(p), maxPEMSize)
	}
	return b, nil
}

// importDir imports dir's fullchain.pem and privkey.pem (no other file is
// read). shown is the path used in messages.
func (m *Manager) importDir(ctx context.Context, root, dir, shown string, o importOpts) ImportResult {
	r := ImportResult{Source: shown}
	chain, err := readConfined(root, filepath.Join(dir, FullchainFile))
	if err != nil {
		r.Err = fmt.Errorf("acme: import %s: %w", shown, err)
		return r
	}
	key, err := readConfined(root, filepath.Join(dir, PrivkeyFile))
	if err != nil {
		r.Err = fmt.Errorf("acme: import %s: %w", shown, err)
		return r
	}
	leaf, err := leafCert(chain)
	if err != nil {
		r.Err = fmt.Errorf("acme: import %s: %w", shown, err)
		return r
	}
	zone := m.zoneFor(certNames(leaf))
	if zone == "" {
		r.Err = fmt.Errorf("acme: import %s: no configured zone contains all of %s", shown, strings.Join(certNames(leaf), ","))
		return r
	}
	ir, err := m.importPEM(ctx, zone, chain, key, o)
	if err != nil {
		r.Err = fmt.Errorf("acme: import %s: %w", shown, err)
		return r
	}
	ir.Source = shown
	return *ir
}

// zoneFor returns the longest configured zone containing every name.
func (m *Manager) zoneFor(names []string) string {
	best := ""
	for _, z := range m.cfg.Zones {
		zn := normName(z.Name)
		ok := len(names) > 0
		for _, n := range names {
			if _, err := checkName(zn, n); err != nil {
				ok = false
				break
			}
		}
		if ok && len(zn) > len(best) {
			best = zn
		}
	}
	return best
}
