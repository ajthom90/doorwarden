package acme

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
	Err     error
}

// maxPEMSize bounds an imported PEM file.
const maxPEMSize = 1 << 20

// ImportPEM stores an existing certificate for zone as an imported
// (managed=false) certificate. The key must match the leaf certificate and
// every certificate name must lie inside the zone. An expired certificate
// is imported but flagged (Expired, row last_error). Imported certificates
// are never renewed automatically; see RenewNow. Re-importing the same leaf
// is idempotent (same id).
func (m *Manager) ImportPEM(ctx context.Context, zone string, fullchainPEM, keyPEM []byte) (*ImportResult, error) {
	ir, err := m.importPEM(ctx, zone, fullchainPEM, keyPEM)
	return ir, m.red.safeErr(err)
}

func (m *Manager) importPEM(ctx context.Context, zone string, fullchainPEM, keyPEM []byte) (*ImportResult, error) {
	z := normName(zone)
	if _, ok := m.zone(z); !ok {
		return nil, fmt.Errorf("acme: zone %q is not configured", zone)
	}
	pair, err := tls.X509KeyPair(fullchainPEM, keyPEM)
	if err != nil {
		// Never wrap the parser error: the message is generic, but keep the
		// guarantee that nothing derived from the key reaches callers.
		if _, cerr := leafCert(fullchainPEM); cerr != nil {
			return nil, errors.New("acme: import: certificate PEM does not parse")
		}
		return nil, errors.New("acme: import: private key is missing, unreadable or does not match the certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("acme: import: certificate does not parse")
	}
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
	if err := writeCertFiles(m.certsDir, id, fullchainPEM, keyPEM); err != nil {
		return nil, err
	}
	now := m.now()
	expired := !leaf.NotAfter.After(now)
	dj, _ := json.Marshal(names)
	row := store.Cert{ID: id, Zone: z, DomainsJSON: string(dj), NotAfter: leaf.NotAfter, Status: StatusImported,
		LastResult: "imported", Path: id, Managed: false}
	if expired {
		row.LastError = "imported certificate is expired"
	}
	if err := m.st.UpsertCert(ctx, row); err != nil {
		return nil, fmt.Errorf("acme: import: store: %w", err)
	}
	m.log.Info("acme: certificate imported", "cert", id, "zone", z, "names", strings.Join(names, ","), "not_after", leaf.NotAfter, "expired", expired)
	m.changed()
	return &ImportResult{Expired: expired, Bundle: &Bundle{ID: id, Zone: z, Names: names, NotAfter: leaf.NotAfter,
		Dir: id, ChainPEM: append([]byte(nil), fullchainPEM...), Key: secrets.Secret(keyPEM)}}, nil
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
func (m *Manager) ImportNPMDir(ctx context.Context, dir string) ([]ImportResult, error) {
	rs, err := m.importNPMDir(ctx, dir)
	for i := range rs {
		rs[i].Err = m.red.safeErr(rs[i].Err)
	}
	return rs, m.red.safeErr(err)
}

func (m *Manager) importNPMDir(ctx context.Context, dir string) ([]ImportResult, error) {
	if fileExists(filepath.Join(dir, FullchainFile)) {
		return []ImportResult{m.importDir(ctx, dir)}, nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("acme: import: %w", err)
	}
	var out []ImportResult
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "npm-") {
			continue
		}
		out = append(out, m.importDir(ctx, filepath.Join(dir, e.Name())))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("acme: import: no npm-* certificate directories in %s", dir)
	}
	return out, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func readLimited(p string) ([]byte, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxPEMSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(p), maxPEMSize)
	}
	return os.ReadFile(p)
}

func (m *Manager) importDir(ctx context.Context, dir string) ImportResult {
	r := ImportResult{Source: dir}
	chain, err := readLimited(filepath.Join(dir, FullchainFile))
	if err != nil {
		r.Err = fmt.Errorf("acme: import %s: %w", dir, err)
		return r
	}
	key, err := readLimited(filepath.Join(dir, PrivkeyFile))
	if err != nil {
		r.Err = fmt.Errorf("acme: import %s: cannot read %s", dir, PrivkeyFile)
		return r
	}
	leaf, err := leafCert(chain)
	if err != nil {
		r.Err = fmt.Errorf("acme: import %s: %w", dir, err)
		return r
	}
	zone := m.zoneFor(certNames(leaf))
	if zone == "" {
		r.Err = fmt.Errorf("acme: import %s: no configured zone contains all of %s", dir, strings.Join(certNames(leaf), ","))
		return r
	}
	ir, err := m.importPEM(ctx, zone, chain, key)
	if err != nil {
		r.Err = fmt.Errorf("acme: import %s: %w", dir, err)
		return r
	}
	ir.Source = dir
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
