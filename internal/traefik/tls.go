package traefik

// Certificate selection: which certificate rows (internal/store, written by
// internal/acme) are rendered into tls.certificates, and which one becomes
// Traefik's default certificate. Pure: no file is opened, no key material is
// read; only row metadata and paths are used.
//
// # How Traefik v3 picks a certificate (the reason for every rule below)
//
// For a TLS handshake Traefik collects, over every loaded certificate, each
// SAN that matches the SNI name ("*.zone" matches exactly one extra label),
// keyed by that SAN string, and serves the certificate of the
// lexicographically LAST matching SAN. An exact name therefore beats a
// wildcard, and two certificates that carry the SAME SAN collide in a Go map:
// which one is served is then random. Certificates are also deduplicated by
// their full SAN list (the first loaded wins). Without SNI, or when nothing
// matches, the default store's defaultCertificate is served (Traefik
// generates a self-signed one when none is configured). (From Traefik's
// pkg/tls certificate store; verify against the deployed version, see the
// T17 report.)
//
// # Selection policy (deterministic for any row order)
//
//  1. A row is a candidate only when: its ID is a valid certificate id; its
//     Status is "valid", "imported" or "unwanted" (unwanted only stops
//     renewal: a still-valid certificate keeps serving its names, which can
//     only avoid a gap, never cause one); its Path is "<id>/v<N>" (or that
//     below LocalCertsRoot); it has an expiry and at least one valid name.
//     "failed" and unknown statuses, and malformed rows, get a Problem.
//     LastError does not matter: a failed renewal keeps the old certificate.
//  2. Expired rows (now >= NotAfter) get KindCertExpired and are dropped,
//     unless ServeExpired (see TLSOptions).
//  3. One certificate per exact name set (lowercase, no trailing dot,
//     deduplicated, order-free). Within a set the best row wins: not expired,
//     then production over staging, then later NotAfter, then managed over
//     imported, then the smaller ID. The others get KindCertSuperseded.
//  4. Tiers: valid production, valid staging, expired production, expired
//     staging. Valid production certificates are always rendered. A
//     certificate of a lower tier is rendered only if it cannot take a name
//     away from a rendered certificate of a better tier, i.e. none of its
//     names is also a name of that certificate, and none of its exact names
//     is covered by that certificate's wildcard (an exact name would win the
//     SNI match). Otherwise the whole certificate is dropped
//     (KindCertSuperseded): its uncovered names then get the default
//     certificate (a name-mismatch error), which is no worse than an
//     untrusted staging or an expired certificate, while the covered names
//     keep the good one. Certificates of the same tier may overlap: either
//     serves the name correctly.
//
// # Default certificate
//
// Traefik has one default store with one defaultCertificate; there are no
// per-zone defaults. Per-zone selection is done by SNI through
// tls.certificates (every rendered certificate). The defaultCertificate only
// matters for clients without SNI or with a name nothing covers; it is the
// best valid PRODUCTION certificate of TLSOptions.DefaultZone (the
// configured settings.default_zone, else the only configured zone; see
// config.DefaultCertZone), preferring the one carrying "*.<zone>", then the
// apex "<zone>", then the order of rule 3. With no default zone, or no such
// certificate, none is set and Traefik serves its self-signed default: with
// several zones and no default_zone any choice would expose one zone's names
// to clients asking for another, and a staging or expired default is no
// better than Traefik's own.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/store"
)

// Certificate problem kinds (Problem.Cert names the row).
const (
	// KindCertExpired: the row is expired; it is not rendered unless
	// TLSOptions.ServeExpired (then this Problem is informational).
	KindCertExpired = "certificate-expired"
	// KindCertSuperseded: a better certificate covers the row's names.
	KindCertSuperseded = "certificate-superseded"
	// KindCertUnusable: the row has no servable certificate (status failed
	// or unknown, or no expiry recorded).
	KindCertUnusable = "certificate-unusable"
	// KindNoCertificate: a rendered router's hostname is not covered by any
	// rendered certificate, so Traefik serves the default certificate for it
	// (a name mismatch). The route is still rendered.
	KindNoCertificate = "no-certificate-for-host"
)

// Certificate file names inside a version directory (internal/acme).
const (
	FullchainFile = "fullchain.pem"
	PrivkeyFile   = "privkey.pem"
)

// DefaultLocalCertsRoot is doorwarden's own view of the certificate
// directory when TLSOptions.LocalCertsRoot is empty.
const DefaultLocalCertsRoot = "/data/certs"

// Row statuses that may be served (internal/acme status constants, as plain
// strings so this package does not depend on internal/acme).
var servableStatus = map[string]bool{"valid": true, "imported": true, "unwanted": true}

// TLSOptions tunes CertsFromRows.
type TLSOptions struct {
	// LocalCertsRoot is doorwarden's view of the certificate directory
	// (config acme.certs_dir; default DefaultLocalCertsRoot). Row Paths are
	// normally relative ("<id>/v<N>"); an absolute Path must lie below this
	// root. The Traefik-side prefix is applied by Render (Options.PathPrefix),
	// so certificate paths here are relative to the certificate root.
	LocalCertsRoot string
	// DefaultZone is the zone whose certificate becomes Traefik's default
	// certificate ("" = none).
	DefaultZone string
	// ServeExpired renders an expired certificate when no valid one could
	// serve its names (default false). Off: the name gets the default
	// certificate, a name-mismatch error that never looks like a certificate
	// the operator still trusts, and the KindCertExpired Problem surfaces it.
	// On: clients get an expiry error naming the right host, which can help
	// diagnosis; an expired certificate never displaces a valid one.
	ServeExpired bool
}

// DefaultCert is the certificate chosen for tls.stores.default. The zero
// value means none (Traefik generates its own).
type DefaultCert struct {
	Zone string
	Cert TLSCert
}

// IsSet reports whether a default certificate was chosen.
func (d DefaultCert) IsSet() bool { return d.Cert.CertFile != "" }

type candidate struct {
	row     store.Cert
	names   []string // canonical, sorted
	set     string
	rel     string // "<id>/v<N>"
	expired bool
}

func (c *candidate) tier() int {
	t := 0
	if c.row.Staging {
		t++
	}
	if c.expired {
		t += 2
	}
	return t
}

// better is the order of rule 3 (and the tier order).
func better(a, b *candidate) bool {
	if a.expired != b.expired {
		return !a.expired
	}
	if a.row.Staging != b.row.Staging {
		return !a.row.Staging
	}
	if !a.row.NotAfter.Equal(b.row.NotAfter) {
		return a.row.NotAfter.After(b.row.NotAfter)
	}
	if a.row.Managed != b.row.Managed {
		return a.row.Managed
	}
	return a.row.ID < b.row.ID
}

func (c *candidate) cert() TLSCert {
	return TLSCert{ID: c.row.ID, Zone: canonName(c.row.Zone), Domains: append([]string(nil), c.names...),
		CertFile: c.rel + "/" + FullchainFile, KeyFile: c.rel + "/" + PrivkeyFile}
}

// CertsFromRows selects the certificates to render and the default
// certificate (see the policy above). certs is sorted by ID; problems is
// sorted. now decides expiry. No file is read.
func CertsFromRows(rows []store.Cert, opts TLSOptions, now time.Time) (certs []TLSCert, def DefaultCert, problems []Problem) {
	root := opts.LocalCertsRoot
	if root == "" {
		root = DefaultLocalCertsRoot
	}
	if root != "/" {
		root = strings.TrimRight(root, "/")
	}
	rootErr := cleanPath(root, true)

	certs = []TLSCert{}
	prob := func(kind string, r store.Cert, f string, a ...any) {
		problems = append(problems, Problem{Kind: kind, Cert: r.ID, Detail: fmt.Sprintf(f, a...)})
	}
	groups := map[string][]*candidate{}
	for _, r := range rows {
		if !validCertID(r.ID) {
			prob(KindInvalidCert, r, "certificate id %q is not [a-z0-9_-]{1,200}", r.ID)
			continue
		}
		if !servableStatus[r.Status] {
			prob(KindCertUnusable, r, "certificate %s has status %q; not served", r.ID, r.Status)
			continue
		}
		rel, err := relCertDir(r, root, rootErr)
		if err != nil {
			prob(KindInvalidCert, r, "certificate %s: %v; not served", r.ID, err)
			continue
		}
		if r.NotAfter.Unix() <= 0 {
			prob(KindCertUnusable, r, "certificate %s has no expiry recorded; not served", r.ID)
			continue
		}
		names, err := certNames(r.DomainsJSON)
		if err != nil {
			prob(KindInvalidCert, r, "certificate %s: %v; not served", r.ID, err)
			continue
		}
		c := &candidate{row: r, names: names, set: strings.Join(names, ","), rel: rel, expired: !now.Before(r.NotAfter)}
		if c.expired && !opts.ServeExpired {
			prob(KindCertExpired, r, "certificate %s for %s expired at %s; not served", r.ID, c.set, r.NotAfter.UTC().Format(time.RFC3339))
			continue
		}
		groups[c.set] = append(groups[c.set], c)
	}

	// Rule 3: one winner per exact name set.
	var winners []*candidate
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool { return better(g[i], g[j]) })
		winners = append(winners, g[0])
		for _, l := range g[1:] {
			prob(KindCertSuperseded, l.row, "certificate %s for %s not served: %s is preferred", l.row.ID, l.set, g[0].row.ID)
		}
	}
	sort.Slice(winners, func(i, j int) bool { return better(winners[i], winners[j]) })

	// Rule 4: tiers.
	var rendered []*candidate
	for _, c := range winners {
		var by *candidate
		for _, r := range rendered {
			if r.tier() < c.tier() && takesName(c.names, r.names) {
				by = r
				break
			}
		}
		if by != nil {
			what := "staging"
			if c.expired {
				what = "expired"
			}
			prob(KindCertSuperseded, c.row, "%s certificate %s for %s not served: it would take a name from %s", what, c.row.ID, c.set, by.row.ID)
			continue
		}
		if c.expired {
			prob(KindCertExpired, c.row, "certificate %s for %s expired at %s; served anyway (serve_expired): no valid certificate covers its names",
				c.row.ID, c.set, c.row.NotAfter.UTC().Format(time.RFC3339))
		}
		rendered = append(rendered, c)
	}
	for _, c := range rendered {
		certs = append(certs, c.cert())
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].ID < certs[j].ID })

	// Default certificate: valid production certificates of the zone.
	if z := canonName(opts.DefaultZone); z != "" {
		var best *candidate
		rank := func(c *candidate) int {
			switch {
			case contains(c.names, "*."+z):
				return 0
			case contains(c.names, z):
				return 1
			}
			return 2
		}
		for _, c := range rendered {
			if c.tier() != 0 || canonName(c.row.Zone) != z {
				continue
			}
			if best == nil || rank(c) < rank(best) || rank(c) == rank(best) && better(c, best) {
				best = c
			}
		}
		if best != nil {
			def = DefaultCert{Zone: z, Cert: best.cert()}
		}
	}
	sortProblems(problems)
	return certs, def, problems
}

// takesName reports whether a certificate with names cand, loaded next to
// one with names held, could be served for an SNI name that held serves:
// a shared SAN (random choice) or an exact name below a wildcard of held
// (the exact name wins).
func takesName(cand, held []string) bool {
	for _, n := range cand {
		if contains(held, n) {
			return true
		}
		if !strings.HasPrefix(n, "*.") && covers(wildcards(held), n) {
			return true
		}
	}
	return false
}

func wildcards(ns []string) []string {
	var out []string
	for _, n := range ns {
		if strings.HasPrefix(n, "*.") {
			out = append(out, n)
		}
	}
	return out
}

func contains(ns []string, n string) bool {
	for _, x := range ns {
		if x == n {
			return true
		}
	}
	return false
}

// covers reports whether a certificate for names serves host: an equal
// name, or "*.<rest>" where host is one label followed by ".<rest>".
// Comparison ignores case and a trailing dot.
func covers(names []string, host string) bool {
	h := canonName(host)
	if h == "" {
		return false
	}
	for _, n := range names {
		n = canonName(n)
		if n == h {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if label, tail, ok := strings.Cut(h, "."); ok && label != "" && tail == rest {
				return true
			}
		}
	}
	return false
}

func canonName(s string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(s)), ".") }

// certNames parses and canonicalizes a row's DomainsJSON.
func certNames(dj string) ([]string, error) {
	var raw []string
	if err := json.Unmarshal([]byte(dj), &raw); err != nil {
		return nil, fmt.Errorf("domains are not a JSON list of names")
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range raw {
		n := strings.TrimSuffix(strings.ToLower(d), ".")
		base := strings.TrimPrefix(n, "*.")
		if strings.Contains(base, "*") || !validRouteHostname(base) {
			return nil, fmt.Errorf("invalid name %q", d)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no names")
	}
	sort.Strings(out)
	return out, nil
}

// validCertID mirrors internal/acme's certificate id rule.
func validCertID(id string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 200 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// validVersion mirrors internal/acme's "v<N>" directory rule.
func validVersion(s string) bool {
	d, ok := strings.CutPrefix(s, "v")
	if !ok || d == "" || len(d) > 9 || d[0] == '0' {
		return false
	}
	_, err := strconv.ParseUint(d, 10, 32)
	return err == nil
}

// relCertDir maps a row Path to the version directory relative to the
// certificate root: exactly "<row id>/v<N>". An absolute Path must be that
// below root.
func relCertDir(r store.Cert, root string, rootErr error) (string, error) {
	p := r.Path
	if p == "" {
		return "", fmt.Errorf("no certificate files recorded")
	}
	if strings.HasPrefix(p, "/") {
		if rootErr != nil {
			return "", fmt.Errorf("certs root: %v", rootErr)
		}
		if err := cleanPath(p, true); err != nil {
			return "", err
		}
		rel, ok := strings.CutPrefix(p, strings.TrimRight(root, "/")+"/")
		if !ok {
			return "", fmt.Errorf("path %q is outside the certs root %s", p, root)
		}
		p = rel
	}
	if err := cleanPath(p, false); err != nil {
		return "", err
	}
	id, ver, ok := strings.Cut(p, "/")
	if !ok || id != r.ID || !validVersion(ver) {
		return "", fmt.Errorf("path %q is not %s/v<N>", r.Path, r.ID)
	}
	return p, nil
}
