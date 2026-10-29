package config

import (
	"fmt"
	"path"
	"strings"
)

// TraefikTLS holds the TLS settings of the traefik: section (inlined into
// Traefik, so the keys are traefik.tls_min_version etc.). Certificate paths
// as Traefik sees them use traefik.cert_path_prefix; doorwarden's own view of
// the certificate directory is acme.certs_dir (CertsRoot).
type TraefikTLS struct {
	// TLSMinVersion is tls.options.default.minVersion: VersionTLS12
	// (default) or VersionTLS13.
	TLSMinVersion string `yaml:"tls_min_version"`
	// SNIStrict (opt-in) makes Traefik reject handshakes without SNI or with
	// a name no certificate matches, instead of serving the default
	// certificate. Off by default: clients that send no SNI (some health
	// checks, old clients, access by IP) would be refused outright.
	SNIStrict bool `yaml:"sni_strict"`
	// ServeExpired (opt-in) keeps rendering an expired certificate when no
	// valid one covers its names, so clients see an expiry error naming the
	// right host instead of the default certificate. An expired certificate
	// never displaces a valid one either way.
	ServeExpired bool `yaml:"serve_expired"`
}

// TLSMinVersions are the accepted traefik.tls_min_version values.
var TLSMinVersions = []string{"VersionTLS12", "VersionTLS13"}

// DefaultCertsRoot is CertsRoot when acme.certs_dir is unset.
const DefaultCertsRoot = "/data/certs"

func (t *TraefikTLS) applyDefaults() {
	if t.TLSMinVersion == "" {
		t.TLSMinVersion = TLSMinVersions[0]
	}
}

// CertsRoot is doorwarden's view of the certificate directory
// (acme.certs_dir, default DefaultCertsRoot).
func (c *Config) CertsRoot() string {
	if c.ACME.CertsDir != "" {
		return c.ACME.CertsDir
	}
	return DefaultCertsRoot
}

// DefaultCertZone is the zone whose certificate becomes Traefik's single
// default certificate: settings.default_zone when set, else the only
// configured zone, else "" (none; Traefik serves its self-signed default).
// The result is lowercased without a trailing dot.
func (c *Config) DefaultCertZone() string {
	if dz := normZoneName(c.Settings.DefaultZone); dz != "" {
		return dz
	}
	if len(c.Zones) == 1 {
		return normZoneName(c.Zones[0].Name)
	}
	return ""
}

// validateTLS checks the TLS settings and that acme.certs_dir is clean.
func (c *Config) validateTLS() []error {
	var errs []error
	if v := c.Traefik.TLSMinVersion; v != "" {
		ok := false
		for _, a := range TLSMinVersions {
			ok = ok || v == a
		}
		if !ok {
			errs = append(errs, fmt.Errorf("traefik.tls_min_version %q must be one of %s", v, strings.Join(TLSMinVersions, ", ")))
		}
	}
	if d := c.ACME.CertsDir; strings.HasPrefix(d, "/") && d != "/" && path.Clean(d) != strings.TrimRight(d, "/") {
		errs = append(errs, fmt.Errorf("acme.certs_dir %q must be a clean path (no . or .. elements)", d))
	}
	return errs
}
