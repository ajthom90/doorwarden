package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// ACME tunes the certificate manager (internal/acme). Zero values mean the
// manager's defaults.
type ACME struct {
	// CertsDir is where certificates are written as <id>/{fullchain,privkey}.pem
	// (default /data/certs).
	CertsDir string `yaml:"certs_dir"`
	// HTTP01Listen is the host:port the HTTP-01 challenge server listens on.
	// Unset disables HTTP-01. Traefik must forward
	// /.well-known/acme-challenge/ on port 80 to this address.
	HTTP01Listen string `yaml:"http01_listen"`
	// DNSPropagationTimeout bounds the wait for a DNS-01 TXT record to
	// propagate (default: the challenge provider's own timeout).
	DNSPropagationTimeout time.Duration `yaml:"dns_propagation_timeout"`
	// Resolvers are recursive resolvers (host or host:port) used for the
	// DNS-01 propagation check (default: the system resolvers).
	Resolvers []string `yaml:"resolvers"`
	// IssueTimeout bounds one issuance as seen by the reconcile loop
	// (default 5m).
	IssueTimeout time.Duration `yaml:"issue_timeout"`
}

// validateACME checks the acme section and the certificate settings of every
// zone that has an issuer. Issuer directories, e-mail and lego provider
// names are checked by acme.NewManager (it owns the lego catalog).
func (c *Config) validateACME() []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	a := c.ACME
	if a.DNSPropagationTimeout < 0 {
		add("acme.dns_propagation_timeout must not be negative")
	}
	if a.IssueTimeout < 0 {
		add("acme.issue_timeout must not be negative")
	}
	if a.CertsDir != "" && !strings.HasPrefix(a.CertsDir, "/") {
		add("acme.certs_dir %q must be an absolute path", a.CertsDir)
	}
	if a.HTTP01Listen != "" {
		if _, port, err := net.SplitHostPort(a.HTTP01Listen); err != nil || port == "" {
			add("acme.http01_listen %q must be host:port", a.HTTP01Listen)
		}
	}
	for _, r := range a.Resolvers {
		if strings.TrimSpace(r) == "" {
			add("acme.resolvers: empty entry")
		}
	}
	for i, z := range c.Zones {
		cert := z.Certificate
		if cert.Issuer == "" {
			continue
		}
		id := fmt.Sprintf("zone[%d] %q", i, z.Name)
		switch cert.Challenge {
		case "", "dns-01":
			if cert.DNSProvider == "" {
				add("%s: certificate.dns_provider is required for challenge dns-01", id)
			}
		case "http-01":
			if a.HTTP01Listen == "" {
				add("%s: certificate.challenge http-01 requires acme.http01_listen", id)
			}
		}
	}
	names := make([]string, 0, len(c.Issuers))
	for n := range c.Issuers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if (c.Issuers[n].EABKid == "") != (c.Issuers[n].EABHMAC == "") {
			add("issuer %q: eab_kid and eab_hmac must be set together", n)
		}
	}
	return errs
}
