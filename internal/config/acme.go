package config

import (
	"net/url"
	"strconv"

	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
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
	// HTTP01Backend is the URL Traefik uses to reach the HTTP-01 challenge
	// server on HTTP01Listen (scheme://host[:port], default
	// http://doorwarden:<port of http01_listen>). Doorwarden renders a
	// challenge router to it (internal/traefik, ChallengeFile).
	HTTP01Backend string `yaml:"http01_backend"`
	// http01BackendDefaulted: HTTP01Backend was derived from HTTP01Listen
	// (not set in the file).
	http01BackendDefaulted bool
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
	if b := a.HTTP01Backend; b != "" {
		if a.HTTP01Listen == "" {
			add("acme.http01_backend requires acme.http01_listen")
		}
		if msg := backendURLProblem(b); msg != "" {
			add("acme.http01_backend %q %s", b, msg)
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

// backendURLProblem checks a scheme://host[:port] URL (http or https, no
// userinfo, path, query or fragment). It returns "" when it is usable.
func backendURLProblem(raw string) string {
	u, err := url.Parse(raw)
	switch {
	case err != nil || strings.ContainsAny(raw, " \t\r\n"):
		return "is not a valid URL"
	case u.Scheme != "http" && u.Scheme != "https":
		return "must be http:// or https://"
	case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#"):
		return "must be scheme://host[:port] without userinfo, path, query or fragment"
	case u.Hostname() == "":
		return "has no host"
	case !model.ValidHost(u.Hostname()) && !model.ValidHost("["+u.Hostname()+"]"):
		return "has an invalid host"
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "port " + p + " out of range 1..65535"
		}
	}
	return ""
}
