package config

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/ajthom90/doorwarden/internal/acme/legonames"
)

// Capabilities describes what a DNS provider type can do. A later task adapts
// dns.Capabilities to this.
type Capabilities struct{ WildcardA bool }

// Validate returns every problem found, not just the first.
func (c *Config) Validate(caps func(providerType string) (Capabilities, bool)) []error {
	if caps == nil {
		caps = func(string) (Capabilities, bool) { return Capabilities{}, true }
	}
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	names := make([]string, 0, len(c.Providers))
	for n := range c.Providers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if c.Providers[n].Type == "" {
			add("provider %q: type is required", n)
		}
	}

	oneOf := func(v string, opts ...string) bool {
		for _, o := range opts {
			if v == o {
				return true
			}
		}
		return false
	}

	for i, z := range c.Zones {
		id := fmt.Sprintf("zone[%d] %q", i, z.Name)
		if z.Name == "" {
			add("zone[%d]: name is required", i)
		}
		if z.TargetIP == "" {
			add("%s: target_ip is required", id)
		} else if _, err := netip.ParseAddr(z.TargetIP); err != nil {
			add("%s: target_ip %q is not a valid IP", id, z.TargetIP)
		}

		if z.Records.Mode != "" && !oneOf(z.Records.Mode, "wildcard", "per-host", "off") {
			add("%s: records.mode %q must be wildcard, per-host or off", id, z.Records.Mode)
		}
		if z.Records.Mode != "off" && z.Records.Provider != "" {
			p, ok := c.Providers[z.Records.Provider]
			if !ok {
				add("%s: records.provider %q is not defined", id, z.Records.Provider)
			} else if z.Records.Mode == "wildcard" {
				if cp, known := caps(p.Type); !known {
					add("%s: records.provider %q has unknown type %q", id, z.Records.Provider, p.Type)
				} else if !cp.WildcardA {
					add("%s: records.mode wildcard requires a provider with wildcard A record support; %q (type %s) lacks it", id, z.Records.Provider, p.Type)
				}
			}
		} else if z.Records.Mode != "off" && z.Records.Mode != "" {
			add("%s: records.provider is required when records.mode is %q", id, z.Records.Mode)
		}

		cert := z.Certificate
		if cert.Strategy != "" && !oneOf(cert.Strategy, "wildcard", "per-host", "san") {
			add("%s: certificate.strategy %q must be wildcard, per-host or san", id, cert.Strategy)
		}
		if cert.Challenge != "" && !oneOf(cert.Challenge, "dns-01", "http-01") {
			add("%s: certificate.challenge %q must be dns-01 or http-01", id, cert.Challenge)
		}
		if cert.Strategy == "wildcard" && cert.Challenge != "" && cert.Challenge != "dns-01" {
			add("%s: certificate.strategy wildcard requires challenge dns-01", id)
		}
		if cert.Issuer != "" {
			if _, ok := c.Issuers[cert.Issuer]; !ok {
				add("%s: certificate.issuer %q is not defined", id, cert.Issuer)
			}
		}
		if cert.DNSProvider != "" {
			p, ok := c.Providers[cert.DNSProvider]
			if !ok {
				add("%s: certificate.dns_provider %q is not defined", id, cert.DNSProvider)
			} else if recordOnlyTypes[p.Type] {
				add("%s: certificate.dns_provider %q is of type %s, a record-only provider that cannot solve ACME challenges", id, cert.DNSProvider, p.Type)
			} else if !legonames.Known(p.Type) {
				add("%s: certificate.dns_provider %q has type %q, which is not a supported ACME DNS provider (a lego provider code)", id, cert.DNSProvider, p.Type)
			}
		}
	}

	for _, a := range []struct {
		name, v string
	}{
		{"sources.truenas.approval", approval(c.Sources.TrueNAS != nil, func() string { return c.Sources.TrueNAS.Approval })},
		{"sources.docker.approval", approval(c.Sources.Docker != nil, func() string { return c.Sources.Docker.Approval })},
	} {
		if a.v != "" && !oneOf(a.v, "auto", "approve", "off") {
			add("%s %q must be auto, approve or off", a.name, a.v)
		}
	}
	if dz := normZoneName(c.Settings.DefaultZone); dz != "" {
		found := false
		for _, z := range c.Zones {
			if normZoneName(z.Name) == dz {
				found = true
				break
			}
		}
		if !found {
			add("settings.default_zone %q is not a configured zone", c.Settings.DefaultZone)
		}
	}
	seen := map[string]int{}
	for i, st := range c.Static {
		for _, p := range st.Problems() {
			add("static[%d] %s: %s", i, st.Name, p)
		}
		if k := st.Key(); k != "" {
			if j, dup := seen[k]; dup {
				add("static[%d] %s: duplicate key %s (also static[%d])", i, st.Name, k, j)
			} else {
				seen[k] = i
			}
		}
	}
	errs = append(errs, c.validateTraefik()...)
	errs = append(errs, c.validateACME()...)
	return errs
}

// recordOnlyTypes are DNS record providers (records.provider) that cannot
// solve DNS-01 challenges.
var recordOnlyTypes = map[string]bool{"unifi": true, "pihole": true, "adguard": true}

func normZoneName(z string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(z)), ".")
}

func approval(present bool, f func() string) string {
	if !present {
		return ""
	}
	return f()
}
