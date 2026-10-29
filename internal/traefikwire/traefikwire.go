// Package traefikwire connects the configuration and the certificate rows to
// the Traefik renderer: it maps config.Config to traefik.Options and
// traefik.TLSOptions and renders routes plus certificates in one call. It
// reads no files (internal/traefik never reads key material; Write is the
// only disk access and touches only Traefik's dynamic directory).
package traefikwire

import (
	"sort"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
)

// Options maps the configuration to the renderer's options. The default
// certificate itself is chosen by Render (traefik.CertsFromRows).
func Options(cfg *config.Config) (traefik.Options, traefik.TLSOptions) {
	t := cfg.Traefik
	return traefik.Options{
			EntryPoint:          t.EntryPoint,
			PathPrefix:          t.CertPathPrefix,
			ExternalMiddlewares: append([]string(nil), t.ExternalMiddlewares...),
			MinTLSVersion:       t.TLSMinVersion,
			SNIStrict:           t.SNIStrict,
		}, traefik.TLSOptions{
			LocalCertsRoot: cfg.CertsRoot(),
			DefaultZone:    cfg.DefaultCertZone(),
			ServeExpired:   t.ServeExpired,
		}
}

// Render selects the certificates among rows (as of now) and renders the
// FULL file set for traefik.Write: routes, middlewares, certificates, the
// default certificate and TLS options. Problems are the certificate
// selection's followed by the renderer's (each part sorted); err is only for
// invalid options or programming errors (see traefik.Render).
func Render(cfg *config.Config, routes []store.Route, rows []store.Cert, now time.Time) (traefik.Files, []traefik.Problem, error) {
	opts, topts := Options(cfg)
	certs, def, cprobs := traefik.CertsFromRows(rows, topts, now)
	if def.IsSet() {
		d := def.Cert
		opts.DefaultCert = &d
	}
	opts.Challenge = Challenge(cfg, routes, nil)
	files, probs, err := traefik.Render(routes, traefik.MiddlewareDefs(cfg.MiddlewareDefs()), certs, opts)
	if err != nil {
		return nil, nil, err
	}
	return files, append(cprobs, probs...), nil
}

// HTTP01Zones returns the normalized names of the zones whose certificates
// are issued by http-01 (an issuer and certificate.challenge http-01), or
// nil when acme.http01_listen is unset (no challenge server, so no route).
func HTTP01Zones(cfg *config.Config) map[string]bool {
	if cfg.ACME.HTTP01Listen == "" {
		return nil
	}
	var out map[string]bool
	for _, z := range cfg.Zones {
		if z.Certificate.Issuer != "" && z.Certificate.Challenge == "http-01" {
			if out == nil {
				out = map[string]bool{}
			}
			out[norm(z.Name)] = true
		}
	}
	return out
}

// Challenge returns the HTTP-01 challenge router options: the hostnames of
// the routes in http-01 zones (the names the ACME manager orders and renews,
// RouteHosts.Wanted; the apex included) plus extra (names about to be
// ordered whose routes are not persisted yet). nil when no zone uses
// http-01 or acme.http01_listen is unset; an empty host list renders no
// file either way.
func Challenge(cfg *config.Config, routes []store.Route, extra []string) *traefik.Challenge {
	zones := HTTP01Zones(cfg)
	if zones == nil {
		return nil
	}
	seen := map[string]bool{}
	var hosts []string
	add := func(h string) {
		h = norm(h)
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	for _, rt := range routes {
		if zones[norm(rt.Zone)] {
			add(rt.Hostname)
		}
	}
	for _, h := range extra {
		add(h)
	}
	sort.Strings(hosts)
	return &traefik.Challenge{EntryPoint: cfg.Traefik.HTTPEntryPoint, Backend: cfg.ACME.HTTP01Backend, Hosts: hosts}
}

func norm(s string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(s)), ".") }
