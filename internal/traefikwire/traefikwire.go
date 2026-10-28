// Package traefikwire connects the configuration and the certificate rows to
// the Traefik renderer: it maps config.Config to traefik.Options and
// traefik.TLSOptions and renders routes plus certificates in one call. It
// reads no files (internal/traefik never reads key material; Write is the
// only disk access and touches only Traefik's dynamic directory).
package traefikwire

import (
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
	files, probs, err := traefik.Render(routes, traefik.MiddlewareDefs(cfg.MiddlewareDefs()), certs, opts)
	if err != nil {
		return nil, nil, err
	}
	return files, append(cprobs, probs...), nil
}
