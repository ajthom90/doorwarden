package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
	"github.com/ajthom90/doorwarden/internal/traefikwire"
)

// render writes Traefik's dynamic files from the persisted routes and cert
// rows (traefikwire's composition, plus an on-disk check of the default
// certificate) and records the certificate expiry metrics. The routes of
// the keys in quarantined (this cycle's gate verdict) are rendered as
// quarantined even if storing the flag failed, so a failed write cannot
// leave a quarantined service served.
func (a *App) render(ctx context.Context, now time.Time, quarantined map[string]bool) error {
	return a.renderWith(ctx, now, quarantined, nil)
}

// renderWith is render with extra HTTP-01 challenge hosts (names about to
// be ordered whose routes are not persisted yet, see challengeFirst).
func (a *App) renderWith(ctx context.Context, now time.Time, quarantined map[string]bool, extraChallenge []string) error {
	routes, err := a.st.ListRoutes(ctx)
	if err != nil {
		return fmt.Errorf("traefik render: reading routes: %w", err)
	}
	for i := range routes {
		if quarantined[routes[i].Key] {
			routes[i].Quarantined = true
		}
	}
	rows, err := a.st.ListCerts(ctx)
	if err != nil {
		return fmt.Errorf("traefik render: reading certificates: %w", err)
	}
	opts, topts := traefikwire.Options(a.cfg)
	certs, def, probs := traefik.CertsFromRows(rows, topts, now)
	if def.IsSet() {
		d := def.Cert
		root := a.cfg.CertsRoot()
		var missing []string
		for _, f := range []string{d.CertFile, d.KeyFile} {
			if err := a.stat(filepath.Join(root, filepath.FromSlash(f))); err != nil {
				missing = append(missing, f)
			}
		}
		if len(missing) == 0 {
			opts.DefaultCert = &d
			a.logChange(ctx, "default-cert", "", "")
		} else {
			// Traefik refuses the whole TLS file when the default store
			// names a missing file; leave out only the default store.
			a.logChange(ctx, "default-cert", "error", fmt.Sprintf(
				"default certificate %s: file(s) %s missing below the certificate directory; Traefik's default store is left out (it serves its self-signed default)",
				d.ID, strings.Join(missing, ", ")))
		}
	}
	opts.Challenge = traefikwire.Challenge(a.cfg, routes, extraChallenge)
	files, rprobs, err := traefik.Render(routes, traefik.MiddlewareDefs(a.cfg.MiddlewareDefs()), certs, opts)
	if err != nil {
		return fmt.Errorf("traefik render: %w", err)
	}
	probs = append(probs, rprobs...)
	msg := ""
	if len(probs) > 0 {
		ps := make([]string, 0, len(probs))
		for _, p := range probs {
			ps = append(ps, p.Kind+" "+strings.TrimSpace(p.Hostname+" "+p.Key+" "+p.Cert)+": "+p.Detail)
		}
		msg = "traefik: " + strings.Join(ps, "; ")
	}
	a.logChange(ctx, "traefik-problems", "warn", msg)
	mode, err := a.cfg.Traefik.Mode()
	if err != nil {
		return err // config.Validate rejects it at load
	}
	if err := traefik.WriteMode(a.cfg.Traefik.DynamicDir, files, mode); err != nil {
		return fmt.Errorf("traefik write: %w", err)
	}
	a.setChallengeHosts(opts.Challenge)
	a.certExpiryMetrics(rows)
	return nil
}

// NextCertExpiry is the earliest certificate NotAfter strictly after now
// among rows (zero when none): the Traefik files must be rendered again
// then, because the certificate selection changes when a row expires.
func NextCertExpiry(rows []store.Cert, now time.Time) time.Time {
	var next time.Time
	for _, r := range rows {
		if r.NotAfter.After(now) && (next.IsZero() || r.NotAfter.Before(next)) {
			next = r.NotAfter
		}
	}
	return next
}

// certExpiryMetrics records the earliest valid certificate expiry per zone.
func (a *App) certExpiryMetrics(rows []store.Cert) {
	best := map[string]time.Time{}
	for _, r := range rows {
		if r.Status != "valid" && r.Status != "imported" {
			continue
		}
		z := normZone(r.Zone)
		if t, ok := best[z]; !ok || r.NotAfter.Before(t) {
			best[z] = r.NotAfter
		}
	}
	for z, t := range best {
		a.met.SetCertExpiry(z, t)
	}
}
