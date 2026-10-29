package app

import (
	"context"
	"fmt"
	"time"

	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/traefik"
	"github.com/ajthom90/doorwarden/internal/traefikwire"
)

// HTTP-01 ordering. A cycle applies CertEnsure before RouteWrite and
// renders Traefik's files last, so the first order for a new http-01 name
// would reach the CA before Traefik routes /.well-known/acme-challenge/ for
// it. challengeFirst wraps the certificate executor: before a batch that
// orders http-01 names the challenge file does not yet match, it renders
// the files with those names added to the challenge router (everything else
// as of the persisted state and this cycle's quarantine verdict) and waits
// ChallengeSettle for Traefik to load them. Renewals (Manager.Renew) need
// nothing: their names are persisted routes, already in the file.

// setChallengeHosts records the hosts of the challenge file just written.
func (a *App) setChallengeHosts(ch *traefik.Challenge) {
	m := map[string]bool{}
	if ch != nil {
		for _, h := range ch.Hosts {
			m[h] = true
		}
	}
	a.chMu.Lock()
	a.challengeHosts = m
	a.chMu.Unlock()
}

// pendingChallenge returns the http-01 names of actions not in the last
// written challenge file.
func (a *App) pendingChallenge(actions []reconcile.Action) []string {
	zones := traefikwire.HTTP01Zones(a.cfg)
	if zones == nil {
		return nil
	}
	a.chMu.Lock()
	defer a.chMu.Unlock()
	var out []string
	for _, ac := range actions {
		if ac.Kind != reconcile.CertEnsure || !zones[normZone(ac.Zone)] {
			continue
		}
		for _, n := range ac.Names {
			if n = normZone(n); n != "" && !a.challengeHosts[n] {
				out = append(out, n)
			}
		}
	}
	return out
}

func (a *App) challengeFirst(next reconcile.Executor) reconcile.Executor {
	return reconcile.ExecutorFunc(func(ctx context.Context, actions []reconcile.Action, dryRun bool) error {
		if !dryRun {
			if names := a.pendingChallenge(actions); len(names) > 0 {
				rctx, cancel := context.WithTimeout(ctx, renderTimeout)
				err := a.renderWith(rctx, a.now(), a.cycleQuar, names)
				cancel()
				if err != nil {
					// Order anyway: the CA's failure is reported and backed
					// off like any other.
					a.logChange(ctx, "acme-http01-route", "warn", fmt.Sprintf("writing the HTTP-01 challenge route before ordering failed: %v", err))
				} else {
					a.logChange(ctx, "acme-http01-route", "", "")
					if a.challengeSettle > 0 {
						t := time.NewTimer(a.challengeSettle)
						select {
						case <-ctx.Done():
						case <-t.C:
						}
						t.Stop()
					}
				}
			}
		}
		return next.Apply(ctx, actions, dryRun)
	})
}
