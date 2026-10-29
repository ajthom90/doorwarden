package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ajthom90/doorwarden/internal/acme"
)

// Run is the reconcile loop: one cycle at once, then one per poll interval
// (settings.poll_interval), per Trigger, and when a certificate expires (the
// Traefik selection changes). Ticks and triggers that arrive while a cycle
// runs coalesce into one more cycle. With an ACME manager, Renew runs every
// RenewEvery when the run is not dry.
//
// Run returns nil when ctx is cancelled, after the running cycle (aborted
// through ctx: executors stop between actions) and the renewal goroutine
// returned. The caller then calls Close and closes the store.
func (a *App) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("app: nil context")
	}
	poll := a.cfg.Settings.PollInterval
	if poll <= 0 {
		poll = 30 * time.Second
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	certTimer := time.NewTimer(time.Hour)
	certTimer.Stop()
	defer certTimer.Stop()

	var wg sync.WaitGroup
	defer wg.Wait()
	renewStarted := a.mgr == nil

	a.Trigger()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-a.trigger:
		case <-tick.C:
		case <-certTimer.C:
		}
		// Coalesce: whatever else is pending is covered by this cycle.
		drain(a.trigger)
		drainTick(tick.C)
		a.RunOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if !renewStarted {
			// After the first cycle, so Renew's Wanted callback sees the
			// persisted routes.
			renewStarted = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				a.renewLoop(ctx)
			}()
		}
		a.cycleMu.Lock()
		next := a.nextCert
		a.cycleMu.Unlock()
		certTimer.Stop()
		if !next.IsZero() {
			d := certDelay(next, a.now())
			if a.onCertArm != nil {
				a.onCertArm(d)
			}
			certTimer.Reset(d)
		}
	}
}

// MinCertRearm is the shortest delay the certificate-expiry timer is armed
// for, so the timer alone never runs more than one cycle a minute (an
// expiry that is already past, a failing write, ...).
const MinCertRearm = time.Minute

// certDelay is how long to wait before the re-render at next (one second
// past it), never less than MinCertRearm.
func certDelay(next, now time.Time) time.Duration {
	d := next.Sub(now) + time.Second
	if d < MinCertRearm {
		d = MinCertRearm
	}
	return d
}

func drain(c chan struct{}) {
	select {
	case <-c:
	default:
	}
}

func drainTick(c <-chan time.Time) {
	select {
	case <-c:
	default:
	}
}

// renewLoop calls ACME Renew right away and then every RenewEvery, unless
// the run is dry (no ACME orders in dry run).
func (a *App) renewLoop(ctx context.Context) {
	t := time.NewTicker(a.renewTO)
	defer t.Stop()
	for {
		a.renewOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *App) renewOnce(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if dry, _ := a.DryRun(ctx); dry {
		return
	}
	if a.beforeRenew != nil {
		if err := a.beforeRenew(ctx); err != nil {
			a.log.WarnContext(ctx, "certificate renewal round skipped", "error", err)
			return
		}
	}
	rctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	for _, r := range a.mgr.Renew(rctx) {
		if a.countRenewal(r) == "error" {
			a.log.WarnContext(ctx, "certificate renewal failed", "cert", r.CertID, "zone", r.Zone, "error", r.Err)
		}
	}
}

// countRenewal counts one certificate result in
// doorwarden_cert_renewal_total when an attempt was made (issuance,
// renewal, re-issue: from the hourly round, the cycle's CertEnsure, the
// API's renew and issuer switch alike) and returns its result ("ok",
// "error", or "" when no attempt was made: deferred, skipped, unwanted,
// imported, needs a switch, already in flight, refused downgrade, unknown
// certificate, no issuer).
func (a *App) countRenewal(r acme.Result) string {
	res := ""
	switch {
	case r.Skipped, errors.Is(r.Err, acme.ErrDeferred), errors.Is(r.Err, acme.ErrUnwanted),
		errors.Is(r.Err, acme.ErrImported), errors.Is(r.Err, acme.ErrNeedsSwitch), errors.Is(r.Err, acme.ErrInFlight),
		errors.Is(r.Err, acme.ErrDowngrade), errors.Is(r.Err, acme.ErrNotFound), errors.Is(r.Err, acme.ErrNoIssuer):
	case r.Err == nil:
		res = "ok"
	default:
		res = "error"
	}
	if res != "" {
		a.met.CertRenewal(res)
	}
	return res
}
