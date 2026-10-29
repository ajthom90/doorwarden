package app

// The API's control plane (web.Control) and the UI overrides.
//
// UI overrides (services.overrides_json, written only by
// SetServiceOverride; TouchService never touches the column) are loaded at
// the start of every cycle and applied to each discovered service after
// dedupe and before the approval gate, so the gate fingerprints the
// overridden service: a rename or skip-verify change of an approve-mode
// service puts it back to pending until re-approved. An override row that
// cannot be read or parsed fails closed: the overrides cannot be loaded ->
// every source is treated as unavailable this cycle (nothing published,
// nothing removed); one row unparsable -> that service is skipped.
//
// An override is applied by an administrator, who is the authority: when
// the service's content before the change was approved, SetServiceOverride
// moves the approval to the overridden content in the same action
// (approval.Gate.Reapprove) and records it in the activity log. Content
// nobody approved stays Pending.
//
// A TrueNAS app without a usable portal is an Error service with no backend
// host. A UI Port override on it promotes it to Discovered with the host the
// TrueNAS source uses (the default zone's target_ip) and the overridden port
// (scheme http unless the app reported one); the approval gate still
// applies (final-review H2 ruling).
//
// Unpublish sets skip: the service is absent from the plan, so its route
// and records are scheduled for removal after settings.grace_period (24h
// by default), the same as a service that disappeared. Publish clears it.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/acme"
	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/web"
)

var _ web.Control = (*App)(nil)

// listed is one discovered service of the last cycle (pre-gate).
type listed struct {
	spec  string        // source spec name
	raw   model.Service // as discovered (no UI overrides)
	svc   model.Service // UI overrides applied
	ov    model.UIOverrides
	state string
}

// loadOverrides reads every service's UI overrides. bad lists rows that
// could not be parsed.
func (a *App) loadOverrides(ctx context.Context) (map[string]model.UIOverrides, map[string]bool, error) {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	rows, err := a.st.ListServices(sctx)
	if err != nil {
		return nil, nil, err
	}
	out, bad := map[string]model.UIOverrides{}, map[string]bool{}
	for _, r := range rows {
		o, err := model.ParseUIOverrides(strings.TrimSpace(r.OverridesJSON))
		if err != nil {
			bad[r.Key] = true
			continue
		}
		if !o.Empty() {
			out[r.Key] = o
		}
	}
	return out, bad, nil
}

// promote returns s ready for the UI overrides o: a TrueNAS app in Error
// with no backend host and a Port override gets the TrueNAS backend host
// (tip) and becomes Discovered, so the override yields a routable backend.
// Everything else is returned unchanged.
func promote(s model.Service, o model.UIOverrides, tip string) model.Service {
	if o.Port == nil || tip == "" || !strings.HasPrefix(s.Key, "truenas:") ||
		s.State != model.StateError || s.Backend.Host != "" {
		return s
	}
	s.State = model.StateDiscovered
	s.Backend.Host = tip
	if s.Backend.Scheme == "" {
		s.Backend.Scheme = "http"
	}
	return s
}

// overridden is raw with the UI overrides o applied (after promote).
func (a *App) overridden(raw model.Service, o model.UIOverrides) model.Service {
	return model.ApplyUI(promote(raw, o, sourceTargetIP(a.cfg)), o)
}

// applyOverrides applies the UI overrides to one source's services and
// records them for the listing.
func (a *App) applyOverrides(ctx context.Context, spec string, svcs []model.Service, ovs map[string]model.UIOverrides, bad map[string]bool) ([]model.Service, []listed) {
	out := make([]model.Service, 0, len(svcs))
	ls := make([]listed, 0, len(svcs))
	for _, s := range svcs {
		o := ovs[s.Key]
		got := a.overridden(s, o)
		msg := ""
		if bad[s.Key] {
			got.Options.Skip = true
			msg = fmt.Sprintf("service %s: its UI overrides cannot be read; it is not published until they are set again", s.Key)
		}
		a.logChange(ctx, "overrides/"+s.Key, "error", msg)
		out = append(out, got)
		ls = append(ls, listed{spec: spec, raw: s, svc: got, ov: o})
	}
	return out, ls
}

// zoneNames returns the planner's zone names and default zone.
func (a *App) zoneNames() ([]string, string) {
	var zs []string
	for _, z := range a.cfg.Zones {
		zs = append(zs, normZone(z.Name))
	}
	dz := normZone(a.cfg.Settings.DefaultZone)
	if dz == "" && len(zs) == 1 {
		dz = zs[0]
	}
	return zs, dz
}

// publishListing stores the cycle's listing; sources that were unavailable
// keep their previous entries.
func (a *App) publishListing(cur []listed, down map[string]bool) {
	a.hmu.Lock()
	defer a.hmu.Unlock()
	next := append([]listed(nil), cur...)
	for _, l := range a.listing {
		if down[l.spec] {
			next = append(next, l)
		}
	}
	sort.Slice(next, func(i, j int) bool { return next[i].raw.Key < next[j].raw.Key })
	a.listing = next
}

// SetEventSink sets where cycle events go (the API's SSE broker).
func (a *App) SetEventSink(f func(name string, v any)) {
	a.hmu.Lock()
	a.events = f
	a.hmu.Unlock()
}

func (a *App) emit(name string, v any) {
	a.hmu.RLock()
	f := a.events
	a.hmu.RUnlock()
	if f != nil {
		f(name, v)
	}
}

// ServiceList implements web.Control.
func (a *App) ServiceList() []web.ServiceInfo {
	zs, dz := a.zoneNames()
	fps := a.gate.Fingerprints()
	a.hmu.RLock()
	defer a.hmu.RUnlock()
	out := make([]web.ServiceInfo, 0, len(a.listing))
	for _, l := range a.listing {
		h, _ := model.Hostname(l.svc, zs, dz)
		mws := append([]string{}, l.svc.Options.Middlewares...)
		si := web.ServiceInfo{Key: l.raw.Key, Source: l.raw.Source, Name: l.svc.Name, Zone: l.svc.Zone, Hostname: h,
			Backend: l.svc.Backend, Websockets: l.svc.Options.Websockets, Middlewares: mws, State: l.state, Overrides: l.ov}
		if l.state == model.StatePending || l.state == model.StatePublished {
			si.Fingerprint = fps[l.raw.Key]
		}
		out = append(out, si)
	}
	return out
}

// SetServiceOverride implements web.Control.
func (a *App) SetServiceOverride(ctx context.Context, key string, edit func(*model.UIOverrides) error) error {
	a.ovMu.Lock()
	defer a.ovMu.Unlock()
	var raw model.Service
	found := false
	a.hmu.RLock()
	for _, l := range a.listing {
		if l.raw.Key == key {
			raw, found = l.raw, true
		}
	}
	a.hmu.RUnlock()
	if !found {
		return web.ErrUnknownService
	}
	cur, _, err := a.st.GetService(ctx, key)
	if err != nil {
		return err
	}
	o, err := model.ParseUIOverrides(strings.TrimSpace(cur.OverridesJSON))
	readable := err == nil
	if err != nil {
		o = model.UIOverrides{} // unreadable: replaced by the edit
	}
	before := a.overridden(raw, o)
	if err := edit(&o); err != nil {
		return err
	}
	zs, dz := a.zoneNames()
	if err := o.Validate(promote(raw, o, sourceTargetIP(a.cfg)), zs, dz); err != nil {
		return err
	}
	after := a.overridden(raw, o)
	js, err := o.JSON()
	if err != nil {
		return err
	}
	if err := a.st.SetServiceOverrides(ctx, key, raw.Source, js, a.now()); err != nil {
		return err
	}
	if readable {
		oldFP, newFP := approval.Fingerprint(before), approval.Fingerprint(after)
		ok, err := a.gate.Reapprove(ctx, key, oldFP, newFP)
		switch {
		case err != nil:
			a.appendActivity(ctx, "warn", "approval", fmt.Sprintf("service %s: UI override saved, but its approval could not be carried over (it may be pending until approved again): %v", key, err))
		case ok && oldFP != newFP:
			a.appendActivity(ctx, "info", "approval", fmt.Sprintf("service %s: approval carried over to the content changed by a UI override (%s)", key, js))
		}
	}
	a.hmu.Lock()
	for i := range a.listing {
		if a.listing[i].raw.Key == key {
			a.listing[i].ov = o
			a.listing[i].svc = a.overridden(a.listing[i].raw, o)
		}
	}
	a.hmu.Unlock()
	a.Trigger()
	return nil
}

// Approve implements web.Control.
func (a *App) Approve(ctx context.Context, key, fingerprint string) error {
	if err := a.gate.Approve(ctx, key, fingerprint); err != nil {
		return err
	}
	a.Trigger()
	return nil
}

// LastPlan implements web.Control.
func (a *App) LastPlan() web.Plan {
	a.hmu.RLock()
	defer a.hmu.RUnlock()
	p := a.plan
	p.Actions = append([]reconcile.Action(nil), a.plan.Actions...)
	return p
}

// TestProvider implements web.Control.
func (a *App) TestProvider(ctx context.Context, name string) error {
	p := a.providers[name]
	if p == nil {
		return web.ErrNotFound
	}
	return p.Test(ctx)
}

var errNoACME = errors.New("no zone has a certificate issuer")

// ErrDryRun: RenewCert and SwitchProduction are refused while dry run is on
// (they would contact the CA and write certificates).
var ErrDryRun = web.ErrDryRun

// refuseDry returns ErrDryRun while dry run is on; a store error reading
// the toggle refuses too (fail safe).
func (a *App) refuseDry(ctx context.Context) error {
	dry, err := a.DryRun(ctx)
	if err != nil {
		return fmt.Errorf("read dry-run state: %w", err)
	}
	if dry {
		return ErrDryRun
	}
	return nil
}

// RenewCert implements web.Control.
func (a *App) RenewCert(ctx context.Context, id string) error {
	if err := a.refuseDry(ctx); err != nil {
		return err
	}
	if a.mgr == nil {
		return errNoACME
	}
	r := a.mgr.RenewNow(ctx, id)
	if r.Err == nil && !r.Skipped {
		a.reRender(ctx)
	}
	if r.Err != nil {
		return r.Err
	}
	if r.Skipped {
		return errors.New("the certificate was not renewed (imported, staging/production mismatch, or no issuer)")
	}
	return nil
}

// SwitchProduction implements web.Control.
func (a *App) SwitchProduction(ctx context.Context, issuer string) error {
	if err := a.refuseDry(ctx); err != nil {
		return err
	}
	if a.mgr == nil {
		return errNoACME
	}
	rs, err := a.mgr.SwitchIssuer(ctx, issuer, "production")
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range rs {
		if r.Err != nil && !errors.Is(r.Err, acme.ErrDeferred) {
			errs = append(errs, fmt.Errorf("%s: %w", r.CertID, r.Err))
		}
	}
	a.reRender(ctx)
	return errors.Join(errs...)
}

// reRender re-renders the Traefik files after a certificate change made
// outside a cycle (the next cycle would do it too; this is sooner).
func (a *App) reRender(context.Context) { a.Trigger() }

// skippedConflicts returns the ids of DNS conflicts skipped in the UI.
func (a *App) skippedConflicts(ctx context.Context) map[string]bool {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	m, err := a.st.ListSettingsWithPrefix(sctx, web.ConflictSkipPrefix)
	out := map[string]bool{}
	if err != nil {
		return out // notifications are not suppressed
	}
	for k := range m {
		out[strings.TrimPrefix(k, web.ConflictSkipPrefix)] = true
	}
	return out
}

func (a *App) setPlan(acts []reconcile.Action, dry bool, at time.Time) {
	a.hmu.Lock()
	a.plan = web.Plan{At: at, DryRun: dry, Actions: append([]reconcile.Action(nil), acts...)}
	a.hmu.Unlock()
}

// stateOf returns the gate's state for key from res, or why it is absent.
func stateOf(res []model.Service, s model.Service, mode approval.Mode) string {
	for _, r := range res {
		if r.Key == s.Key {
			return r.State
		}
	}
	if mode == approval.ModeOff {
		return "off"
	}
	if s.Options.Skip {
		return "skipped"
	}
	return model.StateDiscovered
}
