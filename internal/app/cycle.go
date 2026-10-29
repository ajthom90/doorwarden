package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/notify"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/web"
)

// CycleResult summarizes one reconcile cycle.
type CycleResult struct {
	DryRun  bool
	Actions []reconcile.Action
	// Unavailable are the source names (and Service.Source values) treated
	// as unknown this cycle.
	Unavailable map[string]bool
	// Rendered is true when the Traefik files were rendered and written.
	Rendered bool
	// Err joins the cycle's errors (apply, render, store).
	Err error
}

func statFile(p string) error { _, err := os.Stat(p); return err }

func normZone(z string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(z)), ".") }

// RunOnce runs one reconcile cycle now. Cycles never overlap: a call waits
// for a running one to finish. Cancelling ctx aborts the cycle between
// steps (executors stop between actions and finish their bookkeeping); the
// Traefik render of what was persisted still runs.
func (a *App) RunOnce(ctx context.Context) CycleResult {
	a.cycleMu.Lock()
	defer a.cycleMu.Unlock()
	start := time.Now()
	now := a.now()
	res := CycleResult{Unavailable: map[string]bool{}}
	var errs []error

	dry, err := a.DryRun(ctx)
	if err != nil {
		a.logChange(ctx, "dryrun", "error", fmt.Sprintf("reading the dry-run toggle failed; running dry: %v", err))
		errs = append(errs, err)
	}
	res.DryRun = dry
	a.cycleDry.Store(dry)
	a.seenCur = map[string]bool{}
	defer func() {
		a.seenPrev, a.seenCur = a.seenCur, map[string]bool{}
	}()

	if !dry && !a.liveInitOK {
		if a.liveInit == nil {
			a.liveInitOK = true
		} else if err := a.liveInit(ctx); err != nil {
			a.logChange(ctx, "live-init", "error", fmt.Sprintf("start-up housekeeping failed (retried next cycle): %v", err))
		} else {
			a.liveInitOK = true
			a.logChange(ctx, "live-init", "", "")
		}
	}

	desired, up, quarantined := a.gather(ctx, res.Unavailable, dry)
	if err := ctx.Err(); err != nil {
		res.Err = err
		return res
	}

	obs, err := a.observe(ctx, now, res.Unavailable)
	obs.Quarantined = quarantined
	// The next re-render at a certificate expiry comes from the rows read
	// this cycle, dry run included (a stale value would re-arm in the past).
	a.nextCert = NextCertExpiry(obs.Certs, now)
	if err == nil {
		// Every cycle, dry run included (not only when Traefik's files are
		// rendered).
		a.certExpiryMetrics(obs.Certs)
	}
	if err != nil {
		// Without the persisted routes nothing can be planned safely.
		res.Err = errors.Join(append(errs, err)...)
		a.finishCycle(start, dry, up, desired, "error", res.Err)
		return res
	}

	acts, applyErr := a.runner.Reconcile(ctx, desired, obs, now)
	res.Actions = acts
	a.setPlan(acts, dry, now)
	if applyErr != nil {
		errs = append(errs, applyErr)
		a.logChange(ctx, "apply", "warn", fmt.Sprintf("reconcile apply had errors: %v", applyErr))
	} else {
		a.logChange(ctx, "apply", "", "")
	}
	a.countAndAlert(ctx, acts)

	if !dry {
		a.persistServices(ctx, desired, now)
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), renderTimeout)
		if err := a.render(rctx, now); err != nil {
			errs = append(errs, err)
		} else {
			res.Rendered = true
		}
		cancel()
	}
	res.Err = errors.Join(errs...)
	result := "ok"
	switch {
	case res.Err != nil:
		result = "error"
	case dry:
		result = "dry_run"
	}
	a.finishCycle(start, dry, up, desired, result, res.Err)
	a.emit("cycle", map[string]any{"result": result, "dry_run": dry, "actions": len(acts)})
	return res
}

func (a *App) finishCycle(start time.Time, dry bool, up map[string]bool, desired []model.Service, result string, err error) {
	a.met.ReconcileDone(result, time.Since(start))
	counts := map[string]int{}
	for _, s := range desired {
		counts[s.State]++
	}
	a.met.SetServices(counts)
	t := a.now()
	degraded := err != nil
	for _, ok := range up {
		degraded = degraded || !ok
	}
	a.hmu.Lock()
	a.health = web.HealthStatus{Degraded: degraded, DryRun: dry, Sources: up, LastReconcile: &t, LastResult: result}
	a.snap = append([]model.Service(nil), desired...)
	a.hmu.Unlock()
}

// gather lists every source and applies the approval gate. unavailable is
// filled with every unknown source name.
func (a *App) gather(ctx context.Context, unavailable map[string]bool, dry bool) ([]model.Service, map[string]bool, map[string]bool) {
	up := map[string]bool{}
	quarantined := map[string]bool{}
	var desired []model.Service
	var listing []listed
	down := map[string]bool{}
	mark := func(name string) {
		unavailable[name] = true
		for alias := range a.aliases[name] {
			unavailable[alias] = true
		}
		up[name] = false
		down[name] = true
		a.met.SourceUp(name, false)
	}
	defer func() { a.publishListing(listing, down) }()
	ovs, bad, err := a.loadOverrides(ctx)
	if err != nil {
		// Without the UI overrides a service could be published that the
		// operator unpublished: every source is unknown this cycle.
		a.logChange(ctx, "overrides", "error", fmt.Sprintf("UI overrides could not be read; every source is treated as unknown: %v", err))
		for _, sp := range a.sources {
			mark(sp.name())
		}
		return desired, up, quarantined
	}
	a.logChange(ctx, "overrides", "error", "")
	opt, err := a.approvalOptions(ctx, dry)
	if err != nil {
		// Without the persisted routes the gate cannot tell a served,
		// unchanged service from a changed one: every source is unknown.
		a.logChange(ctx, "approval-routes", "error", fmt.Sprintf("routes could not be read for the approval check; every source is treated as unknown: %v", err))
		for _, sp := range a.sources {
			mark(sp.name())
		}
		return desired, up, quarantined
	}
	a.logChange(ctx, "approval-routes", "error", "")
	for _, sp := range a.sources {
		name := sp.name()
		if sp.Source == nil {
			mark(name)
			a.logChange(ctx, "source/"+name, "error", fmt.Sprintf("source %s is not available: it could not be set up: %v", name, sp.Err))
			a.notifySource(ctx, name)
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, a.srcTO)
		t0 := time.Now()
		svcs, err := sp.Source.List(lctx)
		cancel()
		a.met.SourceListDuration(name, time.Since(t0))
		if err != nil {
			mark(name)
			a.logChange(ctx, "source/"+name, "error", fmt.Sprintf("source %s is unavailable; its services are treated as unknown (nothing is removed): %v", name, err))
			a.notifySource(ctx, name)
			continue
		}
		if w, ok := sp.Source.(interface{ Warnings() []string }); ok {
			ws := w.Warnings()
			msg := ""
			if len(ws) > 0 {
				msg = fmt.Sprintf("source %s: %s", name, strings.Join(ws, "; "))
			}
			a.logChange(ctx, "warnings/"+name, "warn", msg)
		}
		svcs = a.dedupe(ctx, name, svcs)
		svcs, ls := a.applyOverrides(ctx, name, svcs, ovs, bad)
		mode := sp.Mode
		if mode == "" {
			mode = approval.ModeAuto
		}
		rd, err := a.gate.ResolveDetail(ctx, mode, svcs, opt)
		res := rd.Services
		if err != nil {
			// Its approvals could not be loaded: its services would look
			// absent and be removed. Unknown instead.
			for _, s := range svcs {
				a.alias(name, s.Source)
			}
			mark(name)
			a.logChange(ctx, "source/"+name, "error", fmt.Sprintf("source %s: approvals could not be loaded; its services are treated as unknown: %v", name, err))
			continue
		}
		for _, s := range svcs {
			a.alias(name, s.Source)
		}
		if !dry { // dry run writes no approval; its plan shows them served
			for _, k := range rd.Migrated {
				a.appendActivity(ctx, "info", "approval", "service "+k+": migrated approval v1->v2 (the approved content is unchanged and is what its route serves; the approval now also covers the backend and the middleware order)")
			}
			for _, k := range rd.Grandfathered {
				a.appendActivity(ctx, "info", "approval", "service "+k+": grandfathered on mode switch (approved as it was already served: no approval was stored and its content equals its route)")
			}
		}
		for k := range rd.Quarantined {
			quarantined[k] = true
		}
		for i := range ls {
			ls[i].state = stateOf(res, ls[i].svc, mode)
		}
		listing = append(listing, ls...)
		up[name] = true
		a.met.SourceUp(name, true)
		a.logChange(ctx, "source/"+name, "info", "")
		desired = append(desired, res...)
	}
	return desired, up, quarantined
}

// approvalOptions gives the gate what each persisted route serves, so a
// legacy approval migrates and a served unapproved service is
// grandfathered only for unchanged content.
func (a *App) approvalOptions(ctx context.Context, dry bool) (approval.Options, error) {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	routes, err := a.st.ListRoutes(sctx)
	if err != nil {
		return approval.Options{}, err
	}
	o := approval.Options{DryRun: dry, Served: make(map[string]approval.Served, len(routes))}
	for _, r := range routes {
		o.Served[r.Key] = approval.Served{Hostname: r.Hostname, Websockets: r.Websockets, Middlewares: r.Middlewares,
			Quarantined: r.Quarantined, Backend: model.Backend{Scheme: r.Scheme, Host: r.Host, Port: r.Port, SkipVerify: r.SkipVerify}}
	}
	zs, dz := a.zoneNames()
	o.Hostname = func(s model.Service) string {
		h, err := model.Hostname(s, zs, dz)
		if err != nil {
			return ""
		}
		return h
	}
	return o, nil
}

func (a *App) alias(name, src string) {
	if src == "" {
		return
	}
	m := a.aliases[name]
	if m == nil {
		m = map[string]bool{}
		a.aliases[name] = m
	}
	m[src] = true
}

// dedupe keeps the last occurrence of each key (Plan's and the gate's rule)
// and reports the dropped ones.
func (a *App) dedupe(ctx context.Context, src string, svcs []model.Service) []model.Service {
	last := map[string]int{}
	for i, s := range svcs {
		last[s.Key] = i
	}
	if len(last) == len(svcs) {
		return svcs
	}
	out := make([]model.Service, 0, len(last))
	var dropped []string
	for i, s := range svcs {
		if last[s.Key] == i {
			out = append(out, s)
		} else {
			dropped = append(dropped, s.Key)
		}
	}
	sort.Strings(dropped)
	a.logChange(ctx, "dupes/"+src, "warn", fmt.Sprintf("source %s returned duplicate service keys; the last occurrence of each is used: %s",
		src, strings.Join(dropped, ", ")))
	return out
}

// observe builds Observed: Known/LastKnown from routes, certs, and the DNS
// observation. An error reading routes or certs fails the cycle.
func (a *App) observe(ctx context.Context, now time.Time, unavailable map[string]bool) (reconcile.Observed, error) {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	routes, err := a.st.ListRoutes(sctx)
	if err != nil {
		return reconcile.Observed{}, fmt.Errorf("reading routes: %w", err)
	}
	certs, err := a.st.ListCerts(sctx)
	if err != nil {
		return reconcile.Observed{}, fmt.Errorf("reading certificates: %w", err)
	}
	known, lastKnown := reconcile.ObservedFromRoutes(routes)
	obs := reconcile.Observed{Known: known, LastKnown: lastKnown, Certs: certs, Unavailable: unavailable}
	dobs, derrs := reconcile.GatherObservedAt(ctx, a.providers, a.st, reconcile.DNSZoneRefs(a.cfg), a.dnsTO, now)
	dobs.Fill(&obs)
	msg := ""
	if len(derrs) > 0 {
		msg = fmt.Sprintf("DNS observation incomplete; no record is created where the listing failed: %v", errors.Join(derrs...))
	}
	// The listings themselves are counted by meteredProvider.
	a.logChange(ctx, "dns-observe", "warn", msg)
	return obs, nil
}

// backendOf is s's backend as scheme://host:port ("" for nil).
func backendOf(s *model.Service) string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%s://%s:%d", s.Backend.Scheme, s.Backend.Host, s.Backend.Port)
}

// countAndAlert counts the plan's actions per kind and notifies an operator
// of every Alert (and of hostname/DNS conflicts), deduplicated by key; a
// Published service gone Invalid while it holds its route
// (AlertPublishedInvalid) is notified once per reason.
func (a *App) countAndAlert(ctx context.Context, acts []reconcile.Action) {
	n := map[reconcile.ActionKind]int{}
	var skipped map[string]bool
	for _, x := range acts {
		n[x.Kind]++
		if id := web.ConflictID(x); id != "" && x.Alert == "" {
			if skipped == nil {
				skipped = a.skippedConflicts(ctx)
			}
			if skipped[id] {
				continue // the operator chose to ignore this DNS conflict
			}
		}
		switch {
		case x.Alert == reconcile.AlertQuarantined:
			// Planned every quarantined cycle; the key (per backend)
			// suppresses repeats and lets a dropped one be retried.
			a.notify(ctx, notify.Event{Kind: "service.quarantined", Severity: notify.Warning,
				Subject: "doorwarden: " + x.Key + " changed; re-approve to resume", Message: x.Reason,
				Fields:    map[string]string{"key": x.Key, "zone": x.Zone, "host": x.Host},
				DedupeKey: "quarantined/" + x.Key + "/" + backendOf(x.Svc)})
		case x.Alert == reconcile.AlertPublishedInvalid:
			a.notify(ctx, notify.Event{Kind: "service.invalid", Severity: notify.Warning,
				Subject: "doorwarden: " + x.Key + " has invalid labels", Message: x.Reason,
				Fields:    map[string]string{"key": x.Key, "zone": x.Zone, "host": x.Host},
				DedupeKey: invalidDedupeKey(x.Key, x.Reason)})
		case x.Alert != "":
			a.notify(ctx, notify.Event{Kind: "dns.alert", Severity: notify.Critical,
				Subject: "doorwarden: " + x.Alert, Message: x.Reason,
				Fields:    map[string]string{"alert": x.Alert, "provider": x.Provider, "zone": x.Zone},
				DedupeKey: x.Alert + "/" + x.Key})
		case x.Kind == reconcile.Conflict:
			a.notify(ctx, notify.Event{Kind: "conflict", Severity: notify.Warning,
				Subject: "doorwarden: conflict for " + x.Host, Message: x.Reason,
				Fields:    map[string]string{"key": x.Key, "zone": x.Zone, "host": x.Host},
				DedupeKey: "conflict/" + x.Key + "/" + x.Host + "/" + x.Reason})
		}
	}
	for k, c := range n {
		a.met.ReconcileAction(string(k), c)
	}
}

// invalidDedupeKey is the dedupe key of a held-invalid notification: the
// service key plus a short hash of the reason's sorted words, so the same
// problems reported in a different order (map iteration) are not notified
// again, while a different problem is.
func invalidDedupeKey(key, reason string) string {
	words := strings.FieldsFunc(reason, func(r rune) bool {
		return r == ' ' || r == ';' || r == ',' || r == '(' || r == ')' || r == ':' || r == '\n'
	})
	sort.Strings(words)
	sum := sha256.Sum256([]byte(strings.Join(words, " ")))
	return "invalid/" + key + "/" + hex.EncodeToString(sum[:8])
}

// notify sends e to the operator; in a dry-run cycle nothing goes out (the
// event is logged; the activity log already has it).
func (a *App) notify(ctx context.Context, e notify.Event) {
	if a.notifier == nil {
		return
	}
	if a.cycleDry.Load() {
		a.log.InfoContext(ctx, "dry run: notification not sent", "kind", e.Kind, "subject", e.Subject)
		return
	}
	if e.At.IsZero() {
		e.At = a.now()
	}
	if err := a.notifier.Notify(ctx, e); err != nil {
		a.log.WarnContext(ctx, "notification not queued", "kind", e.Kind, "error", err)
	}
}

func (a *App) notifySource(ctx context.Context, name string) {
	a.notify(ctx, notify.Event{Kind: "source.unavailable", Severity: notify.Warning,
		Subject: "doorwarden: source " + name + " unavailable",
		Message: "Source " + name + " could not be listed; its services are kept as they are until it is back.",
		Fields:  map[string]string{"source": name}, DedupeKey: "source.unavailable/" + name})
}

// persistServices records the gate's output in the services table (state
// and last seen). Not in dry run.
func (a *App) persistServices(ctx context.Context, desired []model.Service, now time.Time) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	var errs []error
	for _, s := range desired {
		if err := a.st.TouchService(sctx, s.Key, s.Source, s.State, now); err != nil {
			errs = append(errs, err)
		}
	}
	msg := ""
	if len(errs) > 0 {
		msg = fmt.Sprintf("recording service states failed: %v", errors.Join(errs...))
	}
	a.logChange(ctx, "services", "warn", msg)
}

// recordActivity is the MultiExecutor's ActivityFunc. An action whose
// outcome (kind, target, reason, error, dry run) is the same as in the
// previous cycle is not recorded again; everything new is written to the
// activity log and logged (Invalid, Conflict, Skip and errors at warn).
func (a *App) recordActivity(ctx context.Context, x reconcile.Action, dryRun bool, err error) {
	sig := actionSig(x, dryRun, err)
	a.seenCur[sig] = true
	if a.seenPrev[sig] {
		return
	}
	level := "info"
	switch {
	case err != nil:
		level = "error"
	case x.Alert != "":
		level = "error"
	case reconcile.Informational(x.Kind):
		level = "warn"
	}
	msg := describeAction(x)
	if dryRun {
		msg = "dry run: would " + msg
	}
	if err != nil {
		msg += ": " + err.Error()
	}
	a.appendActivity(ctx, level, "reconcile", msg)
}

func actionSig(x reconcile.Action, dryRun bool, err error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%t|%s|%s|%s|%s|%s|%s|%s|%s|%s", dryRun, x.Kind, x.Key, x.Zone, x.Host, x.Provider, x.Owner, x.NewOwner, x.Reason, x.Alert)
	if x.Backend != nil {
		fmt.Fprintf(&b, "|%s://%s:%d/%t", x.Backend.Scheme, x.Backend.Host, x.Backend.Port, x.Backend.SkipVerify)
	}
	if x.Record != nil {
		fmt.Fprintf(&b, "|%s %s %s", x.Record.Name, x.Record.Type, x.Record.Value)
	}
	if len(x.Names) > 0 {
		b.WriteString("|" + strings.Join(x.Names, ","))
	}
	if err != nil {
		b.WriteString("|err:" + err.Error())
	}
	return b.String()
}

func describeAction(x reconcile.Action) string {
	var b strings.Builder
	b.WriteString(string(x.Kind))
	if x.Host != "" {
		b.WriteString(" " + x.Host)
	}
	if x.Key != "" {
		b.WriteString(" (" + x.Key + ")")
	}
	if x.Backend != nil && x.Kind == reconcile.RouteWrite {
		fmt.Fprintf(&b, " -> %s://%s:%d", x.Backend.Scheme, x.Backend.Host, x.Backend.Port)
	}
	if x.Record != nil {
		fmt.Fprintf(&b, " %s %s", x.Record.Type, x.Record.Value)
	}
	if len(x.Names) > 0 {
		b.WriteString(" [" + strings.Join(x.Names, ", ") + "]")
	}
	if x.Reason != "" {
		b.WriteString(": " + x.Reason)
	}
	return b.String()
}

// appendActivity writes one activity entry and logs it.
func (a *App) appendActivity(ctx context.Context, level, kind, msg string) {
	switch level {
	case "error":
		a.log.ErrorContext(ctx, msg, "kind", kind)
	case "warn":
		a.log.WarnContext(ctx, msg, "kind", kind)
	default:
		a.log.InfoContext(ctx, msg, "kind", kind)
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := a.st.AppendActivity(sctx, store.ActivityEntry{TS: a.now(), Level: level, Kind: kind, Message: msg}); err != nil {
		a.log.WarnContext(ctx, "recording activity failed", "error", err)
	}
}

// logChange records msg (activity + log) under topic when it differs from
// the topic's previous message; an empty msg clears the topic (a recovery
// after a non-empty one is recorded at info).
func (a *App) logChange(ctx context.Context, topic, level, msg string) {
	prev := a.lastLogged[topic]
	if prev == msg {
		return
	}
	a.lastLogged[topic] = msg
	if msg == "" {
		if prev != "" {
			a.appendActivity(ctx, "info", "app", "resolved: "+topic)
		}
		return
	}
	if level == "" {
		level = "info"
	}
	a.appendActivity(ctx, level, "app", msg)
}
