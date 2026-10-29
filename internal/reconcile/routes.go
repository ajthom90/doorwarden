package reconcile

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// RouteStore is the persisted route set (*store.Store implements it). The
// Traefik writer renders from it, and ObservedFromRoutes builds the plan's
// Known and LastKnown from it.
type RouteStore interface {
	UpsertRoute(ctx context.Context, r store.Route) error
	DeleteRoute(ctx context.Context, key string) error
	// DeleteRouteIfDue deletes key's route only if its removed_after is set
	// and strictly before notAfter.
	DeleteRouteIfDue(ctx context.Context, key string, notAfter time.Time) (bool, error)
	SetRouteRemoval(ctx context.Context, key string, at *time.Time) error
	// QuarantineRoute keeps key's route but stops it being rendered
	// (store.ErrRouteNotFound when absent).
	QuarantineRoute(ctx context.Context, key string) error
	ListRoutes(ctx context.Context) ([]store.Route, error)
}

// NewRouteExecutor returns the executor that maintains the persisted route
// set. Register it in a MultiExecutor for RouteWrite, RouteRemove,
// ScheduleRemoval and CancelRemoval; other kinds are ignored.
//
//   - RouteWrite for a service whose State is not Published is a no-op: the
//     persisted set already holds the route as last written, and a Stopped
//     or Error service's labels (name, middlewares, websockets) are not
//     trustworthy. Otherwise it upserts the route for Action.Key from
//     Action.Zone/Host, Action.Svc (Source; Options.Websockets and
//     Options.Middlewares) and Action.Backend (Scheme, Host, Port,
//     SkipVerify). Backend is required: a nil Backend or Svc, or a backend
//     failing model.ValidateBackend (store.ErrInvalidRoute) is an error and
//     nothing is written. A scheduled removal is preserved.
//   - RouteRemove deletes the route (absent is not an error). It is the ONLY
//     way a route leaves the set. With Cause CauseRemovalGrace (or no Cause)
//     the route is deleted only if its stored removed_after is still set
//     and in the past at now (store.DeleteRouteIfDue): a plan computed from
//     a stale Observed never removes a route whose removal a newer cycle
//     cancelled (or re-scheduled to a later time); otherwise nothing
//     happens. CauseTakeover and CauseRename removals are decided on the
//     current claimants and labels and are applied as planned.
//     CauseQuarantine does not delete the row: it marks it quarantined
//     (store.QuarantineRoute), so it is not rendered while its key stays
//     Known (the hostname's incumbent) and its DNS records and
//     certificates are kept; the next Published RouteWrite clears it.
//   - ScheduleRemoval persists Action.RemovedAfter (required);
//     CancelRemoval clears it. For a key without a route both do nothing
//     (store.ErrRouteNotFound is swallowed): there is nothing to remove.
//
// now stamps UpdatedAt. In dry run nothing is written. Every action of a
// batch is attempted; errors are joined.
func NewRouteExecutor(st RouteStore, now func() time.Time) Executor {
	if now == nil {
		now = time.Now
	}
	return &routeExecutor{st: st, now: now}
}

type routeExecutor struct {
	st  RouteStore
	now func() time.Time
}

func (e *routeExecutor) Apply(ctx context.Context, actions []Action, dryRun bool) error {
	if dryRun {
		return nil
	}
	var errs []error
	for _, a := range actions {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := e.apply(ctx, a); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", a.Kind, a.Key, err))
		}
	}
	return errors.Join(errs...)
}

func (e *routeExecutor) apply(ctx context.Context, a Action) error {
	switch a.Kind {
	case RouteWrite:
		if a.Svc != nil && a.Svc.State != model.StatePublished {
			// Stopped/Error RouteWrites carry the service's CURRENT labels
			// (name, middlewares, ...); only Published may change a route.
			return nil
		}
		r, err := routeFromAction(a, e.now())
		if err != nil {
			return err
		}
		return e.st.UpsertRoute(ctx, r)
	case RouteRemove:
		if a.Cause == CauseQuarantine {
			return ignoreNotFound(e.st.QuarantineRoute(ctx, a.Key))
		}
		if a.Cause == CauseTakeover || a.Cause == CauseRename {
			return e.st.DeleteRoute(ctx, a.Key)
		}
		_, err := e.st.DeleteRouteIfDue(ctx, a.Key, e.now())
		return err
	case ScheduleRemoval:
		if a.RemovedAfter == nil {
			return errors.New("ScheduleRemoval without RemovedAfter")
		}
		at := *a.RemovedAfter
		return ignoreNotFound(e.st.SetRouteRemoval(ctx, a.Key, &at))
	case CancelRemoval:
		return ignoreNotFound(e.st.SetRouteRemoval(ctx, a.Key, nil))
	}
	return nil
}

func ignoreNotFound(err error) error {
	if errors.Is(err, store.ErrRouteNotFound) {
		return nil
	}
	return err
}

func routeFromAction(a Action, now time.Time) (store.Route, error) {
	if a.Backend == nil {
		return store.Route{}, errors.New("RouteWrite without a backend")
	}
	if a.Svc == nil {
		return store.Route{}, errors.New("RouteWrite without a service")
	}
	b := *a.Backend
	return store.Route{ // validated by the store (model.ValidateBackend)
		Key: a.Key, Source: a.Svc.Source, Zone: a.Zone, Hostname: a.Host,
		Scheme: b.Scheme, Host: b.Host, Port: b.Port, SkipVerify: b.SkipVerify,
		Websockets:  a.Svc.Options.Websockets,
		Middlewares: append([]string(nil), a.Svc.Options.Middlewares...),
		UpdatedAt:   now,
	}, nil
}

// ObservedFromRoutes builds Observed.Known and Observed.LastKnown from the
// persisted route set. Every persisted backend is authoritative: only a
// RouteWrite with a real backend can persist a route. A key whose route was
// deleted (RouteRemove applied) is thereby forgotten, as doc.go requires.
// Both maps are non-nil.
func ObservedFromRoutes(routes []store.Route) (known map[string]KnownService, lastKnown map[string]model.Backend) {
	known = make(map[string]KnownService, len(routes))
	lastKnown = make(map[string]model.Backend, len(routes))
	for _, r := range routes {
		var ra *time.Time
		if r.RemovedAfter != nil {
			t := *r.RemovedAfter
			ra = &t
		}
		known[r.Key] = KnownService{Key: r.Key, Source: r.Source, Zone: r.Zone, Hostname: r.Hostname, RemovedAfter: ra,
			Quarantined: r.Quarantined}
		lastKnown[r.Key] = model.Backend{Scheme: r.Scheme, Host: r.Host, Port: r.Port, SkipVerify: r.SkipVerify}
	}
	return known, lastKnown
}
