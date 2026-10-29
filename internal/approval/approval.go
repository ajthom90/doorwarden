// Package approval decides which discovered services are published.
//
// Modes: auto publishes everything, approve publishes only services a human
// approved (the rest are Pending), off drops everything. Options.Skip always
// wins. Services already Stopped or Error keep that state in every mode: they
// carry no authoritative backend and must not trigger changes.
//
// Persistence: approvals live in their own store table (approvals), never in
// the services table, so reconciler writes cannot clobber them. The Gate does
// not write services at all; the reconciler owns that table and records state
// from Resolve's output.
//
// An approval is bound to a fingerprint of the approved content (key, name,
// rename, zone, backend scheme, host and port, skip-verify, websockets, and
// the middlewares IN ORDER, since the renderer applies them in order). The
// backend is included for every source (final-review H2/H3, fail safe): a
// source reporting another host or port, or reordered middlewares, makes the
// service Pending again until re-approved. Consequence: a Docker container
// in approve mode whose published host port changes on restart needs
// re-approval (pin the host port, or use auto mode for docker). If the
// content changes (e.g. an auth middleware is dropped) the stored approval no
// longer applies. A service that disappears and returns unchanged stays
// approved. Reapprove carries an approval over to content an administrator
// changed through a UI override (the admin is the authority).
//
// Quarantine: in approve mode, a service whose stored approval no longer
// matches its content (a backend or middleware change reported by the
// source after it was approved) is Pending and reported in
// Result.Quarantined; the stored approval is kept as it is. The caller
// stops serving it while its hostname stays reserved, and an Approve of
// the new content resumes it. A service with no stored approval is only
// Pending. Auto mode never reads approvals, so never quarantines.
//
// Legacy approvals: approvals stored before the backend and the
// middleware order were fingerprinted carry FingerprintV1. A v1 approval
// equal to FingerprintV1 of the current content is rewritten to
// Fingerprint (Result.Migrated; the caller records "migrated approval
// v1->v2") only if the service also still serves what its persisted route
// serves (Options.Served: hostname, backend scheme, host, port and
// skip-verify, websockets, and the middlewares in order), since v1 covered
// neither the backend nor the order. Any other v1 approval is treated as
// changed content (Pending, quarantined).
//
// Grandfathering: in approve mode, a service with no stored approval but
// with a persisted route (its source was switched from auto to approve, or
// its approval row was lost) is approved for its current content
// (Result.Grandfathered; the caller records "grandfathered on mode switch")
// if that content equals what the route serves, and quarantined otherwise.
// A service that never had a route is only Pending.
//
// Options.DryRun: no approval is written. A service that would be migrated
// or grandfathered is Published as it would be and still reported.
//
// Approve takes the fingerprint of the service the caller displayed and only
// stores the approval if it still equals the Gate's snapshot (ErrStale
// otherwise), so a service that changed after it was shown cannot be approved
// by accident. Fingerprints returns the values to show and echo back.
//
// The snapshot is additive: each Resolve overwrites the entries for the keys it
// saw and never wipes other keys, so a reconciler may call Resolve once per
// source and every source's services stay approvable. ModeOff leaves it alone.
// Skip'd, Stopped and Error services are removed from the snapshot (they
// cannot be approved). Entries for services that have since disappeared are
// harmless, since Approve always validates the fingerprint, but are not
// garbage-collected; that is the reconciler's job (a later task). A key never
// seen by Resolve returns ErrUnknownService.
package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/ajthom90/doorwarden/internal/model"
)

// Mode is the approval mode (matches config approval values).
type Mode string

const (
	ModeAuto    Mode = "auto"
	ModeApprove Mode = "approve"
	ModeOff     Mode = "off"
)

// ErrUnknownService means the key was never seen by Resolve (or cannot be approved).
var ErrUnknownService = errors.New("unknown service")

// ErrStale means the fingerprint does not match the service as last resolved.
var ErrStale = errors.New("stale fingerprint")

// Store is the persistence the gate needs; *store.Store satisfies it.
type Store interface {
	SetApproval(ctx context.Context, key, fingerprint string) error
	ClearApproval(ctx context.Context, key string) error
	ListApprovals(ctx context.Context) (map[string]string, error)
}

// Gate applies approval decisions. It is safe for concurrent use.
type Gate struct {
	mu   sync.Mutex
	st   Store
	snap map[string]string // key -> fingerprint, additive across Resolve calls
}

// NewGate returns a Gate backed by st.
func NewGate(st Store) *Gate { return &Gate{st: st, snap: map[string]string{}} }

// Fingerprint returns the content fingerprint an approval is bound to. It is
// the value a UI must echo back to Approve for the service it displayed.
func Fingerprint(s model.Service) string {
	mw := append([]string{}, s.Options.Middlewares...) // order matters
	b, _ := json.Marshal([]any{"v2", s.Key, s.Name, s.Options.Rename, s.Zone,
		s.Backend.Scheme, s.Backend.Host, s.Backend.Port, s.Backend.SkipVerify, s.Options.Websockets, mw})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FingerprintV1 is the legacy fingerprint (before final-review H2/H3): no
// backend host or port, middlewares sorted. Only Resolve's one-time
// migration uses it.
func FingerprintV1(s model.Service) string {
	mw := append([]string{}, s.Options.Middlewares...)
	sort.Strings(mw)
	b, _ := json.Marshal([]any{s.Key, s.Name, s.Options.Rename, s.Zone,
		s.Backend.Scheme, s.Backend.SkipVerify, s.Options.Websockets, mw})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Result is ResolveDetail's output.
type Result struct {
	// Services are the input services with their State decided.
	Services []model.Service
	// Quarantined are the Pending keys whose stored approval no longer
	// matches their content (approve mode only).
	Quarantined map[string]bool
	// Migrated are the keys whose v1 approval was rewritten to v2 (in dry
	// run: would be).
	Migrated []string
	// Grandfathered are the keys approved because their unchanged content
	// was already served without an approval (in dry run: would be).
	Grandfathered []string
}

// Served is what a key's persisted route serves.
type Served struct {
	Hostname    string
	Backend     model.Backend
	Websockets  bool
	Middlewares []string
	// Quarantined: the route is withdrawn, so it serves nothing and never
	// grandfathers.
	Quarantined bool
}

// Options are ResolveDetail's inputs besides the services.
type Options struct {
	// DryRun: never write an approval.
	DryRun bool
	// Served is what each persisted route serves, by key.
	Served map[string]Served
	// Hostname returns the hostname a service resolves to ("" if none);
	// nil skips the hostname comparison.
	Hostname func(model.Service) string
}

// servesSame reports whether s, as it is now, is exactly what its persisted
// route serves; false without a route or with a quarantined one.
func (o Options) servesSame(s model.Service) bool {
	r, ok := o.Served[s.Key]
	if !ok || r.Quarantined {
		return false
	}
	if o.Hostname != nil && !strings.EqualFold(strings.TrimSuffix(o.Hostname(s), "."), strings.TrimSuffix(r.Hostname, ".")) {
		return false
	}
	a, b := s.Backend, r.Backend
	if !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(model.UnbracketHost(a.Host), model.UnbracketHost(b.Host)) ||
		a.Port != b.Port || a.SkipVerify != b.SkipVerify || s.Options.Websockets != r.Websockets {
		return false
	}
	return slices.Equal(s.Options.Middlewares, r.Middlewares)
}

// Resolve returns svcs with their State decided; see the package comment.
// Services dropped by Skip or ModeOff are not part of the snapshot, so they
// cannot be approved. It knows no persisted routes, so it never migrates or
// grandfathers.
func (g *Gate) Resolve(ctx context.Context, mode Mode, svcs []model.Service) ([]model.Service, error) {
	r, err := g.ResolveDetail(ctx, mode, svcs, Options{})
	return r.Services, err
}

// ResolveDetail is Resolve that also migrates, grandfathers and reports
// quarantined keys (see the package comment). A failed approval write
// leaves the service Pending (not quarantined); it is retried at the next
// Resolve.
func (g *Gate) ResolveDetail(ctx context.Context, mode Mode, svcs []model.Service, opt Options) (Result, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if mode != ModeAuto && mode != ModeApprove && mode != ModeOff {
		return Result{}, fmt.Errorf("approval: unknown mode %q", mode)
	}
	var approved map[string]string
	if mode == ModeApprove {
		var err error
		if approved, err = g.st.ListApprovals(ctx); err != nil {
			return Result{}, err // snapshot untouched
		}
	}
	if mode == ModeOff {
		return Result{}, nil
	}
	res := Result{Quarantined: map[string]bool{}}
	seen := map[string]string{} // key -> fingerprint; "" = not approvable
	var out []model.Service
	for _, s := range svcs {
		if s.Options.Skip {
			seen[s.Key] = ""
			continue
		}
		if s.State == model.StateStopped || s.State == model.StateError {
			seen[s.Key] = ""
			out = append(out, s)
			continue
		}
		fp := Fingerprint(s)
		seen[s.Key] = fp
		stored, has := approved[s.Key]
		switch {
		case mode == ModeAuto:
			s.State = model.StatePublished
		case has && stored == fp:
			s.State = model.StatePublished
		case has && stored == FingerprintV1(s) && opt.servesSame(s):
			if g.record(ctx, &s, fp, opt.DryRun) {
				res.Migrated = append(res.Migrated, s.Key)
			}
		case has:
			s.State = model.StatePending
			res.Quarantined[s.Key] = true
		case hasServed(opt, s.Key):
			if !opt.servesSame(s) {
				s.State = model.StatePending
				res.Quarantined[s.Key] = true
			} else if g.record(ctx, &s, fp, opt.DryRun) {
				res.Grandfathered = append(res.Grandfathered, s.Key)
			}
		default:
			s.State = model.StatePending
		}
		out = append(out, s)
	}
	for k, fp := range seen {
		if fp == "" {
			delete(g.snap, k)
		} else {
			g.snap[k] = fp
		}
	}
	res.Services = out
	return res, nil
}

// record approves s's current content fp (no write in dry run) and makes s
// Published; on a failed write s is Pending and false is returned.
func (g *Gate) record(ctx context.Context, s *model.Service, fp string, dry bool) bool {
	if !dry {
		if err := g.st.SetApproval(ctx, s.Key, fp); err != nil {
			s.State = model.StatePending
			return false
		}
	}
	s.State = model.StatePublished
	return true
}

func hasServed(o Options, key string) bool {
	_, ok := o.Served[key]
	return ok
}

// Fingerprints returns a copy of the snapshot (key -> fingerprint).
func (g *Gate) Fingerprints() map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]string, len(g.snap))
	for k, v := range g.snap {
		out[k] = v
	}
	return out
}

// Approve persists approval of key, provided fingerprint matches the snapshot.
func (g *Gate) Approve(ctx context.Context, key, fingerprint string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	fp, ok := g.snap[key]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownService, key)
	}
	if fingerprint != fp {
		return fmt.Errorf("%w: %q changed since it was displayed", ErrStale, key)
	}
	return g.st.SetApproval(ctx, key, fp)
}

// Reapprove moves the approval of key from the content fingerprinted oldFP to
// newFP, for a change an administrator made (a UI override). It does so only
// when the stored approval is exactly oldFP, i.e. the content before the
// change was approved; otherwise nothing is stored and ok is false (an
// override never approves content nobody approved). The snapshot entry is
// updated so the UI can show and approve the new content at once.
func (g *Gate) Reapprove(ctx context.Context, key, oldFP, newFP string) (ok bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cur, err := g.st.ListApprovals(ctx)
	if err != nil {
		return false, err
	}
	if stored, has := cur[key]; !has || stored != oldFP || oldFP == "" || newFP == "" {
		return false, nil
	}
	if oldFP == newFP {
		return true, nil
	}
	if err := g.st.SetApproval(ctx, key, newFP); err != nil {
		return false, err
	}
	if _, seen := g.snap[key]; seen {
		g.snap[key] = newFP
	}
	return true, nil
}

// Revoke removes any approval for key; it is a no-op if there is none.
func (g *Gate) Revoke(ctx context.Context, key string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	cur, err := g.st.ListApprovals(ctx)
	if err != nil {
		return err
	}
	if _, ok := cur[key]; !ok {
		return nil
	}
	return g.st.ClearApproval(ctx, key)
}
