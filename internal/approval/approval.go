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
// rename, zone, backend scheme, skip-verify, websockets, sorted middlewares).
// Backend host and port are deliberately excluded because Docker host ports
// change on every restart. If the content changes (e.g. an auth middleware is
// dropped) the stored approval no longer applies and the service is Pending
// again until re-approved. A service that disappears and returns unchanged
// stays approved.
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
	"sort"
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
	mw := append([]string{}, s.Options.Middlewares...)
	sort.Strings(mw)
	b, _ := json.Marshal([]any{s.Key, s.Name, s.Options.Rename, s.Zone,
		s.Backend.Scheme, s.Backend.SkipVerify, s.Options.Websockets, mw})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Resolve returns svcs with their State decided; see the package comment.
// Services dropped by Skip or ModeOff are not part of the snapshot, so they
// cannot be approved.
func (g *Gate) Resolve(ctx context.Context, mode Mode, svcs []model.Service) ([]model.Service, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if mode != ModeAuto && mode != ModeApprove && mode != ModeOff {
		return nil, fmt.Errorf("approval: unknown mode %q", mode)
	}
	var approved map[string]string
	if mode == ModeApprove {
		var err error
		if approved, err = g.st.ListApprovals(ctx); err != nil {
			return nil, err // snapshot untouched
		}
	}
	if mode == ModeOff {
		return nil, nil
	}
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
		if mode == ModeAuto {
			s.State = model.StatePublished
		} else if stored, ok := approved[s.Key]; ok && stored == fp {
			s.State = model.StatePublished
		} else {
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
	return out, nil
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
