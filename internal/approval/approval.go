// Package approval decides which discovered services are published.
//
// Modes: auto publishes everything, approve publishes only services a human
// approved (the rest are Pending), off drops everything. Options.Skip always
// wins. Services already Stopped or Error keep that state in every mode: they
// carry no authoritative backend and must not trigger changes.
//
// Persistence: the decision is stored in the services table, in
// overrides_json under the reserved key "approved" (other keys are preserved).
// In approve mode Resolve inserts a Pending row for services the store has not
// seen, so that Approve has a row to mark. Callers that rewrite
// overrides_json for these rows must preserve the "approved" key.
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// Mode is the approval mode (matches config approval values).
type Mode string

const (
	ModeAuto    Mode = "auto"
	ModeApprove Mode = "approve"
	ModeOff     Mode = "off"
)

// approvedKey is the reserved overrides_json key holding the decision.
const approvedKey = "approved"

// ErrUnknownService means no service with that key is known to the store.
var ErrUnknownService = errors.New("unknown service")

// Store is the persistence the gate needs; *store.Store satisfies it.
type Store interface {
	ListServices(ctx context.Context) ([]store.Service, error)
	UpsertService(ctx context.Context, v store.Service) error
}

// Gate applies approval decisions. It is safe for concurrent use.
type Gate struct {
	mu  sync.Mutex
	st  Store
	now func() time.Time
}

// NewGate returns a Gate backed by st.
func NewGate(st Store) *Gate { return &Gate{st: st, now: time.Now} }

func isApproved(overridesJSON string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(overridesJSON), &m) != nil {
		return false
	}
	return string(m[approvedKey]) == "true"
}

func setApproved(overridesJSON string, v bool) (string, error) {
	m := map[string]json.RawMessage{}
	if overridesJSON != "" {
		if err := json.Unmarshal([]byte(overridesJSON), &m); err != nil {
			return "", fmt.Errorf("approval: corrupt overrides_json: %w", err)
		}
		if m == nil {
			m = map[string]json.RawMessage{}
		}
	}
	if v {
		m[approvedKey] = json.RawMessage("true")
	} else {
		delete(m, approvedKey)
	}
	b, err := json.Marshal(m)
	return string(b), err
}

// Resolve returns svcs with their State decided; see the package comment.
func (g *Gate) Resolve(ctx context.Context, mode Mode, svcs []model.Service) ([]model.Service, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if mode == ModeOff {
		return nil, nil
	}
	if mode != ModeAuto && mode != ModeApprove {
		return nil, fmt.Errorf("approval: unknown mode %q", mode)
	}
	known := map[string]store.Service{}
	if mode == ModeApprove {
		rows, err := g.st.ListServices(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			known[r.Key] = r
		}
	}
	var out []model.Service
	for _, s := range svcs {
		if s.Options.Skip {
			continue
		}
		if s.State == model.StateStopped || s.State == model.StateError {
			out = append(out, s)
			continue
		}
		if mode == ModeAuto {
			s.State = model.StatePublished
			out = append(out, s)
			continue
		}
		row, ok := known[s.Key]
		if !ok {
			now := g.now()
			if err := g.st.UpsertService(ctx, store.Service{Key: s.Key, Source: s.Source,
				State: model.StatePending, OverridesJSON: "{}", FirstSeen: now, LastSeen: now}); err != nil {
				return nil, err
			}
		}
		if ok && isApproved(row.OverridesJSON) {
			s.State = model.StatePublished
		} else {
			s.State = model.StatePending
		}
		out = append(out, s)
	}
	return out, nil
}

// Approve persists approval for key. The key must already be known to the store.
func (g *Gate) Approve(ctx context.Context, key string) error { return g.set(ctx, key, true) }

// Revoke removes the approval for key, returning it to Pending.
func (g *Gate) Revoke(ctx context.Context, key string) error { return g.set(ctx, key, false) }

func (g *Gate) set(ctx context.Context, key string, v bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	rows, err := g.st.ListServices(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.Key != key {
			continue
		}
		js, err := setApproved(r.OverridesJSON, v)
		if err != nil {
			return err
		}
		r.OverridesJSON = js
		return g.st.UpsertService(ctx, r)
	}
	return fmt.Errorf("%w: %q", ErrUnknownService, key)
}
