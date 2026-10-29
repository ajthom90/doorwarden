package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
)

// ErrNoExecutor is returned when a non-informational action has no executor.
var ErrNoExecutor = errors.New("reconcile: no executor for action kind")

// Executor applies a plan.
//
// Dry-run contract: with dryRun true an executor records activity and calls
// no provider, writes no file and persists nothing. MultiExecutor enforces
// this by never dispatching in dry run.
//
// Apply calls are serialized by the caller (Runner holds a mutex); executors
// need not be safe for concurrent Apply calls.
type Executor interface {
	Apply(ctx context.Context, actions []Action, dryRun bool) error
}

// ExecutorFunc adapts a function to Executor.
type ExecutorFunc func(ctx context.Context, actions []Action, dryRun bool) error

// Apply calls f.
func (f ExecutorFunc) Apply(ctx context.Context, actions []Action, dryRun bool) error {
	return f(ctx, actions, dryRun)
}

// ActivityFunc records one action's outcome (err is nil in dry run and on
// success).
type ActivityFunc func(ctx context.Context, a Action, dryRun bool, err error)

// MultiExecutor dispatches actions to per-kind executors. Consecutive actions
// of the same kind are passed as one batch, in plan order. A failing batch
// does not stop later batches (the loop is level-triggered and retries next
// cycle); all errors are joined. Informational kinds (Invalid, Conflict, Skip)
// are only recorded unless an executor is registered for them.
type MultiExecutor struct {
	handlers map[ActionKind]Executor
	activity ActivityFunc
}

// NewMultiExecutor returns an executor recording through activity (may be nil).
func NewMultiExecutor(activity ActivityFunc) *MultiExecutor {
	return &MultiExecutor{handlers: map[ActionKind]Executor{}, activity: activity}
}

// Handle registers e for kind k and returns m. Not safe to call concurrently
// with Apply; register everything at construction.
func (m *MultiExecutor) Handle(k ActionKind, e Executor) *MultiExecutor {
	m.handlers[k] = e
	return m
}

func (m *MultiExecutor) record(ctx context.Context, as []Action, dryRun bool, err error) {
	if m.activity == nil {
		return
	}
	for _, a := range as {
		m.activity(ctx, a, dryRun, err)
	}
}

// Apply implements Executor.
func (m *MultiExecutor) Apply(ctx context.Context, actions []Action, dryRun bool) error {
	if dryRun {
		m.record(ctx, actions, true, nil)
		return nil
	}
	var errs []error
	for start := 0; start < len(actions); {
		end := start + 1
		for end < len(actions) && actions[end].Kind == actions[start].Kind {
			end++
		}
		batch := actions[start:end]
		start = end
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		k := batch[0].Kind
		h, ok := m.handlers[k]
		if !ok {
			if Informational(k) {
				m.record(ctx, batch, false, nil)
				continue
			}
			err := fmt.Errorf("%w: %s", ErrNoExecutor, k)
			m.record(ctx, batch, false, err)
			errs = append(errs, err)
			continue
		}
		err := h.Apply(ctx, batch, false)
		if err != nil {
			err = fmt.Errorf("%s: %w", k, err)
			errs = append(errs, err)
		}
		m.record(ctx, batch, false, err)
	}
	m.finish(ctx)
	return errors.Join(errs...)
}

// Finisher is an optional hook of a registered Executor: MultiExecutor
// calls Finish once at the end of every non-dry Apply (each distinct
// executor once, in sorted kind order of its first registration), whether
// or not the plan had an action for it. Never in dry run. The DNS executor
// uses it to clear mass-repair acknowledgements of recovered zones.
type Finisher interface {
	Finish(ctx context.Context)
}

func (m *MultiExecutor) finish(ctx context.Context) {
	kinds := make([]string, 0, len(m.handlers))
	for k := range m.handlers {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)
	done := map[any]bool{}
	for _, k := range kinds {
		h := m.handlers[ActionKind(k)]
		f, ok := h.(Finisher)
		if !ok {
			continue
		}
		if reflect.ValueOf(h).Comparable() {
			if done[h] {
				continue
			}
			done[h] = true
		}
		f.Finish(ctx)
	}
}

// RecordedCall is one Apply call seen by a Recorder.
type RecordedCall struct {
	Actions []Action
	DryRun  bool
}

// Recorder is an Executor that only remembers what it was asked to do. It
// is safe for concurrent use.
type Recorder struct {
	mu    sync.Mutex
	calls []RecordedCall
}

// Apply records the call and returns nil.
func (r *Recorder) Apply(_ context.Context, actions []Action, dryRun bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, RecordedCall{Actions: append([]Action(nil), actions...), DryRun: dryRun})
	return nil
}

// Calls returns a copy of the recorded calls.
func (r *Recorder) Calls() []RecordedCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RecordedCall(nil), r.calls...)
}

// LoggingExecutor logs one line per action and changes nothing. It logs
// selected scalar fields only, never whole structs.
type LoggingExecutor struct{ Log *slog.Logger }

// Apply logs each action.
func (l LoggingExecutor) Apply(ctx context.Context, actions []Action, dryRun bool) error {
	lg := l.Log
	if lg == nil {
		lg = slog.Default()
	}
	for _, a := range actions {
		lg.InfoContext(ctx, "reconcile action", "kind", string(a.Kind), "zone", a.Zone, "host", a.Host,
			"key", a.Key, "provider", a.Provider, "reason", a.Reason, "dry_run", dryRun)
	}
	return nil
}

// Runner plans and applies under a mutex so reconciles never overlap.
// Gathering desired/observed state is the caller's job (later tasks).
type Runner struct {
	Exec   Executor
	Config *config.Config
	// DryRun is the global dry-run toggle; the run is dry if it returns
	// true OR Config.Settings.DryRun is set.
	DryRun func() bool

	mu sync.Mutex
}

// Reconcile computes the plan and applies it. It returns the plan even when
// Apply fails. desired must cover every available source.
func (r *Runner) Reconcile(ctx context.Context, desired []model.Service, obs Observed, now time.Time) ([]Action, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Config == nil || r.Exec == nil {
		return nil, errors.New("reconcile: runner has no config or executor")
	}
	acts := Plan(desired, obs, r.Config, now)
	dry := r.Config.Settings.DryRun || (r.DryRun != nil && r.DryRun())
	return acts, r.Exec.Apply(ctx, acts, dry)
}
