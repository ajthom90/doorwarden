package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ajthom90/doorwarden/internal/reconcile"
)

// CertExecutor applies reconcile CertEnsure actions. Register it with
// reconcile.MultiExecutor.Handle(reconcile.CertEnsure, ...).
//
// Each action is issued synchronously with its own timeout (acme.issue_timeout,
// default 5m); an order that outlives it finishes in the background and is
// persisted. Sets in backoff or parked return a deferred error at once
// without contacting the CA, so the loop's per-cycle CertEnsure (Plan
// re-emits until a covering row exists) never hammers the CA. Panics are
// recovered per action. The strategy comes from the zone's configuration
// (reconcile.Action has none); Action.Names give the names.
type CertExecutor struct {
	m        *Manager
	log      *slog.Logger
	onResult func(Result)
}

// OnResult sets f to receive every issuance result (including deferrals,
// see Result.Err) and returns e. Set it before the first Apply.
func (e *CertExecutor) OnResult(f func(Result)) *CertExecutor {
	e.onResult = f
	return e
}

// NewCertExecutor returns the executor for m.
func NewCertExecutor(m *Manager) *CertExecutor { return &CertExecutor{m: m, log: m.log} }

var _ reconcile.Executor = (*CertExecutor)(nil)

// Apply implements reconcile.Executor. In dry run nothing is issued and
// nothing persisted; the actions are only logged.
func (e *CertExecutor) Apply(ctx context.Context, actions []reconcile.Action, dryRun bool) error {
	var errs []error
	for _, a := range actions {
		if a.Kind != reconcile.CertEnsure {
			errs = append(errs, fmt.Errorf("acme: cert executor cannot apply %s", a.Kind))
			continue
		}
		if dryRun {
			e.log.InfoContext(ctx, "acme: dry run: would ensure certificate", "zone", a.Zone, "names", strings.Join(a.Names, ","))
			continue
		}
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		errs = append(errs, e.apply(ctx, a)...)
	}
	return errors.Join(errs...)
}

func (e *CertExecutor) apply(ctx context.Context, a reconcile.Action) (errs []error) {
	defer func() {
		if p := recover(); p != nil {
			errs = append(errs, errors.New(truncate(e.m.red.redact(fmt.Sprintf("acme: certificate for %s panicked: %v", a.Zone, p)))))
		}
	}()
	ictx, cancel := context.WithTimeout(ctx, e.m.issueTimeout)
	defer cancel()
	for _, r := range e.m.IssueAll(ictx, IssueRequest{Zone: a.Zone, Names: a.Names}) {
		if e.onResult != nil {
			e.onResult(r)
		}
		if r.Err != nil {
			errs = append(errs, fmt.Errorf("certificate %s [%s]: %w", r.CertID, strings.Join(r.Names, ","), r.Err))
		}
	}
	return errs
}
