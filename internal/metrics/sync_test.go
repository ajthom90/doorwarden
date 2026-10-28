package metrics_test

import (
	"sort"
	"testing"

	"github.com/ajthom90/doorwarden/internal/metrics"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/reconcile"
)

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	a, b = sorted(a), sorted(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The closed label sets must track the real constants.
func TestLabelSetsMatchRealConstants(t *testing.T) {
	var kinds []string
	for _, k := range reconcile.KindOrder {
		kinds = append(kinds, string(k))
	}
	// every declared kind constant must be in KindOrder (guards a new kind
	// added to the const block but not to KindOrder)
	for _, k := range []reconcile.ActionKind{reconcile.Invalid, reconcile.Conflict, reconcile.Skip, reconcile.CancelRemoval,
		reconcile.ScheduleRemoval, reconcile.DNSEnsure, reconcile.CertEnsure, reconcile.RouteWrite, reconcile.RouteRemove, reconcile.DNSDelete,
		reconcile.DNSScheduleRemoval, reconcile.DNSCancelRemoval} {
		found := false
		for _, o := range kinds {
			found = found || o == string(k)
		}
		if !found {
			t.Errorf("%s missing from reconcile.KindOrder", k)
		}
	}
	if !equal(metrics.ActionKinds(), kinds) {
		t.Errorf("metrics action kinds %v != reconcile %v", sorted(metrics.ActionKinds()), sorted(kinds))
	}
	states := []string{model.StateDiscovered, model.StatePending, model.StatePublished, model.StateConflict,
		model.StateError, model.StateStopped, model.StateRemoved}
	if !equal(metrics.ServiceStates(), states) {
		t.Errorf("metrics states %v != model %v", sorted(metrics.ServiceStates()), sorted(states))
	}
}
