package approval

import (
	"testing"

	"github.com/ajthom90/doorwarden/internal/model"
)

// servedAs is what a persisted route for s would serve.
func servedAs(s model.Service) Served {
	return Served{Hostname: "h-" + s.Key, Backend: s.Backend, Websockets: s.Options.Websockets,
		Middlewares: append([]string(nil), s.Options.Middlewares...)}
}

func opts(dry bool, served ...model.Service) Options {
	o := Options{DryRun: dry, Served: map[string]Served{},
		Hostname: func(s model.Service) string { return "h-" + s.Key }}
	for _, s := range served {
		o.Served[s.Key] = servedAs(s)
	}
	return o
}

// A v1 approval migrates only when the service still serves what its
// persisted route serves: a long-absent service that returns on another
// port (v1 never covered the port) is changed content, so quarantined.
func TestV1MigratesOnlyWhenServedContentUnchanged(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("docker:a", model.StateDiscovered)
	_ = f.SetApproval(ctx, s.Key, FingerprintV1(s))
	moved := s
	moved.Backend.Port = 8099
	r, err := g.ResolveDetail(ctx, ModeApprove, []model.Service{moved}, opts(false, s))
	if err != nil || r.Services[0].State != model.StatePending || !r.Quarantined[s.Key] || len(r.Migrated) != 0 {
		t.Fatalf("moved: %+v %v", r, err)
	}
	if f.m[s.Key] != FingerprintV1(s) {
		t.Fatal("v1 approval rewritten for a changed backend")
	}
	// reordered middlewares: v1 sorted them, the route has the old order
	re := s
	re.Options.Middlewares = []string{"rl", "auth"}
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{re}, opts(false, s))
	if r.Services[0].State != model.StatePending || !r.Quarantined[s.Key] {
		t.Fatalf("reordered: %+v", r)
	}
	// no persisted route: nothing to verify against
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{s}, opts(false))
	if r.Services[0].State != model.StatePending || !r.Quarantined[s.Key] || len(r.Migrated) != 0 {
		t.Fatalf("no route: %+v", r)
	}
	// another hostname than the route serves
	o := opts(false, s)
	o.Hostname = func(model.Service) string { return "elsewhere" }
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{s}, o)
	if r.Services[0].State != model.StatePending || !r.Quarantined[s.Key] {
		t.Fatalf("renamed: %+v", r)
	}
	// unchanged: migrates
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{s}, opts(false, s))
	if r.Services[0].State != model.StatePublished || len(r.Migrated) != 1 || f.m[s.Key] != Fingerprint(s) {
		t.Fatalf("unchanged: %+v", r)
	}
}

// Dry run never writes an approval: an eligible v1 approval stays v1 (the
// service is Published as it would be) and is reported as migrated.
func TestV1MigrationDryRunWritesNothing(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("docker:a", model.StateDiscovered)
	_ = f.SetApproval(ctx, s.Key, FingerprintV1(s))
	w := f.writes
	r, err := g.ResolveDetail(ctx, ModeApprove, []model.Service{s}, opts(true, s))
	if err != nil || r.Services[0].State != model.StatePublished || len(r.Migrated) != 1 || len(r.Quarantined) != 0 {
		t.Fatalf("dry: %+v %v", r, err)
	}
	if f.writes != w || f.m[s.Key] != FingerprintV1(s) {
		t.Fatal("dry run wrote an approval")
	}
}

// Approve mode, a persisted route and no stored approval (a source switched
// from auto to approve, or a lost approval row): unchanged content is
// grandfathered (approval recorded), changed content is quarantined, and a
// service that never had a route is only Pending. Dry run writes nothing.
func TestGrandfatherServedWithoutApproval(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("docker:a", model.StateDiscovered)
	r, err := g.ResolveDetail(ctx, ModeApprove, []model.Service{s}, opts(true, s))
	if err != nil || r.Services[0].State != model.StatePublished || len(r.Grandfathered) != 1 || f.writes != 0 {
		t.Fatalf("dry: %+v %v writes=%d", r, err, f.writes)
	}
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{s}, opts(false, s))
	if r.Services[0].State != model.StatePublished || len(r.Grandfathered) != 1 || r.Grandfathered[0] != s.Key || f.m[s.Key] != Fingerprint(s) {
		t.Fatalf("grandfather: %+v", r)
	}
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{s}, opts(false, s))
	if len(r.Grandfathered) != 0 || r.Services[0].State != model.StatePublished {
		t.Fatalf("second: %+v", r)
	}

	b := svc("docker:b", model.StateDiscovered)
	moved := b
	moved.Backend.Port = 8099
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{moved}, opts(false, b))
	if r.Services[0].State != model.StatePending || !r.Quarantined[b.Key] || len(r.Grandfathered) != 0 {
		t.Fatalf("changed: %+v", r)
	}
	if _, ok := f.m[b.Key]; ok {
		t.Fatal("changed content approved")
	}

	c := svc("docker:c", model.StateDiscovered)
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{c}, opts(false))
	if r.Services[0].State != model.StatePending || len(r.Quarantined) != 0 || len(r.Grandfathered) != 0 {
		t.Fatalf("never served: %+v", r)
	}
	// a withdrawn (quarantined) route serves nothing: no grandfathering
	d := svc("docker:d", model.StateDiscovered)
	o := opts(false, d)
	sv := o.Served[d.Key]
	sv.Quarantined = true
	o.Served[d.Key] = sv
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{d}, o)
	if r.Services[0].State != model.StatePending || !r.Quarantined[d.Key] || len(r.Grandfathered) != 0 {
		t.Fatalf("quarantined route: %+v", r)
	}
	// auto mode never grandfathers (it needs no approval)
	r, _ = g.ResolveDetail(ctx, ModeAuto, []model.Service{c}, opts(false, c))
	if len(r.Grandfathered) != 0 {
		t.Fatalf("auto: %+v", r)
	}
}
