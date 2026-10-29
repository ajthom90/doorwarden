package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/traefik"
)

// Approve mode: an approved service whose source reports another port is
// quarantined: not rendered, DNS record kept, hostname kept against a
// squatter on the same name, a "re-approve" issue in the UI and exactly one
// notification across cycles. Re-approving resumes serving at once.
func TestApprovedBackendChangeQuarantines(t *testing.T) {
	e := newEnv(t, testYAML)
	app := svc("docker", "app")
	e.src.set(nil, app)
	a := e.app(func(o *Options) { o.Sources = []SourceSpec{{Source: e.src, Mode: approval.ModeApprove}} })
	ctx := context.Background()
	a.RunOnce(ctx)
	if err := a.Approve(ctx, "docker/app", info(t, a, "docker/app").Fingerprint); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	routesFile := filepath.Join(e.dir, traefik.RoutesFile)
	if b, _ := os.ReadFile(routesFile); !strings.Contains(string(b), "app.example.test") {
		t.Fatalf("not published: %s", b)
	}
	dnsWrites := len(writes(e.fk))

	moved := app
	moved.Backend.Port = 8099
	squat := svc("docker", "aaa") // doorwarden.name=app, on the freed port
	squat.Name = "app"
	e.src.set(nil, squat, moved)
	for i := 0; i < 3; i++ {
		a.RunOnce(ctx)
		s := info(t, a, "docker/app")
		if s.State != model.StatePending {
			t.Fatalf("cycle %d: %+v", i, s)
		}
		found := false
		for _, x := range a.LastPlan().Actions { // the UI's issues for the service
			found = found || (x.Key == "docker/app" && x.Kind == reconcile.Invalid &&
				strings.Contains(x.Reason, "backend changed; re-approve to resume"))
		}
		if !found {
			t.Fatalf("cycle %d: no re-approve issue: %+v", i, a.LastPlan().Actions)
		}
		b, _ := os.ReadFile(routesFile)
		if strings.Contains(string(b), "app.example.test") {
			t.Fatalf("cycle %d: quarantined (or squatter) host still rendered: %s", i, b)
		}
		if r, ok, _ := e.st.GetRoute(ctx, "docker/app"); !ok || !r.Quarantined {
			t.Fatalf("cycle %d: route %+v %v", i, r, ok)
		}
		if _, ok, _ := e.st.GetRoute(ctx, "docker/aaa"); ok {
			t.Fatalf("cycle %d: squatter got a route", i)
		}
	}
	if w := writes(e.fk); len(w) != dnsWrites {
		t.Fatalf("DNS changed while quarantined: %+v", w[dnsWrites:])
	}
	n := 0
	for _, ev := range e.notif.events() {
		if ev.Kind == "service.quarantined" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("quarantine notifications = %d, want 1: %+v", n, e.notif.events())
	}

	if err := a.Approve(ctx, "docker/app", info(t, a, "docker/app").Fingerprint); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	if s := info(t, a, "docker/app"); s.State != model.StatePublished {
		t.Fatalf("re-approved: %+v", s)
	}
	if b, _ := os.ReadFile(routesFile); !strings.Contains(string(b), "app.example.test") || !strings.Contains(string(b), ":8099") {
		t.Fatalf("not resumed: %s", b)
	}
}

// served runs one auto-mode cycle so svcs have persisted routes, as they
// would after running in auto mode (or before an upgrade).
func served(t *testing.T, e *env, svcs ...model.Service) {
	t.Helper()
	e.src.set(nil, svcs...)
	e.app().RunOnce(context.Background())
	for _, s := range svcs {
		if _, ok, _ := e.st.GetRoute(context.Background(), s.Key); !ok {
			t.Fatalf("%s not routed", s.Key)
		}
	}
}

func activityCount(t *testing.T, e *env, sub string) int {
	t.Helper()
	acts, _ := e.st.ListActivity(context.Background(), 200)
	n := 0
	for _, x := range acts {
		if strings.Contains(x.Message, sub) {
			n++
		}
	}
	return n
}

// A stored v1 approval of the unchanged content, still served as its route
// serves it, is migrated at the first cycle (audited once) and the service
// stays served. One of changed content, and one whose service returns on
// another port than its route (v1 never covered the port), is not
// migrated: quarantined.
func TestLegacyApprovalMigration(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	same, changed, moved := svc("docker", "app"), svc("docker", "other"), svc("docker", "moved")
	served(t, e, same, changed, moved)
	if err := e.st.SetApproval(ctx, same.Key, approval.FingerprintV1(same)); err != nil {
		t.Fatal(err)
	}
	old := changed
	old.Zone = "gone.test"
	if err := e.st.SetApproval(ctx, changed.Key, approval.FingerprintV1(old)); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetApproval(ctx, moved.Key, approval.FingerprintV1(moved)); err != nil {
		t.Fatal(err)
	}
	back := moved
	back.Backend.Port = 9001
	e.src.set(nil, same, changed, back)
	a := e.app(func(o *Options) { o.Sources = []SourceSpec{{Source: e.src, Mode: approval.ModeApprove}} })
	a.RunOnce(ctx)
	if s := info(t, a, same.Key); s.State != model.StatePublished {
		t.Fatalf("migrated: %+v", s)
	}
	for _, k := range []string{changed.Key, moved.Key} {
		if s := info(t, a, k); s.State != model.StatePending {
			t.Fatalf("%s: %+v", k, s)
		}
		if r, ok, _ := e.st.GetRoute(ctx, k); !ok || !r.Quarantined {
			t.Fatalf("%s not quarantined: %+v %v", k, r, ok)
		}
	}
	if fp, _, _ := e.st.GetApproval(ctx, same.Key); fp != approval.Fingerprint(same) {
		t.Fatal("not rewritten to v2")
	}
	if fp, _, _ := e.st.GetApproval(ctx, changed.Key); fp != approval.FingerprintV1(old) {
		t.Fatal("changed v1 approval rewritten")
	}
	if fp, _, _ := e.st.GetApproval(ctx, moved.Key); fp != approval.FingerprintV1(moved) {
		t.Fatal("moved v1 approval rewritten")
	}
	n := activityCount(t, e, "migrated approval v1->v2")
	a.RunOnce(ctx)
	if m := activityCount(t, e, "migrated approval v1->v2"); n != 1 || m != 1 {
		t.Fatalf("migration audited %d then %d times, want once", n, m)
	}
}

// Dry run migrates nothing: the v1 approval stays as stored and the
// service keeps being served.
func TestLegacyApprovalMigrationDryRun(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	same := svc("docker", "app")
	served(t, e, same)
	_ = e.st.SetApproval(ctx, same.Key, approval.FingerprintV1(same))
	a := e.app(func(o *Options) { o.Sources = []SourceSpec{{Source: e.src, Mode: approval.ModeApprove}} })
	if err := a.SetDryRun(ctx, true); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	if fp, _, _ := e.st.GetApproval(ctx, same.Key); fp != approval.FingerprintV1(same) {
		t.Fatal("dry run rewrote the approval")
	}
	if s := info(t, a, same.Key); s.State != model.StatePublished {
		t.Fatalf("dry: %+v", s)
	}
	for _, x := range a.LastPlan().Actions {
		if x.Key == same.Key && (x.Kind == reconcile.RouteRemove || x.Kind == reconcile.Invalid) {
			t.Fatalf("dry run plans a quarantine: %+v", x)
		}
	}
}

// A source switched from auto to approve: a served service whose content is
// unchanged is grandfathered (approval recorded, audited, still served); one
// whose backend changed is quarantined; dry run writes no approval.
func TestModeSwitchGrandfathersUnchanged(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	same, other := svc("docker", "app"), svc("docker", "other")
	served(t, e, same, other)
	moved := other
	moved.Backend.Port = 9001
	e.src.set(nil, same, moved)
	a := e.app(func(o *Options) { o.Sources = []SourceSpec{{Source: e.src, Mode: approval.ModeApprove}} })

	if err := a.SetDryRun(ctx, true); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	if _, ok, _ := e.st.GetApproval(ctx, same.Key); ok {
		t.Fatal("dry run recorded an approval")
	}
	if r, _, _ := e.st.GetRoute(ctx, other.Key); r.Quarantined {
		t.Fatal("dry run quarantined a route")
	}
	if err := a.SetDryRun(ctx, false); err != nil {
		t.Fatal(err)
	}

	a.RunOnce(ctx)
	if s := info(t, a, same.Key); s.State != model.StatePublished {
		t.Fatalf("grandfathered: %+v", s)
	}
	if fp, ok, _ := e.st.GetApproval(ctx, same.Key); !ok || fp != approval.Fingerprint(same) {
		t.Fatal("no approval recorded")
	}
	if n := activityCount(t, e, "grandfathered on mode switch"); n != 1 {
		t.Fatalf("grandfather audited %d times", n)
	}
	if r, ok, _ := e.st.GetRoute(ctx, same.Key); !ok || r.Quarantined {
		t.Fatalf("grandfathered route %+v %v", r, ok)
	}
	if s := info(t, a, other.Key); s.State != model.StatePending {
		t.Fatalf("changed: %+v", s)
	}
	if r, ok, _ := e.st.GetRoute(ctx, other.Key); !ok || !r.Quarantined || r.Port != 8080 {
		t.Fatalf("changed route not quarantined: %+v %v", r, ok)
	}
	if _, ok, _ := e.st.GetApproval(ctx, other.Key); ok {
		t.Fatal("changed content approved")
	}
}

// Auto mode never quarantines: a stale approval row is ignored and a
// backend change is published.
func TestAutoModeNeverQuarantines(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	app := svc("docker", "app")
	_ = e.st.SetApproval(ctx, app.Key, "stale")
	e.src.set(nil, app)
	a := e.app()
	a.RunOnce(ctx)
	moved := app
	moved.Backend.Port = 8099
	e.src.set(nil, moved)
	a.RunOnce(ctx)
	if s := info(t, a, app.Key); s.State != model.StatePublished {
		t.Fatalf("auto: %+v", s)
	}
	for _, x := range a.LastPlan().Actions {
		if x.Key == app.Key && x.Kind == reconcile.Invalid {
			t.Fatalf("auto mode quarantined: %+v", x)
		}
	}
	if r, ok, _ := e.st.GetRoute(ctx, app.Key); !ok || r.Quarantined || r.Port != 8099 {
		t.Fatalf("route %+v %v", r, ok)
	}
}
