package approval

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

type fake struct {
	mu       sync.Mutex
	m        map[string]string
	writes   int
	failList bool
}

func newFake() *fake { return &fake{m: map[string]string{}} }
func (f *fake) SetApproval(_ context.Context, k, fp string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[k] = fp
	f.writes++
	return nil
}
func (f *fake) ClearApproval(_ context.Context, k string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, k)
	f.writes++
	return nil
}
func (f *fake) ListApprovals(context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return nil, errors.New("boom")
	}
	o := map[string]string{}
	for k, v := range f.m {
		o[k] = v
	}
	return o, nil
}

var ctx = context.Background()

func svc(key, state string) model.Service {
	return model.Service{Key: key, Source: "docker", Name: key, Zone: "example.test", State: state,
		Backend: model.Backend{Scheme: "http", Host: "192.0.2.1", Port: 80},
		Options: model.Options{Middlewares: []string{"auth", "rl"}}}
}

func states(out []model.Service) map[string]string {
	m := map[string]string{}
	for _, s := range out {
		m[s.Key] = s.State
	}
	return m
}

// approveCur approves key with the gate's current fingerprint for it.
func approveCur(t *testing.T, g *Gate, key string) {
	t.Helper()
	if err := g.Approve(ctx, key, g.Fingerprints()[key]); err != nil {
		t.Fatal(err)
	}
}

func resolveState(t *testing.T, g *Gate, m Mode, s model.Service) string {
	t.Helper()
	out, err := g.Resolve(ctx, m, []model.Service{s})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("out=%+v", out)
	}
	return out[0].State
}

func TestAutoPublishesAndSkipWins(t *testing.T) {
	g := NewGate(newFake())
	sk := svc("b", model.StateDiscovered)
	sk.Options.Skip = true
	out, err := g.Resolve(ctx, ModeAuto, []model.Service{svc("a", model.StateDiscovered), sk})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Key != "a" || out[0].State != model.StatePublished {
		t.Fatalf("%+v", out)
	}
}

func TestOffOmits(t *testing.T) {
	g := NewGate(newFake())
	out, err := g.Resolve(ctx, ModeOff, []model.Service{svc("a", model.StateDiscovered), svc("b", model.StateStopped)})
	if err != nil || len(out) != 0 {
		t.Fatalf("%v %+v", err, out)
	}
	if err := g.Approve(ctx, "a", "x"); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("off mode must not allow approval: %v", err)
	}
}

func TestApproveFlowAndRevoke(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("a", model.StateDiscovered)
	if resolveState(t, g, ModeApprove, s) != model.StatePending {
		t.Fatal("want pending")
	}
	approveCur(t, g, "a")
	if resolveState(t, g, ModeApprove, s) != model.StatePublished {
		t.Fatal("want published")
	}
	if err := g.Revoke(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if resolveState(t, g, ModeApprove, s) != model.StatePending {
		t.Fatal("want pending after revoke")
	}
	w := f.writes
	if err := g.Revoke(ctx, "a"); err != nil || f.writes != w {
		t.Fatalf("revoke of absent must be a no-op: err=%v writes %d->%d", err, w, f.writes)
	}
}

func TestSkipWinsInApprove(t *testing.T) {
	g := NewGate(newFake())
	s := svc("a", model.StateDiscovered)
	s.Options.Skip = true
	out, err := g.Resolve(ctx, ModeApprove, []model.Service{s})
	if err != nil || len(out) != 0 {
		t.Fatalf("%v %+v", err, out)
	}
	if err := g.Approve(ctx, "a", "x"); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("%v", err)
	}
}

func TestUnknownKey(t *testing.T) {
	g := NewGate(newFake())
	if err := g.Approve(ctx, "nope", "x"); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("%v", err)
	}
	if err := g.Revoke(ctx, "nope"); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestStoppedErrorKeepStateEveryMode(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s, e := svc("s", model.StateStopped), svc("e", model.StateError)
	f.m["s"], f.m["e"] = Fingerprint(s), Fingerprint(e) // even if "approved"
	for _, m := range []Mode{ModeAuto, ModeApprove} {
		out, err := g.Resolve(ctx, m, []model.Service{s, e})
		st := states(out)
		if err != nil || len(out) != 2 || st["s"] != model.StateStopped || st["e"] != model.StateError {
			t.Fatalf("%s: %v %+v", m, err, out)
		}
	}
}

func TestFingerprintChangesFlipToPending(t *testing.T) {
	mut := map[string]func(*model.Service){
		"drop middleware": func(s *model.Service) { s.Options.Middlewares = []string{"rl"} },
		"zone":            func(s *model.Service) { s.Zone = "other.test" },
		"rename":          func(s *model.Service) { s.Options.Rename = "evil" },
		"name":            func(s *model.Service) { s.Name = "other" },
		"scheme":          func(s *model.Service) { s.Backend.Scheme = "https" },
		"skip-verify":     func(s *model.Service) { s.Backend.SkipVerify = true },
		"websockets":      func(s *model.Service) { s.Options.Websockets = true },
	}
	for name, f := range mut {
		g := NewGate(newFake())
		s := svc("a", model.StateDiscovered)
		resolveState(t, g, ModeApprove, s)
		approveCur(t, g, "a")
		if resolveState(t, g, ModeApprove, s) != model.StatePublished {
			t.Fatalf("%s: not published before change", name)
		}
		c := s
		c.Options.Middlewares = append([]string(nil), s.Options.Middlewares...)
		f(&c)
		if resolveState(t, g, ModeApprove, c) != model.StatePending {
			t.Errorf("%s: change did not revoke approval", name)
		}
		// re-approve the changed content publishes again
		approveCur(t, g, "a")
		if resolveState(t, g, ModeApprove, c) != model.StatePublished {
			t.Errorf("%s: re-approve did not publish", name)
		}
	}
}

// Final-review H2/H3: the fingerprint covers the ORDERED middleware list
// (the renderer applies them in order) and the backend scheme, host and port
// of every source: each such change needs re-approval (fail safe).
func TestFingerprintCoversBackendAndMiddlewareOrder(t *testing.T) {
	for name, mut := range map[string]func(*model.Service){
		"middleware reorder": func(c *model.Service) { c.Options.Middlewares = []string{"rl", "auth"} },
		"port":               func(c *model.Service) { c.Backend.Port = 32768 },
		"host":               func(c *model.Service) { c.Backend.Host = "198.51.100.9" },
		"scheme":             func(c *model.Service) { c.Backend.Scheme = "https" },
	} {
		g := NewGate(newFake())
		s := svc("a", model.StateDiscovered)
		resolveState(t, g, ModeApprove, s)
		approveCur(t, g, "a")
		c := s
		c.Options.Middlewares = append([]string(nil), s.Options.Middlewares...)
		mut(&c)
		if resolveState(t, g, ModeApprove, c) != model.StatePending {
			t.Errorf("%s: change kept the approval", name)
		}
		if resolveState(t, g, ModeApprove, s) != model.StatePublished {
			t.Errorf("%s: unchanged content lost its approval", name)
		}
	}
}

// Reapprove carries an existing approval over to new content (an admin's
// UI override) only when the stored approval is for the old content.
func TestReapprove(t *testing.T) {
	g := NewGate(newFake())
	s := svc("a", model.StateDiscovered)
	resolveState(t, g, ModeApprove, s)
	c := s
	c.Backend.Port = 9000
	ctx := context.Background()
	if ok, err := g.Reapprove(ctx, "a", Fingerprint(s), Fingerprint(c)); err != nil || ok {
		t.Fatalf("unapproved service reapproved: %v %v", ok, err)
	}
	approveCur(t, g, "a")
	if ok, err := g.Reapprove(ctx, "a", "other", Fingerprint(c)); err != nil || ok {
		t.Fatalf("approval of other content carried over: %v %v", ok, err)
	}
	if ok, err := g.Reapprove(ctx, "a", Fingerprint(s), Fingerprint(c)); err != nil || !ok {
		t.Fatalf("reapprove: %v %v", ok, err)
	}
	if resolveState(t, g, ModeApprove, c) != model.StatePublished {
		t.Fatal("new content not approved")
	}
	if resolveState(t, g, ModeApprove, s) != model.StatePending {
		t.Fatal("old content still approved")
	}
}

func TestReturningServiceStaysApproved(t *testing.T) {
	g := NewGate(newFake())
	s := svc("a", model.StateDiscovered)
	resolveState(t, g, ModeApprove, s)
	approveCur(t, g, "a")
	if out, err := g.Resolve(ctx, ModeApprove, nil); err != nil || len(out) != 0 {
		t.Fatal(err)
	}
	if resolveState(t, g, ModeApprove, s) != model.StatePublished {
		t.Fatal("should stay approved")
	}
}

func TestApprovalSurvivesRestartRealStore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := svc("a", model.StateDiscovered)
	g1 := NewGate(st)
	if resolveState(t, g1, ModeApprove, s) != model.StatePending {
		t.Fatal("want pending")
	}
	approveCur(t, g1, "a")
	g2 := NewGate(st)
	if err := g2.Approve(ctx, "a", "x"); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("fresh gate has no snapshot: %v", err)
	}
	if resolveState(t, g2, ModeApprove, s) != model.StatePublished {
		t.Fatal("approval lost across gates")
	}
	// a services-table rewrite does not touch approvals
	if err := st.UpsertService(ctx, store.Service{Key: "a", Source: "docker", State: model.StatePublished, OverridesJSON: `{"x":1}`}); err != nil {
		t.Fatal(err)
	}
	if resolveState(t, NewGate(st), ModeApprove, s) != model.StatePublished {
		t.Fatal("approval clobbered by services write")
	}
	if err := g2.Revoke(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if resolveState(t, NewGate(st), ModeApprove, s) != model.StatePending {
		t.Fatal("revoke not persisted")
	}
}

func TestUnknownModeErrors(t *testing.T) {
	g := NewGate(newFake())
	if _, err := g.Resolve(ctx, Mode("bogus"), []model.Service{svc("a", model.StateDiscovered)}); err == nil {
		t.Fatal("want error")
	}
}

func TestResolveStoreErrorLeavesNoState(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("a", model.StateDiscovered)
	resolveState(t, g, ModeApprove, s) // snapshot has "a"
	f.failList = true
	if _, err := g.Resolve(ctx, ModeApprove, []model.Service{svc("b", model.StateDiscovered)}); err == nil {
		t.Fatal("want error")
	}
	if f.writes != 0 || len(f.m) != 0 {
		t.Fatalf("unexpected writes: %d %v", f.writes, f.m)
	}
	f.failList = false
	approveCur(t, g, "a") // snapshot unchanged by failed Resolve
	if err := g.Approve(ctx, "b", "x"); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("%v", err)
	}
}

func TestConcurrentConsistency(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	in := []model.Service{svc("a", model.StateDiscovered)}
	if _, err := g.Resolve(ctx, ModeApprove, in); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := g.Approve(ctx, "a", Fingerprint(in[0])); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := g.Resolve(ctx, ModeApprove, in); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if resolveState(t, g, ModeApprove, in[0]) != model.StatePublished || f.m["a"] != Fingerprint(in[0]) {
		t.Fatalf("inconsistent: %v", f.m)
	}
	var wg2 sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg2.Add(2)
		go func() { defer wg2.Done(); _ = g.Revoke(ctx, "a") }()
		go func() { defer wg2.Done(); _, _ = g.Resolve(ctx, ModeApprove, in) }()
	}
	wg2.Wait()
	if resolveState(t, g, ModeApprove, in[0]) != model.StatePending {
		t.Fatal("revoke should leave pending")
	}
}

func TestApproveFingerprintChecks(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("a", model.StateDiscovered)
	resolveState(t, g, ModeApprove, s)
	fp := g.Fingerprints()["a"]
	if fp != Fingerprint(s) {
		t.Fatal("Fingerprints must expose Fingerprint")
	}
	for _, bad := range []string{"", "abc", fp + "00", fp[:len(fp)-1]} {
		if err := g.Approve(ctx, "a", bad); !errors.Is(err, ErrStale) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if len(f.m) != 0 || f.writes != 0 {
		t.Fatalf("stale approve stored something: %v", f.m)
	}
	if err := g.Approve(ctx, "a", fp); err != nil || f.m["a"] != fp {
		t.Fatalf("%v %v", err, f.m)
	}
}

func TestApproveStaleAfterServiceChanges(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("a", model.StateDiscovered)
	resolveState(t, g, ModeApprove, s)
	old := g.Fingerprints()["a"]
	c := s
	c.Options.Middlewares = []string{"rl"} // auth dropped
	resolveState(t, g, ModeApprove, c)
	if err := g.Approve(ctx, "a", old); !errors.Is(err, ErrStale) {
		t.Fatalf("%v", err)
	}
	if len(f.m) != 0 {
		t.Fatal("stored on stale")
	}
	if err := g.Approve(ctx, "a", g.Fingerprints()["a"]); err != nil {
		t.Fatal(err)
	}
	if resolveState(t, g, ModeApprove, c) != model.StatePublished {
		t.Fatal("new fp should publish")
	}
}

func TestFingerprintsReturnsCopy(t *testing.T) {
	g := NewGate(newFake())
	resolveState(t, g, ModeApprove, svc("a", model.StateDiscovered))
	m := g.Fingerprints()
	m["a"] = "tampered"
	if g.Fingerprints()["a"] == "tampered" {
		t.Fatal("not a copy")
	}
}

func TestSnapshotAdditiveAcrossSources(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	a, b := svc("docker:a", model.StateDiscovered), svc("truenas:b", model.StateDiscovered)
	if _, err := g.Resolve(ctx, ModeApprove, []model.Service{a}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Resolve(ctx, ModeApprove, []model.Service{b}); err != nil {
		t.Fatal(err)
	}
	approveCur(t, g, "docker:a")
	approveCur(t, g, "truenas:b")
	if len(f.m) != 2 {
		t.Fatalf("%v", f.m)
	}
}

func TestModeOffKeepsSnapshot(t *testing.T) {
	g := NewGate(newFake())
	resolveState(t, g, ModeApprove, svc("a", model.StateDiscovered))
	if _, err := g.Resolve(ctx, ModeOff, []model.Service{svc("z", model.StateDiscovered)}); err != nil {
		t.Fatal(err)
	}
	approveCur(t, g, "a")
	if _, ok := g.Fingerprints()["z"]; ok {
		t.Fatal("off-mode service must not enter snapshot")
	}
}

func TestSnapshotDropsSkippedAndStopped(t *testing.T) {
	g := NewGate(newFake())
	s := svc("a", model.StateDiscovered)
	resolveState(t, g, ModeApprove, s)
	st := svc("a", model.StateStopped)
	if _, err := g.Resolve(ctx, ModeApprove, []model.Service{st}); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.Fingerprints()["a"]; ok {
		t.Fatal("stopped service must leave the snapshot")
	}
}
