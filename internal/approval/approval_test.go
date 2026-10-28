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
	if err := g.Approve(ctx, "a"); !errors.Is(err, ErrUnknownService) {
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
	if err := g.Approve(ctx, "a"); err != nil {
		t.Fatal(err)
	}
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
	if err := g.Approve(ctx, "a"); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("%v", err)
	}
}

func TestUnknownKey(t *testing.T) {
	g := NewGate(newFake())
	if err := g.Approve(ctx, "nope"); !errors.Is(err, ErrUnknownService) {
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
		if err := g.Approve(ctx, "a"); err != nil {
			t.Fatal(err)
		}
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
		if err := g.Approve(ctx, "a"); err != nil {
			t.Fatal(err)
		}
		if resolveState(t, g, ModeApprove, c) != model.StatePublished {
			t.Errorf("%s: re-approve did not publish", name)
		}
	}
}

func TestFingerprintIgnoresPortHostAndMiddlewareOrder(t *testing.T) {
	g := NewGate(newFake())
	s := svc("a", model.StateDiscovered)
	resolveState(t, g, ModeApprove, s)
	if err := g.Approve(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	c := s
	c.Backend.Port, c.Backend.Host = 32768, "198.51.100.9"
	c.Options.Middlewares = []string{"rl", "auth"}
	if resolveState(t, g, ModeApprove, c) != model.StatePublished {
		t.Fatal("port/host/order change must keep approval")
	}
}

func TestReturningServiceStaysApproved(t *testing.T) {
	g := NewGate(newFake())
	s := svc("a", model.StateDiscovered)
	resolveState(t, g, ModeApprove, s)
	if err := g.Approve(ctx, "a"); err != nil {
		t.Fatal(err)
	}
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
	if err := g1.Approve(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	g2 := NewGate(st)
	if err := g2.Approve(ctx, "a"); !errors.Is(err, ErrUnknownService) {
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
	if err := g.Approve(ctx, "a"); err != nil { // snapshot unchanged by failed Resolve
		t.Fatal(err)
	}
	if err := g.Approve(ctx, "b"); !errors.Is(err, ErrUnknownService) {
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
			if err := g.Approve(ctx, "a"); err != nil {
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
