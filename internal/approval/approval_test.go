package approval

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

type fake struct {
	mu sync.Mutex
	m  map[string]store.Service
}

func newFake() *fake { return &fake{m: map[string]store.Service{}} }
func (f *fake) ListServices(context.Context) ([]store.Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var o []store.Service
	for _, v := range f.m {
		o = append(o, v)
	}
	return o, nil
}
func (f *fake) UpsertService(_ context.Context, v store.Service) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[v.Key] = v
	return nil
}

var ctx = context.Background()

func svc(key, state string) model.Service {
	return model.Service{Key: key, Source: "docker", Name: key, State: state,
		Backend: model.Backend{Scheme: "http", Host: "192.0.2.1", Port: 80}}
}

func states(out []model.Service) map[string]string {
	m := map[string]string{}
	for _, s := range out {
		m[s.Key] = s.State
	}
	return m
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
	out, _ := g.Resolve(ctx, ModeOff, []model.Service{svc("a", model.StateDiscovered), svc("b", model.StateStopped)})
	if len(out) != 0 {
		t.Fatalf("%+v", out)
	}
}

func TestApproveFlow(t *testing.T) {
	g := NewGate(newFake())
	in := []model.Service{svc("a", model.StateDiscovered)}
	out, _ := g.Resolve(ctx, ModeApprove, in)
	if states(out)["a"] != model.StatePending {
		t.Fatalf("%+v", out)
	}
	if err := g.Approve(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	out, _ = g.Resolve(ctx, ModeApprove, in)
	if states(out)["a"] != model.StatePublished {
		t.Fatalf("%+v", out)
	}
	if err := g.Revoke(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	out, _ = g.Resolve(ctx, ModeApprove, in)
	if states(out)["a"] != model.StatePending {
		t.Fatalf("%+v", out)
	}
}

func TestApproveSkipStillOmitted(t *testing.T) {
	g := NewGate(newFake())
	s := svc("a", model.StateDiscovered)
	s.Options.Skip = true
	out, _ := g.Resolve(ctx, ModeApprove, []model.Service{s})
	if len(out) != 0 {
		t.Fatalf("%+v", out)
	}
}

func TestUnknownKey(t *testing.T) {
	g := NewGate(newFake())
	if err := g.Approve(ctx, "nope"); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("%v", err)
	}
	if err := g.Revoke(ctx, "nope"); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("%v", err)
	}
}

func TestStoppedErrorKeepStateEveryMode(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	in := []model.Service{svc("s", model.StateStopped), svc("e", model.StateError)}
	// pre-approve both
	f.UpsertService(ctx, store.Service{Key: "s", State: model.StatePublished, OverridesJSON: `{"approved":true}`})
	f.UpsertService(ctx, store.Service{Key: "e", State: model.StatePublished, OverridesJSON: `{"approved":true}`})
	for _, m := range []Mode{ModeAuto, ModeApprove} {
		out, _ := g.Resolve(ctx, m, in)
		st := states(out)
		if len(out) != 2 || st["s"] != model.StateStopped || st["e"] != model.StateError {
			t.Fatalf("%s: %+v", m, out)
		}
	}
}

func TestApprovePreservesOverrides(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	f.UpsertService(ctx, store.Service{Key: "a", Source: "docker", State: model.StatePending, OverridesJSON: `{"rename":"x","n":1}`})
	if err := g.Approve(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(f.m["a"].OverridesJSON), &m); err != nil {
		t.Fatal(err)
	}
	if m["rename"] != "x" || m["n"] != float64(1) || m["approved"] != true {
		t.Fatalf("%v", m)
	}
	g.Revoke(ctx, "a")
	m = nil
	json.Unmarshal([]byte(f.m["a"].OverridesJSON), &m)
	if m["rename"] != "x" || m["approved"] == true {
		t.Fatalf("%v", m)
	}
}

func TestApprovalSurvivesRestartRealStore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	in := []model.Service{svc("a", model.StateDiscovered)}
	g1 := NewGate(st)
	out, err := g1.Resolve(ctx, ModeApprove, in)
	if err != nil || states(out)["a"] != model.StatePending {
		t.Fatalf("%v %+v", err, out)
	}
	if err := g1.Approve(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	out, err = NewGate(st).Resolve(ctx, ModeApprove, in)
	if err != nil || states(out)["a"] != model.StatePublished {
		t.Fatalf("%v %+v", err, out)
	}
}

func TestConcurrent(t *testing.T) {
	g := NewGate(newFake())
	in := []model.Service{svc("a", model.StateDiscovered)}
	g.Resolve(ctx, ModeApprove, in)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = g.Approve(ctx, "a") }()
		go func() { defer wg.Done(); _, _ = g.Resolve(ctx, ModeApprove, in) }()
	}
	wg.Wait()
}
