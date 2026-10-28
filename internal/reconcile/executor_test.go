package reconcile

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
)

// fakeProvider stands in for a DNS/cert/route executor that talks to a real
// system; it counts every call.
type fakeProvider struct {
	mu    sync.Mutex
	calls [][]Action
	err   error
}

func (f *fakeProvider) Apply(_ context.Context, as []Action, dryRun bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]Action{}, as...))
	return f.err
}

func (f *fakeProvider) n() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

type activityLog struct {
	mu  sync.Mutex
	got []string
}

func (l *activityLog) record(_ context.Context, a Action, dryRun bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := sum(a)
	if dryRun {
		s = "dry " + s
	}
	if err != nil {
		s += " err"
	}
	l.got = append(l.got, s)
}

func samplePlan() []Action {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	return Plan([]model.Service{
		pub("docker:a", "a", "example.test", 1),
		pub("docker:b", "b", "example.test", 2),
		pub("static:b", "b", "example.test", 3),
	}, Observed{Known: knownMap(known("docker:gone", "example.test", "gone.example.test", nil))}, cfg, t0)
}

func fullMulti(act ActivityFunc) (*MultiExecutor, map[ActionKind]*fakeProvider) {
	m := NewMultiExecutor(act)
	fakes := map[ActionKind]*fakeProvider{}
	for _, k := range []ActionKind{DNSEnsure, DNSDelete, CertEnsure, RouteWrite, RouteRemove, ScheduleRemoval, CancelRemoval} {
		fakes[k] = &fakeProvider{}
		m.Handle(k, fakes[k])
	}
	return m, fakes
}

func TestMultiExecutorDryRunCallsNoProvider(t *testing.T) {
	log := &activityLog{}
	m, fakes := fullMulti(log.record)
	acts := samplePlan()
	if err := m.Apply(context.Background(), acts, true); err != nil {
		t.Fatal(err)
	}
	for k, f := range fakes {
		if f.n() != 0 {
			t.Fatalf("dry run dispatched %s", k)
		}
	}
	if len(log.got) != len(acts) {
		t.Fatalf("dry run must record every action: %d of %d", len(log.got), len(acts))
	}
	for _, g := range log.got {
		if !strings.HasPrefix(g, "dry ") {
			t.Fatalf("activity not flagged dry: %q", g)
		}
	}
}

func TestMultiExecutorDispatchesByKindInOrder(t *testing.T) {
	log := &activityLog{}
	m, fakes := fullMulti(log.record)
	acts := samplePlan()
	if err := m.Apply(context.Background(), acts, false); err != nil {
		t.Fatal(err)
	}
	for _, k := range []ActionKind{DNSEnsure, CertEnsure, RouteWrite, ScheduleRemoval} {
		f := fakes[k]
		if f.n() != 1 {
			t.Fatalf("%s: want one batched call, got %d", k, f.n())
		}
		for _, a := range f.calls[0] {
			if a.Kind != k {
				t.Fatalf("%s executor got %s", k, a.Kind)
			}
		}
		if len(f.calls[0]) != len(ofKind(acts, k)) {
			t.Fatalf("%s: batch size %d want %d", k, len(f.calls[0]), len(ofKind(acts, k)))
		}
	}
	if fakes[DNSDelete].n() != 0 || fakes[RouteRemove].n() != 0 {
		t.Fatal("unexpected removal dispatch")
	}
	if len(log.got) != len(acts) {
		t.Fatalf("activity count %d want %d", len(log.got), len(acts))
	}
}

func TestMultiExecutorMissingHandler(t *testing.T) {
	m := NewMultiExecutor(nil)
	info := []Action{{Kind: Conflict, Key: "docker:a"}, {Kind: Invalid, Key: "docker:b"}, {Kind: Skip, Key: "docker:c"}}
	if err := m.Apply(context.Background(), info, false); err != nil {
		t.Fatalf("informational kinds need no executor: %v", err)
	}
	err := m.Apply(context.Background(), []Action{{Kind: CancelRemoval, Key: "docker:a"}}, false)
	if !errors.Is(err, ErrNoExecutor) {
		t.Fatalf("want ErrNoExecutor, got %v", err)
	}
	if err := m.Apply(context.Background(), []Action{{Kind: RouteWrite}}, true); err != nil {
		t.Fatalf("dry run never needs executors: %v", err)
	}
}

func TestMultiExecutorContinuesAndJoinsErrors(t *testing.T) {
	log := &activityLog{}
	m, fakes := fullMulti(log.record)
	boom := errors.New("boom")
	fakes[DNSEnsure].err = boom
	err := m.Apply(context.Background(), samplePlan(), false)
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if fakes[RouteWrite].n() != 1 {
		t.Fatal("later kinds must still be applied")
	}
	failed := 0
	for _, g := range log.got {
		if strings.HasSuffix(g, " err") {
			failed++
		}
	}
	if failed != len(ofKind(samplePlan(), DNSEnsure)) {
		t.Fatalf("failed activity entries %d", failed)
	}
}

func TestMultiExecutorStopsOnCancelledContext(t *testing.T) {
	m, fakes := fullMulti(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Apply(ctx, samplePlan(), false); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	for k, f := range fakes {
		if f.n() != 0 {
			t.Fatalf("%s dispatched after cancel", k)
		}
	}
}

func TestRecorderAndLoggingExecutor(t *testing.T) {
	r := &Recorder{}
	acts := samplePlan()
	_ = r.Apply(context.Background(), acts, true)
	calls := r.Calls()
	if len(calls) != 1 || !calls[0].DryRun || len(calls[0].Actions) != len(acts) {
		t.Fatalf("recorder: %+v", calls)
	}
	var buf bytes.Buffer
	l := LoggingExecutor{Log: slog.New(slog.NewTextHandler(&buf, nil))}
	if err := l.Apply(context.Background(), acts, true); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "\n") != len(acts) || !strings.Contains(buf.String(), "dry_run=true") {
		t.Fatalf("log output:\n%s", buf.String())
	}
}

// blockingExec counts concurrent Apply calls.
type blockingExec struct {
	inFlight, maxSeen atomic.Int32
	calls             atomic.Int32
	mu                sync.Mutex
	got               [][]string
	dry               []bool
}

func (b *blockingExec) Apply(_ context.Context, as []Action, dryRun bool) error {
	n := b.inFlight.Add(1)
	defer b.inFlight.Add(-1)
	for {
		m := b.maxSeen.Load()
		if n <= m || b.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(5 * time.Millisecond)
	b.calls.Add(1)
	b.mu.Lock()
	b.got = append(b.got, sums(as))
	b.dry = append(b.dry, dryRun)
	b.mu.Unlock()
	return nil
}

func TestRunnerSerializesAndIsIdempotent(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	be := &blockingExec{}
	r := &Runner{Exec: be, Config: cfg}
	desired := []model.Service{pub("docker:a", "a", "example.test", 1), pub("docker:b", "b", "example.test", 2)}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Reconcile(context.Background(), desired, Observed{}, t0); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if be.maxSeen.Load() != 1 {
		t.Fatalf("Apply ran concurrently: max %d", be.maxSeen.Load())
	}
	if be.calls.Load() != 8 {
		t.Fatalf("calls %d", be.calls.Load())
	}
	for _, g := range be.got[1:] {
		if strings.Join(g, "|") != strings.Join(be.got[0], "|") {
			t.Fatalf("non-idempotent plan across reconciles")
		}
	}
}

func TestRunnerDryRunFlag(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	desired := []model.Service{pub("docker:a", "a", "example.test", 1)}
	tests := []struct {
		name    string
		cfgDry  bool
		flag    func() bool
		wantDry bool
	}{
		{"neither", false, nil, false},
		{"global flag", false, func() bool { return true }, true},
		{"config", true, func() bool { return false }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := *cfg
			c.Settings.DryRun = tc.cfgDry
			be := &blockingExec{}
			r := &Runner{Exec: be, Config: &c, DryRun: tc.flag}
			acts, err := r.Reconcile(context.Background(), desired, Observed{}, t0)
			if err != nil || len(acts) == 0 {
				t.Fatalf("acts=%v err=%v", acts, err)
			}
			if be.dry[0] != tc.wantDry {
				t.Fatalf("dryRun=%v want %v", be.dry[0], tc.wantDry)
			}
		})
	}
	t.Run("nil config fails closed", func(t *testing.T) {
		be := &blockingExec{}
		r := &Runner{Exec: be}
		if _, err := r.Reconcile(context.Background(), desired, Observed{}, t0); err == nil || be.calls.Load() != 0 {
			t.Fatalf("want error and no Apply, err=%v calls=%d", err, be.calls.Load())
		}
	})
}
