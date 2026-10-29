package web

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Concurrent callers share one probe run; results are reused for the
// minimum interval, so a /healthz flood cannot starve the store.
func TestCachedProbeBoundsCalls(t *testing.T) {
	var n atomic.Int32
	clock := time.Unix(1_800_000_000, 0)
	var cmu sync.Mutex
	now := func() time.Time { cmu.Lock(); defer cmu.Unlock(); return clock }
	release := make(chan struct{})
	p := NewCachedProbe(func(ctx context.Context) error {
		n.Add(1)
		<-release
		return nil
	}, 2*time.Second)
	p.now = now

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = p.Probe(context.Background()) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	for i := 0; i < 50; i++ {
		if err := p.Probe(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("probe ran %d times, want 1", got)
	}
	cmu.Lock()
	clock = clock.Add(3 * time.Second)
	cmu.Unlock()
	_ = p.Probe(context.Background())
	if got := n.Load(); got != 2 {
		t.Fatalf("after the interval probe ran %d times, want 2", got)
	}
}

// A failure is cached too (no retry storm), and the cached error is
// returned to every caller in the interval.
func TestCachedProbeCachesFailure(t *testing.T) {
	var n atomic.Int32
	p := NewCachedProbe(func(context.Context) error { n.Add(1); return errors.New("db locked") }, time.Hour)
	for i := 0; i < 10; i++ {
		if err := p.Probe(context.Background()); err == nil {
			t.Fatal("failure not reported")
		}
	}
	if n.Load() != 1 {
		t.Fatalf("probe ran %d times", n.Load())
	}
}

// A caller whose context ends while waiting for the shared run gets its
// own context error; the run is not cancelled for the others.
func TestCachedProbeWaiterTimeout(t *testing.T) {
	release := make(chan struct{})
	p := NewCachedProbe(func(context.Context) error { <-release; return nil }, time.Second)
	go func() { _ = p.Probe(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Probe(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	close(release)
}
