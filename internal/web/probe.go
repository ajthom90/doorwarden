package web

import (
	"context"
	"sync"
	"time"
)

// DefaultProbeInterval is how long a store probe result is reused.
const DefaultProbeInterval = 2 * time.Second

// CachedProbe runs a probe at most once per interval: concurrent callers
// share one run (single flight) and every caller in the interval gets the
// cached result, failures included. The store probe is a write transaction
// on a single-connection SQLite; a /healthz flood must not starve the
// reconcile loop.
type CachedProbe struct {
	probe    func(context.Context) error
	interval time.Duration
	timeout  time.Duration
	now      func() time.Time

	mu      sync.Mutex
	at      time.Time
	err     error
	have    bool
	running chan struct{} // closed when the current run finishes
}

// NewCachedProbe wraps probe; interval <= 0 means DefaultProbeInterval.
func NewCachedProbe(probe func(context.Context) error, interval time.Duration) *CachedProbe {
	if interval <= 0 {
		interval = DefaultProbeInterval
	}
	return &CachedProbe{probe: probe, interval: interval, timeout: DefaultProbeTimeout, now: time.Now}
}

// Probe returns the cached result, or waits for the shared run. The run
// itself is bounded by its own timeout, not by ctx, so one caller giving up
// does not fail it for the others; ctx bounds only this caller's wait.
func (c *CachedProbe) Probe(ctx context.Context) error {
	c.mu.Lock()
	if c.have && c.now().Sub(c.at) < c.interval {
		err := c.err
		c.mu.Unlock()
		return err
	}
	ch := c.running
	if ch == nil {
		ch = make(chan struct{})
		c.running = ch
		go c.run(ch)
	}
	c.mu.Unlock()
	select {
	case <-ch:
	case <-ctx.Done():
		return ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *CachedProbe) run(ch chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	err := c.probe(ctx)
	cancel()
	c.mu.Lock()
	c.err, c.at, c.have, c.running = err, c.now(), true, nil
	c.mu.Unlock()
	close(ch)
}
