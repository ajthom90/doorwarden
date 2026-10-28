package acme

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
)

// envMu serializes every process-environment mutation done to construct a
// lego provider. lego providers read their settings from the environment in
// their constructor (NewDNSProvider -> NewDefaultConfig), so the variables
// are set, the provider is built and the previous values are restored, all
// under this lock. Nothing else in doorwarden may rely on these variables.
var envMu sync.Mutex

// withEnv sets env, runs fn and restores every variable to its previous
// state (value, or unset) before returning, even if fn panics.
func withEnv(env map[string]string, fn func() (challenge.Provider, error)) (challenge.Provider, error) {
	envMu.Lock()
	defer envMu.Unlock()
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type prev struct {
		v  string
		ok bool
	}
	saved := make(map[string]prev, len(keys))
	for _, k := range keys {
		v, ok := os.LookupEnv(k)
		saved[k] = prev{v, ok}
	}
	defer func() {
		for _, k := range keys {
			if p := saved[k]; p.ok {
				_ = os.Setenv(k, p.v)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	}()
	for _, k := range keys {
		if err := os.Setenv(k, env[k]); err != nil {
			return nil, fmt.Errorf("acme: set provider setting %s: %w", k, err)
		}
	}
	return fn()
}

// timeoutProvider overrides a provider's DNS propagation timeout
// (challenge.ProviderTimeout is how lego's precheck reads it).
type timeoutProvider struct {
	challenge.Provider
	timeout, interval time.Duration
}

func (t timeoutProvider) Timeout() (time.Duration, time.Duration) { return t.timeout, t.interval }

// sequentialProvider is lego's optional interface (challenge/dns01) asking
// for the provider's challenges to be solved one at a time.
type sequentialProvider interface {
	Sequential() time.Duration
}

// sequentialTimeoutProvider is timeoutProvider for a provider that is also
// sequential: wrapping must not hide Sequential() from lego, or providers
// that cannot hold two TXT records at once would be run in parallel.
type sequentialTimeoutProvider struct {
	timeoutProvider
	seq sequentialProvider
}

func (s sequentialTimeoutProvider) Sequential() time.Duration { return s.seq.Sequential() }

// withPropagationTimeout overrides p's propagation timeout, keeping p's
// interval (or 2s) and forwarding the optional Sequential() interface.
func withPropagationTimeout(p challenge.Provider, timeout time.Duration) challenge.Provider {
	if timeout <= 0 {
		return p
	}
	interval := 2 * time.Second
	if pt, ok := p.(challenge.ProviderTimeout); ok {
		if _, iv := pt.Timeout(); iv > 0 {
			interval = iv
		}
	}
	tp := timeoutProvider{Provider: p, timeout: timeout, interval: interval}
	if sp, ok := p.(sequentialProvider); ok {
		return sequentialTimeoutProvider{timeoutProvider: tp, seq: sp}
	}
	return tp
}
