package acme

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/ajthom90/doorwarden/internal/config"
)

// Each zone's challenge provider must see exactly its own settings while it
// is constructed, never another provider's, even under concurrent Issue
// calls; afterwards the environment is exactly as before.
func TestProviderEnvIsolationUnderConcurrentIssue(t *testing.T) {
	t.Setenv("CF_DNS_API_TOKEN", "outer-value") // pre-existing value must come back
	os.Unsetenv("AWS_SECRET_ACCESS_KEY")

	const zones = 12
	cfg := testConfig()
	cfg.Zones = nil
	cfg.Providers = map[string]config.ProviderCfg{}
	for i := range zones {
		pn := fmt.Sprintf("p%d", i)
		typ, extra := "cloudflare", map[string]any{"CF_DNS_API_TOKEN": fmt.Sprintf("token-%d", i)}
		if i%2 == 1 {
			typ, extra = "route53", map[string]any{"AWS_SECRET_ACCESS_KEY": fmt.Sprintf("secret-%d", i), "AWS_REGION": "us-east-1"}
		}
		cfg.Providers[pn] = config.ProviderCfg{Type: typ, Extra: extra}
		cfg.Zones = append(cfg.Zones, config.Zone{Name: fmt.Sprintf("z%d.example.test", i), TargetIP: "192.0.2.10",
			Certificate: config.Certificate{Issuer: "le", Strategy: "wildcard", Challenge: "dns-01", DNSProvider: pn}})
	}
	var mu sync.Mutex
	var problems []string
	seen := map[string]int{}
	h := newHarness(t, cfg, func(mc *ManagerConfig) {
		mc.ProviderByName = func(name string) (challenge.Provider, error) {
			cf, cfOK := os.LookupEnv("CF_DNS_API_TOKEN")
			aws, awsOK := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
			mu.Lock()
			defer mu.Unlock()
			switch name {
			case "cloudflare":
				if awsOK {
					problems = append(problems, "cloudflare saw AWS_SECRET_ACCESS_KEY="+aws)
				}
				seen[cf]++
			case "route53":
				if !cfOK || cf != "outer-value" {
					problems = append(problems, "route53 saw CF_DNS_API_TOKEN="+cf)
				}
				seen[aws]++
			}
			return fakeDNSProvider{name}, nil
		}
	})
	var wg sync.WaitGroup
	for i := range zones {
		wg.Add(1)
		go func() {
			defer wg.Done()
			z := fmt.Sprintf("z%d.example.test", i)
			if _, err := h.m.Issue(ctx, IssueRequest{Zone: z}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for _, p := range problems {
		t.Error(p)
	}
	for i := range zones {
		want := fmt.Sprintf("token-%d", i)
		if i%2 == 1 {
			want = fmt.Sprintf("secret-%d", i)
		}
		if seen[want] != 1 {
			t.Errorf("provider %d saw its own value %d times (seen %v)", i, seen[want], seen)
		}
	}
	if v := os.Getenv("CF_DNS_API_TOKEN"); v != "outer-value" {
		t.Errorf("CF_DNS_API_TOKEN not restored: %q", v)
	}
	if _, ok := os.LookupEnv("AWS_SECRET_ACCESS_KEY"); ok {
		t.Error("AWS_SECRET_ACCESS_KEY left set")
	}
	if _, ok := os.LookupEnv("AWS_REGION"); ok {
		t.Error("AWS_REGION left set")
	}
}

func TestWithEnvRestoresOnPanic(t *testing.T) {
	t.Setenv("DOORWARDEN_TEST_A", "before")
	func() {
		defer func() { _ = recover() }()
		withEnv(map[string]string{"DOORWARDEN_TEST_A": "during", "DOORWARDEN_TEST_B": "x"}, func() (challenge.Provider, error) {
			panic("boom")
		})
	}()
	if os.Getenv("DOORWARDEN_TEST_A") != "before" {
		t.Error("A not restored")
	}
	if _, ok := os.LookupEnv("DOORWARDEN_TEST_B"); ok {
		t.Error("B left set")
	}
}

// The real lego registry receives the mapped settings: cloudflare built
// with only a token succeeds; without credentials it fails naming the
// variables, never their values.
func TestRealLegoProviderConstruction(t *testing.T) {
	cfg := testConfig()
	h := newHarness(t, cfg, func(mc *ManagerConfig) { mc.ProviderByName = nil })
	if _, err := h.m.dnsChallengeProvider("cf"); err != nil {
		t.Fatal(err)
	}
	// The api_token alias alone is enough for the real constructor.
	cfg.Providers["cf"] = config.ProviderCfg{Type: "cloudflare", Extra: map[string]any{"api_token": "alias-token-value"}}
	if _, err := h.m.dnsChallengeProvider("cf"); err != nil {
		t.Fatalf("api_token alias not mapped: %v", err)
	}
	cfg.Providers["cf"] = config.ProviderCfg{Type: "cloudflare", Extra: map[string]any{"zone_hint": "not-mapped-secret"}}
	_, err := h.m.dnsChallengeProvider("cf")
	if err == nil {
		t.Fatal("want missing credentials error")
	}
	if contains(err.Error(), "not-mapped-secret") {
		t.Fatal("setting value leaked into the error")
	}
	if !contains(h.logs.String(), "zone_hint") || contains(h.logs.String(), "not-mapped-secret") {
		t.Fatalf("ignored key should be logged by name only: %s", h.logs.String())
	}
}

func TestPropagationTimeoutWrapper(t *testing.T) {
	cfg := testConfig()
	cfg.ACME.DNSPropagationTimeout = 7 * 60 * 1e9
	h := newHarness(t, cfg, nil)
	p, err := h.m.dnsChallengeProvider("cf")
	if err != nil {
		t.Fatal(err)
	}
	pt, ok := p.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("no timeout")
	}
	if to, _ := pt.Timeout(); to != 7*60*1e9 {
		t.Fatalf("timeout %v", to)
	}
}

type plainProvider struct{}

func (plainProvider) Present(_, _, _ string) error { return nil }
func (plainProvider) CleanUp(_, _, _ string) error { return nil }

type seqProvider struct{ plainProvider }

func (seqProvider) Sequential() time.Duration { return 42 * time.Second }

type seqTimeoutProvider struct{ seqProvider }

func (seqTimeoutProvider) Timeout() (time.Duration, time.Duration) {
	return time.Minute, 9 * time.Second
}

// Wrapping a provider for the propagation timeout must keep lego's optional
// Sequential() interface exactly when the inner provider has it.
func TestPropagationTimeoutKeepsSequential(t *testing.T) {
	type sequential interface{ Sequential() time.Duration }
	for _, tc := range []struct {
		name     string
		p        challenge.Provider
		seq      bool
		interval time.Duration
	}{
		{"plain", plainProvider{}, false, 2 * time.Second},
		{"sequential", seqProvider{}, true, 2 * time.Second},
		{"sequential+timeout", seqTimeoutProvider{}, true, 9 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := withPropagationTimeout(tc.p, 5*time.Minute)
			s, ok := w.(sequential)
			if ok != tc.seq {
				t.Fatalf("Sequential exposed=%v, want %v", ok, tc.seq)
			}
			if ok && s.Sequential() != 42*time.Second {
				t.Fatalf("Sequential()=%v", s.Sequential())
			}
			pt, ok := w.(challenge.ProviderTimeout)
			if !ok {
				t.Fatal("no Timeout")
			}
			if to, iv := pt.Timeout(); to != 5*time.Minute || iv != tc.interval {
				t.Fatalf("Timeout()=%v,%v", to, iv)
			}
			if _, ok := withPropagationTimeout(tc.p, 0).(sequential); ok != tc.seq {
				t.Fatal("zero timeout must return the provider unchanged")
			}
		})
	}
}
