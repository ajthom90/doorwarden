package acme

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/ajthom90/doorwarden/internal/config"
)

// lazyProvider reads its setting from the environment when it is used, as
// lego's oraclecloud provider does (PrivateRSAKey at request signing).
type lazyProvider struct {
	envVar string
	seen   func(string)
}

func (p lazyProvider) Present(string, string, string) error { p.seen(os.Getenv(p.envVar)); return nil }
func (p lazyProvider) CleanUp(string, string, string) error { p.seen(os.Getenv(p.envVar)); return nil }

type trace struct {
	mu  sync.Mutex
	evs []string
}

func (t *trace) add(s string) { t.mu.Lock(); t.evs = append(t.evs, s); t.mu.Unlock() }
func (t *trace) list() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.evs...)
}

// A provider that reads its settings lazily (oraclecloud) still sees them
// during the order, and providers are only constructed once the process-wide
// order slot is held: a second zone's provider is not built (and its
// settings not put into the environment) while the lazy order runs.
func TestLazyEnvProviderSeesSettingsDuringOrder(t *testing.T) {
	const keyPath = "/run/doorwarden/oci-key-path.pem"
	cfg := testConfig()
	cfg.Providers["oc"] = config.ProviderCfg{Type: "oraclecloud", Extra: map[string]any{"oci_private_key_path": keyPath}}
	cfg.Zones[0].Certificate.DNSProvider = "oc"
	z2 := cfgZone("second.test")
	cfg.Zones = append(cfg.Zones, z2)
	os.Unsetenv("OCI_PRIVATE_KEY_PATH")

	tr := &trace{}
	inPresent := make(chan struct{})
	proceed := make(chan struct{})
	h := newHarness(t, cfg, func(mc *ManagerConfig) {
		mc.ProviderByName = func(name string) (challenge.Provider, error) {
			tr.add("construct:" + name)
			if name == "oraclecloud" {
				return lazyProvider{envVar: "OCI_PRIVATE_KEY_PATH", seen: func(v string) { tr.add("lazy-saw:" + v) }}, nil
			}
			return fakeDNSProvider{name}, nil
		}
	})
	ca := h.m.obtain
	h.m.obtain = func(ctx context.Context, o order) (obtained, error) {
		if _, lazy := o.Provider.(lazyProvider); lazy || isLazyWrapped(o.Provider) {
			close(inPresent)
			<-proceed
		}
		_ = o.Provider.Present("d", "t", "k")
		return ca(ctx, o)
	}

	done1 := make(chan error, 1)
	go func() { _, err := h.m.Issue(ctx, wildcardReq()); done1 <- err }()
	<-inPresent
	done2 := make(chan error, 1)
	go func() {
		_, err := h.m.Issue(ctx, IssueRequest{Zone: "second.test", Names: []string{"*.second.test", "second.test"}})
		done2 <- err
	}()
	time.Sleep(100 * time.Millisecond)
	for _, e := range tr.list() {
		if e == "construct:cloudflare" {
			t.Fatalf("second provider constructed while the first order holds the slot: %v", tr.list())
		}
	}
	close(proceed)
	if err := <-done1; err != nil {
		t.Fatal(err)
	}
	if err := <-done2; err != nil {
		t.Fatal(err)
	}
	got := tr.list()
	want := []string{"construct:oraclecloud", "lazy-saw:" + keyPath, "construct:cloudflare"}
	if len(got) != len(want) {
		t.Fatalf("trace %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trace %v, want %v", got, want)
		}
	}
	if v, ok := os.LookupEnv("OCI_PRIVATE_KEY_PATH"); ok {
		t.Fatalf("environment not restored: %q", v)
	}
}

func isLazyWrapped(p challenge.Provider) bool {
	switch w := p.(type) {
	case timeoutProvider:
		_, ok := w.Provider.(lazyProvider)
		return ok
	case sequentialTimeoutProvider:
		_, ok := w.Provider.(lazyProvider)
		return ok
	}
	return false
}

// The lazy set covers the providers found by the audit.
func TestLazyEnvProviderSet(t *testing.T) {
	for _, n := range []string{"oraclecloud", "namecheap"} {
		if !lazyEnvProviders[n] {
			t.Errorf("%s reads settings after construction; it must be in lazyEnvProviders", n)
		}
	}
	if lazyEnvProviders["cloudflare"] {
		t.Error("cloudflare reads its settings in the constructor")
	}
}
