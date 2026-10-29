package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/traefik"
)

const http01YAML = `
zones:
  - name: example.test
    target_ip: 192.0.2.10
    records: {provider: fk, mode: per-host}
    certificate: {issuer: le, strategy: per-host, challenge: http-01}
providers:
  fk: {type: fake}
issuers:
  le: {directory: staging, email: ops@example.test}
settings: {grace_period: 1h, poll_interval: 1h}
traefik: {dynamic_dir: "@DIR@"}
acme: {certs_dir: "@CERTS@", http01_listen: ":8089"}
`

func readChallenge(t *testing.T, dir string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, traefik.ChallengeFile))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), true
}

// A cycle renders the challenge router for the http-01 zone's routes (apex
// included); when the zone stops using http-01 the file is removed.
func TestChallengeRouteRenderedAndRemoved(t *testing.T) {
	e := newEnv(t, http01YAML)
	site := svc("docker", "site")
	site.Options.Apex = true
	e.src.set(nil, site, svc("docker", "www"))
	ctx := context.Background()
	a := e.app()
	a.RunOnce(ctx) // CertEnsure has no executor without a manager; routes are still rendered
	b, ok := readChallenge(t, e.dir)
	if !ok || !strings.Contains(b, "(Host(`example.test`) || Host(`www.example.test`)) && PathPrefix(`/.well-known/acme-challenge/`)") ||
		!strings.Contains(b, "http://doorwarden:8089") || !strings.Contains(b, "- web") {
		t.Fatalf("challenge file (%v):\n%s", ok, b)
	}
	e.cfg.Zones[0].Certificate.Challenge = "dns-01"
	a2 := e.app()
	a2.RunOnce(ctx)
	if b, ok := readChallenge(t, e.dir); ok {
		t.Fatalf("stale challenge file:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(e.dir, traefik.RoutesFile)); err != nil {
		t.Fatal(err)
	}
}

// Before ordering http-01 names not yet in the challenge file the wrapper
// writes them into it (so the CA's validation request is routed), once.
func TestChallengeFirstRendersBeforeOrdering(t *testing.T) {
	e := newEnv(t, http01YAML)
	a := e.app(func(o *Options) { o.ChallengeSettle = -1 })
	var seen []string
	calls := 0
	next := reconcile.ExecutorFunc(func(ctx context.Context, as []reconcile.Action, dry bool) error {
		calls++
		b, _ := readChallenge(t, e.dir)
		seen = append(seen, b)
		return nil
	})
	ex := a.challengeFirst(next)
	act := []reconcile.Action{{Kind: reconcile.CertEnsure, Zone: "example.test", Host: "example.test",
		Names: []string{"example.test"}, Issuer: "le"}}
	ctx := context.Background()
	// Dry run: nothing written.
	if err := ex.Apply(ctx, act, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := readChallenge(t, e.dir); ok {
		t.Fatal("dry run wrote the challenge file")
	}
	if err := ex.Apply(ctx, act, false); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !strings.Contains(seen[1], "rule: Host(`example.test`) && PathPrefix") {
		t.Fatalf("calls %d, file at order time:\n%s", calls, seen[len(seen)-1])
	}
	// Already routed: no re-render (the file is left as is).
	if err := os.Remove(filepath.Join(e.dir, traefik.ChallengeFile)); err != nil {
		t.Fatal(err)
	}
	if err := ex.Apply(ctx, act, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := readChallenge(t, e.dir); ok {
		t.Fatal("re-rendered for an already routed name")
	}
	// Not an http-01 zone: untouched.
	other := []reconcile.Action{{Kind: reconcile.CertEnsure, Zone: "other.test", Names: []string{"x.other.test"}}}
	if names := a.pendingChallenge(other); len(names) != 0 {
		t.Fatalf("pending: %v", names)
	}
}
