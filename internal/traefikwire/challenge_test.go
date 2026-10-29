package traefikwire

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
)

func loadCfg(t *testing.T, yml string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const http01Cfg = `
zones:
  - name: example.test
    target_ip: 192.0.2.10
    records: {mode: "off"}
    certificate: {issuer: le, strategy: per-host, challenge: http-01}
  - name: other.test
    target_ip: 192.0.2.10
issuers:
  le: {directory: staging, email: ops@example.test}
acme:
  http01_listen: ":8089"
`

func rte(key, host, zone string) store.Route {
	return store.Route{Key: key, Source: key[:strings.IndexByte(key, ':')], Hostname: host, Zone: zone, Scheme: "http", Host: "192.0.2.20", Port: 80}
}

// Only routes of http-01 zones (apex included) plus the pending names; the
// entry point and backend come from the configuration defaults.
func TestChallengeFromConfig(t *testing.T) {
	cfg := loadCfg(t, http01Cfg)
	routes := []store.Route{
		rte("static:site", "example.test", "example.test"),
		rte("static:www", "www.example.test", "example.test"),
		rte("docker:x", "x.other.test", "other.test"),
	}
	ch := Challenge(cfg, routes, []string{"new.example.test", "WWW.example.test."})
	want := &traefik.Challenge{EntryPoint: "web", Backend: "http://doorwarden:8089",
		Hosts: []string{"example.test", "new.example.test", "www.example.test"}}
	if !reflect.DeepEqual(ch, want) {
		t.Fatalf("%+v", ch)
	}
	files, _, err := Render(cfg, routes, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b := string(files[traefik.ChallengeFile])
	if !strings.Contains(b, "(Host(`example.test`) || Host(`www.example.test`)) && PathPrefix") || strings.Contains(b, "other.test") {
		t.Fatalf("challenge file:\n%s", b)
	}
}

// No http-01 zone, or no challenge server: nothing (default behaviour
// unchanged).
func TestChallengeAbsent(t *testing.T) {
	cfg := loadCfg(t, `
zones:
  - {name: example.test, target_ip: 192.0.2.10}
acme:
  http01_listen: ":8089"
`)
	routes := []store.Route{rte("static:site", "example.test", "example.test")}
	if ch := Challenge(cfg, routes, []string{"example.test"}); ch != nil {
		t.Fatalf("%+v", ch)
	}
	files, _, err := Render(cfg, routes, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[traefik.ChallengeFile]; ok || len(files) != 2 {
		t.Fatalf("files: %v", files)
	}
	cfg = loadCfg(t, http01Cfg)
	cfg.ACME.HTTP01Listen = ""
	if ch := Challenge(cfg, routes, nil); ch != nil {
		t.Fatalf("%+v", ch)
	}
	// An http-01 zone without routes: no file.
	cfg = loadCfg(t, http01Cfg)
	files, _, err = Render(cfg, nil, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[traefik.ChallengeFile]; ok {
		t.Fatal("challenge file without wanted hosts")
	}
}
