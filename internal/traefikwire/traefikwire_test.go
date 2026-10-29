package traefikwire

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/traefik"
)

func TestOptionsFromConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	yml := `
zones:
  - {name: a.test, target_ip: 192.0.2.10}
  - {name: b.test, target_ip: 192.0.2.10}
settings: {default_zone: B.test}
acme: {certs_dir: /var/lib/dw/certs}
traefik:
  entry_point: https
  cert_path_prefix: /mnt/certs
  external_middlewares: [crowdsec@docker]
  tls_min_version: VersionTLS13
  sni_strict: true
  serve_expired: true
`
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	o, to := Options(cfg)
	if !reflect.DeepEqual(o, traefik.Options{EntryPoint: "https", PathPrefix: "/mnt/certs",
		ExternalMiddlewares: []string{"crowdsec@docker"}, MinTLSVersion: "VersionTLS13", SNIStrict: true}) {
		t.Fatalf("%+v", o)
	}
	if to != (traefik.TLSOptions{LocalCertsRoot: "/var/lib/dw/certs", DefaultZone: "b.test", ServeExpired: true}) {
		t.Fatalf("%+v", to)
	}

	// Defaults.
	cfg = &config.Config{Zones: []config.Zone{{Name: "a.test"}}}
	o, to = Options(cfg)
	if o.MinTLSVersion != "" || o.SNIStrict || to.ServeExpired || to.DefaultZone != "a.test" || to.LocalCertsRoot != "/data/certs" {
		t.Fatalf("%+v %+v", o, to)
	}
}
