package config

import (
	"strings"
	"testing"
)

func TestTraefikTLSDefaults(t *testing.T) {
	c := mustLoad(t, base)
	if got := c.Traefik.TraefikTLS; got != (TraefikTLS{TLSMinVersion: "VersionTLS12"}) {
		t.Fatalf("got %+v", got)
	}
	if c.CertsRoot() != "/data/certs" {
		t.Fatalf("certs root %q", c.CertsRoot())
	}
}

func TestTraefikTLSDecode(t *testing.T) {
	c := mustLoad(t, base+`
traefik:
  cert_path_prefix: /srv/certs
  tls_min_version: VersionTLS13
  sni_strict: true
  serve_expired: true
acme:
  certs_dir: /var/lib/dw/certs
`)
	want := TraefikTLS{TLSMinVersion: "VersionTLS13", SNIStrict: true, ServeExpired: true}
	if c.Traefik.TraefikTLS != want || c.Traefik.CertPathPrefix != "/srv/certs" || c.CertsRoot() != "/var/lib/dw/certs" {
		t.Fatalf("got %+v %q", c.Traefik, c.CertsRoot())
	}
	if errs := c.Validate(caps(true)); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestTraefikTLSValidation(t *testing.T) {
	for _, tc := range []struct{ name, yml, want string }{
		{"tls 1.1", "traefik: {tls_min_version: VersionTLS11}\n", "tls_min_version"},
		{"lowercase", "traefik: {tls_min_version: versiontls12}\n", "tls_min_version"},
		{"bare number", "traefik: {tls_min_version: \"1.3\"}\n", "tls_min_version"},
		{"certs dir with ..", "acme: {certs_dir: /data/../certs}\n", "acme.certs_dir"},
		{"certs dir with .", "acme: {certs_dir: /data/./certs}\n", "acme.certs_dir"},
		{"prefix with ..", "traefik: {cert_path_prefix: /certs/../x}\n", "cert_path_prefix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := mustLoad(t, base+tc.yml)
			errs := c.Validate(caps(true))
			found := false
			for _, e := range errs {
				found = found || strings.Contains(e.Error(), tc.want)
			}
			if !found {
				t.Fatalf("no %s error in %v", tc.want, errs)
			}
		})
	}
	for _, k := range []string{"tls_minversion", "sniStrict", "certs_root"} {
		if _, err := loadStr(t, base+"traefik:\n  "+k+": x\n", nil); err == nil {
			t.Fatalf("unknown key %s accepted", k)
		}
	}
}

func TestDefaultCertZone(t *testing.T) {
	zone := func(n string) Zone { return Zone{Name: n} }
	for _, tc := range []struct {
		name  string
		zones []Zone
		dz    string
		want  string
	}{
		{"no zones", nil, "", ""},
		{"one zone", []Zone{zone("Example.Test.")}, "", "example.test"},
		{"two zones, no default", []Zone{zone("a.test"), zone("b.test")}, "", ""},
		{"two zones, default", []Zone{zone("a.test"), zone("b.test")}, "B.test", "b.test"},
		{"one zone, default", []Zone{zone("a.test")}, "a.test", "a.test"},
		{"three zones, default", []Zone{zone("a.test"), zone("b.test"), zone("c.test")}, "c.test", "c.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{Zones: tc.zones, Settings: Settings{DefaultZone: tc.dz}}
			if got := c.DefaultCertZone(); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
