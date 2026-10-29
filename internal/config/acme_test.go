package config

import (
	"strings"
	"testing"
	"time"
)

func TestACMEDecode(t *testing.T) {
	c := mustLoad(t, base+`
acme:
  certs_dir: /data/certs
  http01_listen: "127.0.0.1:8089"
  dns_propagation_timeout: 3m
  resolvers: ["192.0.2.53:53"]
  issue_timeout: 4m
`)
	a := c.ACME
	if a.CertsDir != "/data/certs" || a.HTTP01Listen != "127.0.0.1:8089" || a.DNSPropagationTimeout != 3*time.Minute ||
		len(a.Resolvers) != 1 || a.IssueTimeout != 4*time.Minute {
		t.Fatalf("got %+v", a)
	}
	if errs := c.Validate(caps(true)); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestACMEValidation(t *testing.T) {
	for _, tc := range []struct{ name, yml, want string }{
		{"negative timeout", base + "acme: {dns_propagation_timeout: -1s}\n", "dns_propagation_timeout"},
		{"relative certs dir", base + "acme: {certs_dir: certs}\n", "certs_dir"},
		{"bad listen", base + "acme: {http01_listen: nope}\n", "http01_listen"},
		{"dns-01 without provider", strings.Replace(base, ", dns_provider: cf", "", 1), "dns_provider is required"},
		{"http-01 without listener", strings.Replace(base, "challenge: dns-01", "challenge: http-01", 1), "requires acme.http01_listen"},
		{"eab half set", strings.Replace(base, "le: {email: admin@example.test}", "le: {email: admin@example.test, eab_kid: k}", 1), "eab_kid and eab_hmac"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := mustLoad(t, tc.yml)
			errs := c.Validate(caps(true))
			found := false
			for _, e := range errs {
				if strings.Contains(e.Error(), tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("want error containing %q, got %v", tc.want, errs)
			}
		})
	}
}
