package config

import (
	"strings"
	"testing"
)

// certificate.dns_provider must name a provider whose type is a lego DNS
// provider; record-only types and unknown types are rejected at load time.
func TestCertDNSProviderTypeValidatedAtLoad(t *testing.T) {
	for _, tc := range []struct {
		typ, want string
	}{
		{"pihole", "record-only"},
		{"adguard", "record-only"},
		{"unifi", "record-only"},
		{"no-such-dns", "not a supported ACME DNS provider"},
		{"cloudflare", ""},
		{"technitium", ""},
	} {
		yml := strings.Replace(base, "uni: {type: unifi", "chal: {type: "+tc.typ, 1)
		yml = strings.Replace(yml, "dns_provider: cf", "dns_provider: chal", 1)
		errs := mustLoad(t, yml).Validate(caps(true))
		if tc.want == "" {
			if hasErr(errs, "dns_provider") {
				t.Errorf("%s: %v", tc.typ, errs)
			}
			continue
		}
		if !hasErr(errs, tc.want) || !hasErr(errs, tc.typ) {
			t.Errorf("%s: errs = %v", tc.typ, errs)
		}
	}
}

// An omitted challenge means dns-01, which the wildcard strategy needs.
func TestWildcardWithOmittedChallenge(t *testing.T) {
	yml := strings.Replace(base, "strategy: per-host, challenge: dns-01,", "strategy: wildcard,", 1)
	if !strings.Contains(yml, "strategy: wildcard, dns_provider") {
		t.Fatal("fixture not rewritten")
	}
	if errs := mustLoad(t, yml).Validate(caps(true)); len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	yml = strings.Replace(yml, "strategy: wildcard,", "strategy: wildcard, challenge: http-01,", 1)
	if errs := mustLoad(t, yml).Validate(caps(true)); !hasErr(errs, "wildcard requires challenge dns-01") {
		t.Fatalf("errs = %v", errs)
	}
}
