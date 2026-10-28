package acme

import (
	"slices"
	"strings"
	"testing"

	legodns "github.com/go-acme/lego/v4/providers/dns"
)

func TestCatalogHasCloudflareAndRoute53(t *testing.T) {
	cat := Catalog()
	if len(cat) < 150 {
		t.Fatalf("catalog has only %d providers", len(cat))
	}
	want := map[string][]string{
		"cloudflare": {"CF_DNS_API_TOKEN", "CF_ZONE_API_TOKEN", "CF_API_EMAIL", "CF_API_KEY", "CLOUDFLARE_PROPAGATION_TIMEOUT"},
		"route53":    {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION", "AWS_HOSTED_ZONE_ID"},
	}
	for name, vars := range want {
		p, ok := LookupChallengeProvider(name)
		if !ok {
			t.Fatalf("%s missing from catalog", name)
		}
		for _, v := range vars {
			if !slices.Contains(p.EnvVars, v) {
				t.Errorf("%s: env var %s missing (have %v)", name, v, p.EnvVars)
			}
		}
		if p.Help == "" || !strings.Contains(p.Help, p.DisplayName) {
			t.Errorf("%s: help %q", name, p.Help)
		}
	}
	if !slices.IsSortedFunc(cat, func(a, b ChallengeProvider) int { return strings.Compare(a.Name, b.Name) }) {
		t.Error("catalog not sorted by name")
	}
}

func TestCatalogExcludesUnsafeProviders(t *testing.T) {
	for _, n := range []string{"manual", "exec", "unifi"} {
		if _, ok := LookupChallengeProvider(n); ok {
			t.Errorf("%s must not be offered as a challenge provider", n)
		}
	}
}

// Every catalog name must be constructible through lego's registry (the
// constructor may fail for missing credentials, but never as unknown).
func TestCatalogNamesKnownToLegoRegistry(t *testing.T) {
	for _, p := range Catalog() {
		_, err := legodns.NewDNSChallengeProviderByName(p.Name)
		if err != nil && strings.Contains(err.Error(), "unrecognized DNS provider") {
			t.Errorf("%s: %v", p.Name, err)
		}
	}
}

func TestCatalogReturnsCopies(t *testing.T) {
	a := Catalog()
	a[0].EnvVars[0] = "MUTATED"
	a[0].Name = "MUTATED"
	b := Catalog()
	if b[0].Name == "MUTATED" || b[0].EnvVars[0] == "MUTATED" {
		t.Fatal("Catalog exposes internal state")
	}
}

func TestEnvForSettings(t *testing.T) {
	p, _ := LookupChallengeProvider("cloudflare")
	env, ignored := envForSettings(p, map[string]string{
		"cf_dns_api_token":  "tok",
		"CF_ZONE_API_TOKEN": "ztok",
		"cf-api-key_file":   "/run/secrets/k",
		"api_token":         "x",
		"cloudflare_ttl":    "120",
	})
	want := map[string]string{"CF_DNS_API_TOKEN": "tok", "CF_ZONE_API_TOKEN": "ztok", "CF_API_KEY_FILE": "/run/secrets/k", "CLOUDFLARE_TTL": "120"}
	if len(env) != len(want) {
		t.Fatalf("env %v", keys(env))
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	if !slices.Equal(ignored, []string{"api_token"}) {
		t.Errorf("ignored %v", ignored)
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
