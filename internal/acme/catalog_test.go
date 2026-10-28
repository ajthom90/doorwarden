package acme

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/acme/legonames"
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

// Hermetic: the generator checks every name against lego's registry source
// (no constructor runs here; see catalog_slow_test.go, tag acme_slow). The
// config-side name list is generated from the same source.
func TestCatalogMatchesLegoNames(t *testing.T) {
	var cat []string
	for _, p := range Catalog() {
		cat = append(cat, p.Name)
	}
	if !slices.Equal(cat, legonames.Names()) {
		t.Fatalf("catalog and legonames differ; run go generate ./internal/acme")
	}
	for _, n := range []string{"cloudflare", "route53", "technitium", "rfc2136"} {
		if !legonames.Known(n) {
			t.Errorf("%s not known", n)
		}
	}
	for _, n := range []string{"unifi", "pihole", "adguard", "exec", "manual", ""} {
		if legonames.Known(n) {
			t.Errorf("%s known", n)
		}
	}
}

// Every documented variable is a primary upper-case name.
func TestCatalogEnvNamesWellFormed(t *testing.T) {
	re := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	for _, p := range Catalog() {
		for _, v := range p.EnvVars {
			if !re.MatchString(v) {
				t.Errorf("%s: %q", p.Name, v)
			}
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
		"cf_dns_api_token":   "tok",
		"CF_ZONE_API_TOKEN":  "ztok",
		"cf-api-key_file":    "/run/secrets/k",
		"api_token":          "x",
		"cloudflare_ttl":     "120",
		"zone_hint":          "y",
		"rfc2136_nameserver": "z",
	})
	want := map[string]string{"CF_DNS_API_TOKEN": "tok", "CF_ZONE_API_TOKEN": "ztok", "CF_API_KEY_FILE": "/run/secrets/k", "CLOUDFLARE_TTL": "120",
		"CLOUDFLARE_DNS_API_TOKEN": "x"}
	if len(env) != len(want) {
		t.Fatalf("env %v", keys(env))
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	if !slices.Equal(ignored, []string{"rfc2136_nameserver", "zone_hint"}) {
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

// Per-type aliases: the shared providers: entry's record-provider key
// api_token feeds lego's cloudflare token. Legacy lego aliases (RFC2136_*)
// are not accepted, only the documented primary names.
func TestSettingAliases(t *testing.T) {
	cf, _ := LookupChallengeProvider("cloudflare")
	env, ignored := envForSettings(cf, map[string]string{"API_TOKEN": "a"})
	if env["CLOUDFLARE_DNS_API_TOKEN"] != "a" || len(ignored) != 0 {
		t.Fatalf("%v %v", env, ignored)
	}
	if !isCredentialSetting(cf, "api_token", settingEnvName(cf, "api_token")) {
		t.Fatal("alias of a credential is not a credential")
	}
	r2, _ := LookupChallengeProvider("rfc2136")
	env, ignored = envForSettings(r2, map[string]string{"rfc2136_nameserver": "192.0.2.53", "dnsupdate_nameserver": "192.0.2.53"})
	if _, ok := env["RFC2136_NAMESERVER"]; ok || env["DNSUPDATE_NAMESERVER"] == "" || !slices.Equal(ignored, []string{"rfc2136_nameserver"}) {
		t.Fatalf("%v %v", env, ignored)
	}
	// Aliases are per type: api_token means nothing to route53.
	r53, _ := LookupChallengeProvider("route53")
	if _, ignored := envForSettings(r53, map[string]string{"api_token": "a"}); !slices.Equal(ignored, []string{"api_token"}) {
		t.Fatalf("%v", ignored)
	}
}

// An alias marked Credential is a credential even when neither its key nor
// its variable looks like one.
func TestCredentialAliasFlag(t *testing.T) {
	cf, _ := LookupChallengeProvider("cloudflare")
	settingAliases["cloudflare"]["ENDPOINT_REF"] = settingAlias{Env: "CLOUDFLARE_ENDPOINT_REF", Credential: true}
	defer delete(settingAliases["cloudflare"], "ENDPOINT_REF")
	if !isCredentialSetting(cf, "endpoint_ref", settingEnvName(cf, "endpoint_ref")) {
		t.Fatal("credential alias not treated as a credential")
	}
	settingAliases["cloudflare"]["ENDPOINT_REF"] = settingAlias{Env: "CLOUDFLARE_ENDPOINT_REF"}
	if isCredentialSetting(cf, "endpoint_ref", settingEnvName(cf, "endpoint_ref")) {
		t.Fatal("plain alias treated as a credential")
	}
}
