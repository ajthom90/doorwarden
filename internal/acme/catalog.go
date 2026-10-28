package acme

//go:generate go run ./internal/gencatalog -o zz_gen_catalog.go

import (
	"sort"
	"strings"
)

// ChallengeProvider describes one lego DNS provider usable for DNS-01.
type ChallengeProvider struct {
	// Name is the lego provider code; it is the `type` of a providers: entry
	// referenced by certificate.dns_provider.
	Name        string
	DisplayName string
	URL         string
	// EnvVars are every documented setting (Credentials then Additional).
	// A setting may also be given as <VAR>_FILE naming a file to read.
	EnvVars []string
	// Credentials and Additional split EnvVars as lego documents them; not
	// every credential is required (providers often accept alternatives).
	Credentials, Additional []string
	Help                    string
}

var catalogByName = func() map[string]ChallengeProvider {
	m := make(map[string]ChallengeProvider, len(generatedCatalog))
	for _, p := range generatedCatalog {
		p.EnvVars = append(append([]string{}, p.Credentials...), p.Additional...)
		p.Help = p.DisplayName + " (" + p.URL + "); settings: https://go-acme.github.io/lego/dns/" + p.Name + "/"
		m[p.Name] = p
	}
	return m
}()

// Catalog returns every DNS challenge provider lego offers (except the
// interactive "manual" and the program-running "exec"), sorted by Name.
// The result is a fresh copy.
func Catalog() []ChallengeProvider {
	out := make([]ChallengeProvider, 0, len(catalogByName))
	for _, p := range catalogByName {
		out = append(out, clonePrv(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LookupChallengeProvider returns the catalog entry for a lego provider code.
func LookupChallengeProvider(name string) (ChallengeProvider, bool) {
	p, ok := catalogByName[name]
	if !ok {
		return ChallengeProvider{}, false
	}
	return clonePrv(p), true
}

func clonePrv(p ChallengeProvider) ChallengeProvider {
	p.EnvVars = append([]string(nil), p.EnvVars...)
	p.Credentials = append([]string(nil), p.Credentials...)
	p.Additional = append([]string(nil), p.Additional...)
	return p
}

// settingAlias maps a setting key that is not a lego variable name to the
// variable it feeds, per provider type.
type settingAlias struct {
	Env        string
	Credential bool
}

// settingAliases are the per-type alias keys. cloudflare's api_token is the
// record provider's key in a shared providers: entry; it feeds lego's
// primary token variable CLOUDFLARE_DNS_API_TOKEN (lego reads it before the
// documented CF_DNS_API_TOKEN, so it wins when both are set).
var settingAliases = map[string]map[string]settingAlias{
	"cloudflare": {"API_TOKEN": {Env: "CLOUDFLARE_DNS_API_TOKEN", Credential: true}},
}

// settingKey normalizes a setting key: upper case, '-' read as '_'.
func settingKey(k string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
}

// envForSettings maps provider settings to lego environment variables. A
// setting key matches a documented variable (ChallengeProvider.EnvVars, the
// primary names lego documents) case-insensitively with '-' read as '_'
// (cf_dns_api_token => CF_DNS_API_TOKEN); <VAR>_FILE is accepted for every
// documented VAR; settingAliases adds a few per-type keys. Legacy aliases
// lego also reads (for example RFC2136_* for rfc2136, whose documented
// names are DNSUPDATE_*) are not accepted. Other keys (for example the
// record-provider settings of a shared providers: entry) are returned in
// ignored, sorted; their values are never returned or logged.
func envForSettings(p ChallengeProvider, settings map[string]string) (env map[string]string, ignored []string) {
	known := make(map[string]bool, len(p.EnvVars)*2)
	for _, v := range p.EnvVars {
		known[v] = true
		known[v+"_FILE"] = true
	}
	aliases := settingAliases[p.Name]
	env = map[string]string{}
	for k, v := range settings {
		n := settingKey(k)
		if known[n] {
			env[n] = v
			continue
		}
		if a, ok := aliases[n]; ok {
			env[a.Env] = v
			continue
		}
		ignored = append(ignored, k)
	}
	sort.Strings(ignored)
	return env, ignored
}
