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

// envForSettings maps provider settings to lego environment variables. A
// setting key matches a documented variable case-insensitively with '-'
// read as '_' (cf_dns_api_token => CF_DNS_API_TOKEN); <VAR>_FILE is accepted
// for every documented VAR. Other keys (for example the record-provider
// settings of a shared providers: entry) are returned in ignored, sorted;
// their values are never returned or logged.
func envForSettings(p ChallengeProvider, settings map[string]string) (env map[string]string, ignored []string) {
	known := make(map[string]bool, len(p.EnvVars)*2)
	for _, v := range p.EnvVars {
		known[v] = true
		known[v+"_FILE"] = true
	}
	env = map[string]string{}
	for k, v := range settings {
		n := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
		if known[n] {
			env[n] = v
			continue
		}
		ignored = append(ignored, k)
	}
	sort.Strings(ignored)
	return env, ignored
}
