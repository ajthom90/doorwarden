// Package legonames lists the lego DNS provider codes doorwarden accepts as
// certificate.dns_provider types. It is generated together with the acme
// catalog (go generate ./internal/acme) and has no dependencies, so config
// validation can use it without importing lego.
package legonames

import "sort"

var set = func() map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}()

// Known reports whether name is a lego DNS provider code doorwarden offers.
func Known(name string) bool { return set[name] }

// Names returns every code, sorted (a fresh copy).
func Names() []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}
