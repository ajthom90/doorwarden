//go:build acme_slow

package acme

import (
	"os"
	"strings"
	"testing"

	legodns "github.com/go-acme/lego/v4/providers/dns"
)

// Every catalog name is constructible through lego's registry (the
// constructor may fail for missing credentials, but never as unknown). The
// constructors run with an empty environment, so no ambient credential is
// used; some may still try instance metadata endpoints, hence the tag.
func TestCatalogNamesKnownToLegoRegistry(t *testing.T) {
	saved := os.Environ()
	os.Clearenv()
	t.Cleanup(func() {
		os.Clearenv()
		for _, kv := range saved {
			k, v, _ := strings.Cut(kv, "=")
			os.Setenv(k, v)
		}
	})
	for _, p := range Catalog() {
		_, err := legodns.NewDNSChallengeProviderByName(p.Name)
		if err != nil && strings.Contains(err.Error(), "unrecognized DNS provider") {
			t.Errorf("%s: %v", p.Name, err)
		}
	}
}
