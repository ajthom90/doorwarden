package providers_test

import (
	"reflect"
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers"
)

func TestAllTypesRegistered(t *testing.T) {
	want := []string{"adguard", "cloudflare", "fake", "pihole", "rfc2136", "route53", "technitium", "unifi"}
	if got := dns.Types(); !reflect.DeepEqual(got, want) {
		t.Fatalf("types = %v", got)
	}
	// secret-flagged fields must never also be required-literals elsewhere; every
	// registered schema lists its secret fields explicitly.
	for _, typ := range want {
		if _, ok := dns.SchemaFor(typ); !ok {
			t.Fatalf("%s: no schema", typ)
		}
	}
}
