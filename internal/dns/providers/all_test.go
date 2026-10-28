package providers_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

func TestAllTypesRegistered(t *testing.T) {
	want := []string{"adguard", "cloudflare", "fake", "pihole", "rfc2136", "route53", "technitium", "unifi"}
	if got := dns.Types(); !reflect.DeepEqual(got, want) {
		t.Fatalf("types = %v", got)
	}
	for _, typ := range want {
		if _, ok := dns.SchemaFor(typ); !ok {
			t.Fatalf("%s: no schema", typ)
		}
	}
}

// TestSecretFieldsReadViaResolveField feeds every Secret-flagged schema field a
// "secret:" reference. Only a factory that reads the field through
// dns.ResolveField asks the resolver for it, so a field that is read as a plain
// string (and would therefore treat the reference as a literal) is caught.
func TestSecretFieldsReadViaResolveField(t *testing.T) {
	base := map[string]map[string]any{
		"cloudflare": {"api_token": "x"},
		"route53":    {"access_key_id": "AKIAX", "secret_access_key": "x"},
		"rfc2136":    {"server": "127.0.0.1", "key_name": "k", "key_secret": "c2VjcmV0"},
		"unifi":      {"url": "https://gw.example.test", "api_key": "x"},
		"technitium": {"url": "https://t.example.test", "token": "x", "password": "x", "username": "u"},
		"pihole":     {"url": "https://p.example.test", "password": "x"},
		"adguard":    {"url": "https://a.example.test", "username": "u", "password": "x"},
	}
	for typ, cfg := range base {
		sch, _ := dns.SchemaFor(typ)
		for _, f := range sch.Fields {
			if !f.Secret {
				continue
			}
			c := map[string]any{}
			for k, v := range cfg {
				c[k] = v
			}
			c[f.Name] = "secret:ref-" + f.Name
			sr := &recorder{}
			_, _ = dns.New(typ, c, sr)
			if !sr.asked["ref-"+f.Name] {
				t.Errorf("%s: secret field %q is not read through dns.ResolveField", typ, f.Name)
			}
		}
	}
}

type recorder struct{ asked map[string]bool }

func (r *recorder) Resolve(ref string) (secrets.Secret, error) {
	if r.asked == nil {
		r.asked = map[string]bool{}
	}
	r.asked[ref] = true
	return secrets.Secret("resolved-value"), nil
}

// TestProviderStructsDoNotLeakSecrets formats each constructed provider with
// %v, %+v and %#v and requires the secret not to appear.
func TestProviderStructsDoNotLeakSecrets(t *testing.T) {
	const sec = "LEAKCHECK-s3cret-value"
	cfgs := map[string]map[string]any{
		"cloudflare": {"api_token": sec},
		"route53":    {"access_key_id": "AKIALEAKCHECK", "secret_access_key": sec},
		"rfc2136":    {"server": "127.0.0.1", "key_name": "k", "key_secret": "TEFLQ0hFQ0tzM2NyZXQ="},
		"unifi":      {"url": "https://gw.example.test", "api_key": sec},
		"technitium": {"url": "https://t.example.test", "token": sec},
		"pihole":     {"url": "https://p.example.test", "password": sec},
		"adguard":    {"url": "https://a.example.test", "username": "u", "password": sec},
	}
	for typ, cfg := range cfgs {
		p, err := dns.New(typ, cfg, nil)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		// a DEREFERENCED copy of the provider (String/GoString have pointer
		// receivers) must not print credentials either: they live behind a
		// pointer to a redacting struct
		deref := reflect.ValueOf(p).Elem().Interface()
		for _, f := range []string{"%v", "%+v", "%#v"} {
			for _, v := range []any{p, deref} {
				out := fmt.Sprintf(f, v)
				for _, needle := range []string{sec, "TEFLQ0hFQ0tzM2NyZXQ=", "Basic ", "Bearer", "AKIALEAKCHECK"} {
					if strings.Contains(out, needle) {
						t.Errorf("%s %s (%T) leaks %q: %.200s", typ, f, v, needle, out)
					}
				}
			}
			out := fmt.Sprintf(f, p)
			for _, needle := range []string{sec, "TEFLQ0hFQ0tzM2NyZXQ=", "Basic "} {
				if strings.Contains(out, needle) || strings.Contains(out, "Bearer") {
					t.Errorf("%s %s leaks %q: %.200s", typ, f, needle, out)
				}
			}
		}
	}
}
