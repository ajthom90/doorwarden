package providers_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
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

const sentinel = "LEAKCHECKs3cretvalue" // 20 characters of valid base64, so it also works as a TSIG secret

// leakConfigs builds every provider with the sentinel in every secret-flagged
// schema field.
func leakConfigs() map[string]map[string]any {
	return map[string]map[string]any{
		"fake":        {},
		"cloudflare":  {"api_token": sentinel},
		"route53":     {"access_key_id": "AKIALEAKCHECKKEY01", "secret_access_key": sentinel},
		"rfc2136":     {"server": "127.0.0.1", "key_name": "k", "key_secret": sentinel},
		"unifi":       {"url": "https://gw.example.test", "api_key": sentinel},
		"technitium":  {"url": "https://t.example.test", "token": sentinel},
		"technitium2": {"url": "https://t.example.test", "username": "u", "password": sentinel},
		"pihole":      {"url": "https://p.example.test", "password": sentinel},
		"adguard":     {"url": "https://a.example.test", "username": "u", "password": sentinel},
	}
}

func needles() []string {
	n := []string{sentinel, "AKIALEAKCHECKKEY01", "Bearer", "Basic "}
	n = append(n, hex.EncodeToString([]byte(sentinel)), strings.ToUpper(hex.EncodeToString([]byte(sentinel))),
		base64.StdEncoding.EncodeToString([]byte(sentinel)), base64.StdEncoding.EncodeToString([]byte("u:"+sentinel)))
	return n
}

func assertNoLeak(t *testing.T, what, out string) {
	t.Helper()
	for _, n := range needles() {
		if strings.Contains(out, n) {
			t.Errorf("%s leaks %q: %.300s", what, n, out)
		}
	}
}

// TestProviderNeverFormatsCredentials formats every provider (and a
// dereferenced copy, and containers holding both) with every verb through
// fmt, json and slog.
func TestProviderNeverFormatsCredentials(t *testing.T) {
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%T", "%p", "%e", "%f", "%c", "%U", "%b", "%o"}
	for name, cfg := range leakConfigs() {
		typ := strings.TrimSuffix(name, "2")
		p, err := dns.New(typ, cfg, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		deref := reflect.ValueOf(p).Elem().Interface()
		shapes := map[string]any{
			"ptr":      p,
			"deref":    deref,
			"struct":   struct{ P any }{p},
			"structD":  struct{ P any }{deref},
			"slice":    []any{p, deref},
			"map":      map[string]any{"p": p, "d": deref},
			"provs":    []dns.Provider{p},
			"ifaceptr": &deref,
		}
		for sh, v := range shapes {
			for _, verb := range verbs {
				assertNoLeak(t, fmt.Sprintf("%s %s %s", name, sh, verb), fmt.Sprintf(verb, v))
			}
			assertNoLeak(t, name+" "+sh+" Sprint", fmt.Sprint(v))
			assertNoLeak(t, name+" "+sh+" Sprintln", fmt.Sprintln(v))
			if b, err := json.Marshal(v); err == nil {
				assertNoLeak(t, name+" "+sh+" json", string(b))
			}
		}
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "p", p, "d", deref)
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "p", p, "d", deref)
		assertNoLeak(t, name+" slog", buf.String())

		// a failing construction must not echo credentials either
		bad := map[string]any{"bogus_key": 1}
		for k, v := range cfg {
			bad[k] = v
		}
		_, err = dns.New(typ, bad, nil)
		if err == nil {
			t.Fatalf("%s: unknown key accepted", name)
		}
		assertNoLeak(t, name+" factory error", fmt.Sprintf("%+v %v %#v", err, err, err))
	}
}

// TestProviderHoldsNoReachableSecret walks each Provider value with reflection
// (unexported fields, pointers, interfaces, slices, maps) through every field
// and container the provider (and doorwarden's httpx.Client) owns, and fails if
// any reachable string or byte slice contains a credential: the property must
// hold structurally, not only for the formatting verbs above.
//
// The walk deliberately stops at the internals of the standard library's
// network types (see walkSkipPkgs): net/http's transport legitimately holds
// recently written request bytes, including the Authorization header, in its
// keep-alive connection buffers. That is outside what fmt can reach through
// the provider and is not something the provider can change without disabling
// keep-alives, which we do not do.
func TestProviderHoldsNoReachableSecret(t *testing.T) {
	for name, cfg := range leakConfigs() {
		p, err := dns.New(strings.TrimSuffix(name, "2"), cfg, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		w := &walker{t: t, name: name, seen: map[uintptr]bool{}}
		w.walk(reflect.ValueOf(p), name)
		if w.nodes < 5 {
			t.Errorf("%s: walked only %d nodes; the walker is not reaching the provider's fields", name, w.nodes)
		}
	}
}

type walker struct {
	t     *testing.T
	name  string
	seen  map[uintptr]bool
	nodes int
}

func (w *walker) leaf(s, path string) {
	for _, n := range needles() {
		if strings.Contains(s, n) {
			w.t.Errorf("%s: credential reachable at %s", w.name, path)
			return
		}
	}
}

// walkSkipPkgs are the standard-library packages whose values the walker does
// not enter (connection pools and their I/O buffers).
var walkSkipPkgs = map[string]bool{"net/http": true, "net": true, "crypto/tls": true, "bufio": true}

func skipType(t reflect.Type) bool {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return walkSkipPkgs[t.PkgPath()]
}

func (w *walker) walk(v reflect.Value, path string) {
	if skipType(v.Type()) {
		return
	}
	w.nodes++
	switch v.Kind() {
	case reflect.String:
		w.leaf(v.String(), path)
	case reflect.Ptr:
		if v.IsNil() || w.seen[v.Pointer()] {
			return
		}
		w.seen[v.Pointer()] = true
		w.walk(v.Elem(), path)
	case reflect.Interface:
		if !v.IsNil() {
			w.walk(v.Elem(), path)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			w.walk(v.Field(i), path+"."+v.Type().Field(i).Name)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			w.leaf(string(v.Bytes()), path)
			return
		}
		if v.IsNil() || w.seen[v.Pointer()] {
			return
		}
		w.seen[v.Pointer()] = true
		for i := 0; i < v.Len(); i++ {
			w.walk(v.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			w.walk(v.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}
	case reflect.Map:
		if v.IsNil() || w.seen[v.Pointer()] {
			return
		}
		w.seen[v.Pointer()] = true
		for it := v.MapRange(); it.Next(); {
			w.walk(it.Key(), path+".key")
			w.walk(it.Value(), path+"[]")
		}
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		// closures are opaque to reflection and print as addresses: this is where
		// credentials are kept
	}
}
