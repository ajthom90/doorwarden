package dns_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
)

type stub struct{ caps dns.Capabilities }

func (s *stub) Type() string                   { return "stub" }
func (s *stub) Capabilities() dns.Capabilities { return s.caps }
func (s *stub) Test(context.Context) error     { return nil }
func (s *stub) ListRecords(context.Context, string) ([]dns.Record, error) {
	return nil, nil
}
func (s *stub) CreateRecord(_ context.Context, _ string, r dns.Record) (dns.Record, error) {
	return r, nil
}
func (s *stub) UpdateRecord(_ context.Context, _ string, r dns.Record) (dns.Record, error) {
	return r, nil
}
func (s *stub) DeleteRecord(context.Context, string, dns.Record) error { return nil }

func reg(t *testing.T, typ string, f dns.Factory, schema dns.ConfigSchema, c dns.Capabilities) {
	t.Helper()
	dns.Register(typ, f, schema, c)
	t.Cleanup(func() { dns.Unregister(typ) })
}

func factory(dns.Capabilities) dns.Factory {
	return func(cfg map[string]any, sr dns.SecretResolver) (dns.Provider, error) { return &stub{}, nil }
}

func mustPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	f()
}

func TestRegisterDuplicatePanics(t *testing.T) {
	reg(t, "t-dup", factory(dns.Capabilities{}), dns.ConfigSchema{}, dns.Capabilities{})
	mustPanic(t, func() {
		reg(t, "t-dup", factory(dns.Capabilities{}), dns.ConfigSchema{}, dns.Capabilities{})
	})
}

func TestRegisterEmptyTypePanics(t *testing.T) {
	mustPanic(t, func() { dns.Register("", factory(dns.Capabilities{}), dns.ConfigSchema{}, dns.Capabilities{}) })
}

func TestNewUnknownTypeListsKnown(t *testing.T) {
	reg(t, "t-known", factory(dns.Capabilities{}), dns.ConfigSchema{}, dns.Capabilities{})
	_, err := dns.New("nope", nil, nil)
	if err == nil || !strings.Contains(err.Error(), `"nope"`) || !strings.Contains(err.Error(), "t-known") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewRequiredFieldMissing(t *testing.T) {
	reg(t, "t-req", factory(dns.Capabilities{}), dns.ConfigSchema{Fields: []dns.Field{
		{Name: "api_token", Secret: true, Required: true}, {Name: "opt"},
	}}, dns.Capabilities{})
	_, err := dns.New("t-req", map[string]any{"opt": "x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "api_token") {
		t.Fatalf("err = %v", err)
	}
	if _, err := dns.New("t-req", map[string]any{"api_token": "ref"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestTypesSorted(t *testing.T) {
	reg(t, "t-zz", factory(dns.Capabilities{}), dns.ConfigSchema{}, dns.Capabilities{})
	reg(t, "t-aa", factory(dns.Capabilities{}), dns.ConfigSchema{}, dns.Capabilities{})
	ts := dns.Types()
	if !sort.StringsAreSorted(ts) || len(ts) < 2 {
		t.Fatalf("types = %v", ts)
	}
}

func TestCapsForAndSchemaFor(t *testing.T) {
	want := dns.Capabilities{WildcardA: true, TTL: true}
	reg(t, "t-caps", func(map[string]any, dns.SecretResolver) (dns.Provider, error) {
		t.Fatal("factory must not be called")
		return nil, nil
	}, dns.ConfigSchema{Fields: []dns.Field{{Name: "a"}}}, want)
	got, ok := dns.CapsFor("t-caps")
	if !ok || got != want {
		t.Fatalf("caps = %+v %v", got, ok)
	}
	if _, ok := dns.CapsFor("missing"); ok {
		t.Fatal("expected !ok")
	}
	s, ok := dns.SchemaFor("t-caps")
	if !ok || len(s.Fields) != 1 {
		t.Fatalf("schema = %+v", s)
	}
	if _, ok := dns.SchemaFor("missing"); ok {
		t.Fatal("expected !ok")
	}
}

func TestConfigCaps(t *testing.T) {
	reg(t, "t-wild", factory(dns.Capabilities{}), dns.ConfigSchema{}, dns.Capabilities{WildcardA: true})
	reg(t, "t-nowild", factory(dns.Capabilities{}), dns.ConfigSchema{}, dns.Capabilities{})
	f := dns.ConfigCaps()
	if c, ok := f("t-wild"); !ok || !c.WildcardA {
		t.Fatal("t-wild")
	}
	if c, ok := f("t-nowild"); !ok || c.WildcardA {
		t.Fatal("t-nowild")
	}
	if _, ok := f("missing"); ok {
		t.Fatal("missing")
	}
}

func TestNewRejectsUnknownKeys(t *testing.T) {
	reg(t, "t-req", factory(dns.Capabilities{}), dns.ConfigSchema{Fields: []dns.Field{
		{Name: "api_token", Secret: true, Required: true}, {Name: "opt"},
	}}, dns.Capabilities{})
	_, err := dns.New("t-req", map[string]any{"api_token": "ref", "opt": "x", "wildcrd": true}, nil)
	if err == nil || !strings.Contains(err.Error(), `"wildcrd"`) || !strings.Contains(err.Error(), "valid fields: api_token, opt") {
		t.Fatalf("err = %v", err)
	}
}
