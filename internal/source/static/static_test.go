package static

import (
	"context"
	"testing"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
)

func list(t *testing.T, es ...Entry) ([]model.Service, *Source) {
	t.Helper()
	s := New(Config{Services: es})
	out, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return out, s
}

func TestFieldMapping(t *testing.T) {
	out, s := list(t, Entry{ID: "app", Name: "static-app", Host: "192.0.2.10", Port: 8080, Scheme: "http",
		Zone: "example.test", Websockets: true, Middlewares: []string{"auth"}, Rename: "nice", Skip: true})
	if s.Name() != "static" || len(out) != 1 {
		t.Fatalf("name=%q out=%+v", s.Name(), out)
	}
	g := out[0]
	if g.Key != "static:app" || g.Source != "static" || g.Name != "static-app" || g.Zone != "example.test" || g.State != model.StateDiscovered {
		t.Fatalf("%+v", g)
	}
	if g.Backend != (model.Backend{Scheme: "http", Host: "192.0.2.10", Port: 8080}) {
		t.Fatalf("backend %+v", g.Backend)
	}
	o := g.Options
	if !o.Websockets || !o.Skip || o.Rename != "nice" || len(o.Middlewares) != 1 || o.Middlewares[0] != "auth" {
		t.Fatalf("opts %+v", o)
	}
}

func TestKeyFallsBackToNameAndDefaultScheme(t *testing.T) {
	out, _ := list(t, Entry{Name: "n1", Host: "h.example.test", Port: 80})
	if out[0].Key != "static:n1" || out[0].Backend.Scheme != "http" {
		t.Fatalf("%+v", out[0])
	}
}

func TestSkipVerifyImpliesHTTPS(t *testing.T) {
	out, _ := list(t, Entry{Name: "a", Host: "198.51.100.5", Port: 443, SkipVerify: true})
	if b := out[0].Backend; b.Scheme != "https" || !b.SkipVerify {
		t.Fatalf("%+v", b)
	}
}

func TestHostnameTargetsUntouched(t *testing.T) {
	out, _ := list(t, Entry{Name: "a", Host: "static-app.example.test", Port: 9000})
	if out[0].Backend.Host != "static-app.example.test" || out[0].State != model.StateDiscovered {
		t.Fatalf("%+v", out[0])
	}
}

func TestInvalidDefinitionsBecomeErrorWithoutBackend(t *testing.T) {
	cases := []Entry{
		{Name: "", Host: "192.0.2.1", Port: 80},
		{Name: "a", Host: "", Port: 80},
		{Name: "b", Host: "192.0.2.1", Port: 0},
		{Name: "c", Host: "192.0.2.1", Port: 65536},
		{Name: "d", Host: "192.0.2.1", Port: 80, Scheme: "ftp"},
	}
	out, s := list(t, cases...)
	if len(out) != len(cases) {
		t.Fatalf("len %d", len(out))
	}
	for _, g := range out {
		if g.State != model.StateError || g.Backend.Host != "" || g.Backend.Port != 0 {
			t.Fatalf("%+v", g)
		}
	}
	if len(s.Warnings()) != len(cases) {
		t.Fatalf("warnings %v", s.Warnings())
	}
	// warnings reset on next List
	s.cfg.Services = nil
	_, _ = s.List(context.Background())
	if len(s.Warnings()) != 0 {
		t.Fatal("warnings not reset")
	}
}

func TestSortedAndDuplicatesBothReturned(t *testing.T) {
	out, _ := list(t,
		Entry{Name: "zed", Host: "192.0.2.1", Port: 1},
		Entry{Name: "dup", Host: "192.0.2.2", Port: 2},
		Entry{Name: "dup", Host: "192.0.2.3", Port: 3},
		Entry{Name: "alpha", Host: "192.0.2.4", Port: 4})
	if len(out) != 4 {
		t.Fatalf("len %d", len(out))
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].Key > out[i].Key {
			t.Fatalf("unsorted: %v", out)
		}
	}
	if out[1].Key != "static:dup" || out[2].Key != "static:dup" || out[1].Backend.Host == out[2].Backend.Host {
		t.Fatalf("dups: %+v %+v", out[1], out[2])
	}
}

func TestFromConfig(t *testing.T) {
	e := FromConfig(config.StaticService{Name: "x", Host: "192.0.2.9", Port: 81})
	if e.Name != "x" || e.Host != "192.0.2.9" || e.Port != 81 {
		t.Fatalf("%+v", e)
	}
	e = FromConfig(config.StaticService{Name: "y", Upstream: "https://198.51.100.7:8443"})
	out, _ := list(t, e)
	if b := out[0].Backend; b.Scheme != "https" || b.Host != "198.51.100.7" || b.Port != 8443 {
		t.Fatalf("%+v", b)
	}
	e = FromConfig(config.StaticService{Name: "z", Upstream: "not a url ::"})
	out, _ = list(t, e)
	if out[0].State != model.StateError {
		t.Fatalf("%+v", out[0])
	}
}
