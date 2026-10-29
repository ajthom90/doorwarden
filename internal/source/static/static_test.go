package static

import (
	"context"
	"testing"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
)

func list(t *testing.T, es ...config.StaticService) ([]model.Service, *Source) {
	t.Helper()
	s := New(Config{Services: es})
	out, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return out, s
}

func TestFieldMapping(t *testing.T) {
	out, s := list(t, config.StaticService{ID: "app", Name: "static-app", Host: "192.0.2.10", Port: 8080, Scheme: "http",
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

func TestKeyFromNameSlugAndDefaults(t *testing.T) {
	out, _ := list(t, config.StaticService{Name: "My App", Host: "h.example.test"})
	if out[0].Key != "static:my-app" || out[0].Backend.Scheme != "http" || out[0].Backend.Port != 80 {
		t.Fatalf("%+v", out[0])
	}
}

func TestSkipVerifyImpliesHTTPS(t *testing.T) {
	out, _ := list(t, config.StaticService{Name: "a", Host: "198.51.100.5", SkipVerify: true})
	if b := out[0].Backend; b.Scheme != "https" || !b.SkipVerify || b.Port != 443 {
		t.Fatalf("%+v", b)
	}
}

func TestUpstreamOverrides(t *testing.T) {
	out, _ := list(t, config.StaticService{Name: "y", Upstream: "https://198.51.100.7:8443"})
	if b := out[0].Backend; b.Scheme != "https" || b.Host != "198.51.100.7" || b.Port != 8443 {
		t.Fatalf("%+v", b)
	}
}

func TestHostnameTargetsUntouched(t *testing.T) {
	out, _ := list(t, config.StaticService{Name: "a", Host: "static-app.example.test", Port: 9000})
	if out[0].Backend.Host != "static-app.example.test" || out[0].State != model.StateDiscovered {
		t.Fatalf("%+v", out[0])
	}
}

func TestInvalidDefinitionsBecomeErrorWithoutBackend(t *testing.T) {
	cases := []config.StaticService{
		{Host: "192.0.2.1", Port: 80},
		{Name: "a", Port: 80},
		{Name: "c", Host: "192.0.2.1", Port: 65536},
		{Name: "d", Host: "192.0.2.1", Scheme: "ftp"},
		{Name: "e", Upstream: "http://h.example.test/path"},
		{Name: "f", Host: "h.example.test:80"},
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
}

func TestSortedAndDuplicatesBothReturned(t *testing.T) {
	out, _ := list(t,
		config.StaticService{Name: "zed", Host: "192.0.2.1", Port: 1},
		config.StaticService{Name: "dup", Host: "192.0.2.2", Port: 2},
		config.StaticService{Name: "dup", Host: "192.0.2.3", Port: 3},
		config.StaticService{Name: "alpha", Host: "192.0.2.4", Port: 4})
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

func TestRepeatedListDoesNotAccumulateWarnings(t *testing.T) {
	s := New(Config{Services: []config.StaticService{{Name: "bad", Host: "h.example.test:80"}}})
	for i := 0; i < 3; i++ {
		if _, err := s.List(context.Background()); err != nil {
			t.Fatal(err)
		}
		if w := s.Warnings(); len(w) != 1 {
			t.Fatalf("list %d: warnings %v", i, w)
		}
	}
}

func TestApexMapped(t *testing.T) {
	out, _ := list(t, config.StaticService{Name: "site", Host: "192.0.2.10", Zone: "example.test", Apex: true},
		config.StaticService{Name: "www", Host: "192.0.2.10", Zone: "example.test"})
	if !out[0].Options.Apex || out[1].Options.Apex {
		t.Fatalf("%+v", out)
	}
}
