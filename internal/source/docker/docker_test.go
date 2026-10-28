package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/source"
)

type ctr map[string]any

func container(name, state string, labels map[string]string, ports []map[string]any, nets map[string]string) ctr {
	n := map[string]any{}
	for k, ip := range nets {
		n[k] = map[string]any{"IPAddress": ip}
	}
	return ctr{"Id": "id-" + name, "Names": []string{"/" + name}, "State": state,
		"Labels": labels, "Ports": ports, "NetworkSettings": map[string]any{"Networks": n}}
}

func port(priv, pub int) map[string]any {
	p := map[string]any{"PrivatePort": priv, "Type": "tcp"}
	if pub > 0 {
		p["PublicPort"] = pub
		p["IP"] = "0.0.0.0"
	}
	return p
}

func lbl(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func fake(t *testing.T, list []ctr) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/containers/json" || r.URL.Query().Get("all") != "1" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(list)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newSrc(t *testing.T, srv *httptest.Server, cfg Config) *Source {
	t.Helper()
	cfg.Endpoint = "tcp://" + strings.TrimPrefix(srv.URL, "http://")
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func list(t *testing.T, s *Source) []model.Service {
	t.Helper()
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestOptInOnly(t *testing.T) {
	srv := fake(t, []ctr{
		container("a", "running", lbl("doorwarden.enable", "true"), []map[string]any{port(80, 8080)}, nil),
		container("b", "running", lbl("doorwarden.enable", "false"), []map[string]any{port(80, 8081)}, nil),
		container("c", "running", lbl("doorwarden.enable", "yes"), []map[string]any{port(80, 8082)}, nil),
		container("d", "running", lbl(), []map[string]any{port(80, 8083)}, nil),
	})
	got := list(t, newSrc(t, srv, Config{TargetIP: "192.0.2.10"}))
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("got %+v", got)
	}
}

func TestDefaults(t *testing.T) {
	srv := fake(t, []ctr{container("whoami", "running", lbl("doorwarden.enable", "true"),
		[]map[string]any{port(80, 8080), port(80, 8080)}, nil)})
	s := newSrc(t, srv, Config{TargetIP: "192.0.2.10"})
	got := list(t, s)
	want := model.Service{Key: "docker:whoami", Source: "docker", Name: "whoami",
		Backend: model.Backend{Scheme: "http", Host: "192.0.2.10", Port: 8080}, State: model.StateDiscovered}
	if len(got) != 1 || got[0].Key != want.Key || got[0].Source != want.Source || got[0].Name != want.Name ||
		got[0].Backend != want.Backend || got[0].State != want.State || got[0].Zone != "" {
		t.Fatalf("got %+v", got)
	}
}

func TestNetworkIPUsesPrivatePort(t *testing.T) {
	srv := fake(t, []ctr{container("whoami", "running", lbl("doorwarden.enable", "true"),
		[]map[string]any{port(80, 0)}, map[string]string{"proxy": "198.51.100.7", "other": "198.51.100.8"})})
	got := list(t, newSrc(t, srv, Config{TargetIP: "192.0.2.10", Network: "proxy"}))
	if got[0].Backend.Host != "198.51.100.7" || got[0].Backend.Port != 80 || got[0].State != model.StateDiscovered {
		t.Fatalf("got %+v", got[0])
	}
}

func TestNetworkSetButNotAttachedFallsBack(t *testing.T) {
	srv := fake(t, []ctr{container("whoami", "running", lbl("doorwarden.enable", "true"),
		[]map[string]any{port(80, 8080)}, map[string]string{"other": "198.51.100.8"})})
	got := list(t, newSrc(t, srv, Config{TargetIP: "192.0.2.10", Network: "proxy"}))
	if got[0].Backend.Host != "192.0.2.10" || got[0].Backend.Port != 8080 {
		t.Fatalf("got %+v", got[0])
	}
}

func TestNoPublishedPortNoNetworkIsError(t *testing.T) {
	srv := fake(t, []ctr{container("whoami", "running", lbl("doorwarden.enable", "true"),
		[]map[string]any{port(80, 0)}, nil)})
	s := newSrc(t, srv, Config{TargetIP: "192.0.2.10"})
	got := list(t, s)
	if got[0].State != model.StateError || len(s.Warnings()) != 1 {
		t.Fatalf("got %+v warnings %v", got[0], s.Warnings())
	}
}

func TestAmbiguousPortIsError(t *testing.T) {
	srv := fake(t, []ctr{container("multi", "running", lbl("doorwarden.enable", "true"),
		[]map[string]any{port(80, 8080), port(443, 8443)}, nil)})
	s := newSrc(t, srv, Config{TargetIP: "192.0.2.10"})
	got := list(t, s)
	if len(got) != 1 || got[0].State != model.StateError || len(s.Warnings()) != 1 {
		t.Fatalf("got %+v warnings %v", got, s.Warnings())
	}
}

func TestLabelOverrides(t *testing.T) {
	srv := fake(t, []ctr{container("whoami", "running", lbl(
		"doorwarden.enable", "true", "doorwarden.name", "Who Am I", "doorwarden.port", "443",
		"doorwarden.scheme", "https", "doorwarden.zone", "example.test", "doorwarden.skip-verify", "true",
		"doorwarden.websockets", "true", "doorwarden.middlewares", "auth@file, rate@file ,"),
		[]map[string]any{port(80, 8080), port(443, 8443)}, nil)})
	got := list(t, newSrc(t, srv, Config{TargetIP: "192.0.2.10"}))[0]
	if got.State != model.StateDiscovered || got.Name != "Who Am I" || got.Key != "docker:whoami" ||
		got.Zone != "example.test" || got.Backend != (model.Backend{Scheme: "https", Host: "192.0.2.10", Port: 8443, SkipVerify: true}) ||
		!got.Options.Websockets || strings.Join(got.Options.Middlewares, "|") != "auth@file|rate@file" {
		t.Fatalf("got %+v", got)
	}
}

func TestInvalidLabels(t *testing.T) {
	for _, kv := range [][2]string{{"doorwarden.port", "abc"}, {"doorwarden.port", "70000"}, {"doorwarden.scheme", "ftp"},
		{"doorwarden.skip-verify", "maybe"}, {"doorwarden.websockets", "2x"}} {
		srv := fake(t, []ctr{container("whoami", "running", lbl("doorwarden.enable", "true", kv[0], kv[1]),
			[]map[string]any{port(80, 8080)}, nil)})
		s := newSrc(t, srv, Config{TargetIP: "192.0.2.10"})
		got := list(t, s)
		if len(got) != 1 || got[0].State != model.StateError || len(s.Warnings()) != 1 ||
			!strings.Contains(s.Warnings()[0], "whoami") {
			t.Fatalf("%v: got %+v warnings %v", kv, got, s.Warnings())
		}
	}
}

func TestStoppedRetained(t *testing.T) {
	for _, tc := range []struct {
		labels map[string]string
		cfg    Config
		nets   map[string]string
	}{
		{lbl("doorwarden.enable", "true"), Config{TargetIP: "192.0.2.10"}, nil},
		{lbl("doorwarden.enable", "true", "doorwarden.port", "80", "doorwarden.scheme", "https", "doorwarden.skip-verify", "true"), Config{TargetIP: "192.0.2.10"}, nil},
		{lbl("doorwarden.enable", "true", "doorwarden.port", "80"), Config{TargetIP: "192.0.2.10", Network: "proxy"}, map[string]string{"proxy": "198.51.100.7"}},
	} {
		srv := fake(t, []ctr{container("whoami", "exited", tc.labels, nil, tc.nets)})
		got := list(t, newSrc(t, srv, tc.cfg))
		if len(got) != 1 || got[0].State != model.StateStopped || got[0].Key != "docker:whoami" {
			t.Fatalf("got %+v", got)
		}
		b := got[0].Backend
		if b.Host != "" || b.Port != 0 {
			t.Fatalf("backend not empty: %+v", b)
		}
	}
	srv := fake(t, []ctr{container("whoami", "exited", lbl("doorwarden.enable", "true", "doorwarden.scheme", "https", "doorwarden.skip-verify", "true"), nil, nil)})
	if b := list(t, newSrc(t, srv, Config{}))[0].Backend; b != (model.Backend{Scheme: "https", SkipVerify: true}) {
		t.Fatalf("got %+v", b)
	}
}

func TestErrorStateHasNoBackend(t *testing.T) {
	srv := fake(t, []ctr{
		container("amb", "running", lbl("doorwarden.enable", "true"), []map[string]any{port(80, 8080), port(443, 8443)}, nil),
		container("bad", "running", lbl("doorwarden.enable", "true", "doorwarden.port", "x"), []map[string]any{port(80, 8080)}, nil),
	})
	for _, g := range list(t, newSrc(t, srv, Config{TargetIP: "192.0.2.10"})) {
		if g.State != model.StateError || g.Backend.Host != "" || g.Backend.Port != 0 {
			t.Fatalf("got %+v", g)
		}
	}
}

func TestEnableAndSchemeNormalization(t *testing.T) {
	srv := fake(t, []ctr{
		container("a", "running", lbl("doorwarden.enable", " TRUE ", "doorwarden.scheme", " HTTPS ", "doorwarden.name", "  Nice  "), []map[string]any{port(80, 8080)}, nil),
		container("b", "running", lbl("doorwarden.enable", "maybe"), []map[string]any{port(80, 8081)}, nil),
		container("c", "running", lbl("doorwarden.enable", "false"), []map[string]any{port(80, 8082)}, nil),
	})
	s := newSrc(t, srv, Config{TargetIP: "192.0.2.10"})
	got := list(t, s)
	if len(got) != 1 || got[0].Backend.Scheme != "https" || got[0].Name != "Nice" {
		t.Fatalf("got %+v", got)
	}
	if w := s.Warnings(); len(w) != 1 || !strings.Contains(w[0], "\"b\"") {
		t.Fatalf("warnings %v", w)
	}
}

func TestContainerNameSelection(t *testing.T) {
	l := lbl("doorwarden.enable", "true")
	a := container("x", "running", l, []map[string]any{port(80, 8080)}, nil)
	a["Names"] = []string{"/parent/alias", "/real"}
	b := container("x", "running", l, []map[string]any{port(80, 8081)}, nil)
	b["Names"] = []string{"/parent/alias"}
	c := container("x", "running", l, []map[string]any{port(80, 8082)}, nil)
	c["Names"] = []string{}
	got := list(t, newSrc(t, fake(t, []ctr{a, b, c}), Config{TargetIP: "192.0.2.10"}))
	if len(got) != 1 || got[0].Key != "docker:real" {
		t.Fatalf("got %+v", got)
	}
}

func TestUDPPortIgnored(t *testing.T) {
	udp := port(53, 5353)
	udp["Type"] = "udp"
	srv := fake(t, []ctr{container("whoami", "running", lbl("doorwarden.enable", "true"), []map[string]any{port(80, 8080), udp}, nil)})
	got := list(t, newSrc(t, srv, Config{TargetIP: "192.0.2.10"}))
	if got[0].State != model.StateDiscovered || got[0].Backend.Port != 8080 {
		t.Fatalf("got %+v", got[0])
	}
}

func TestUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "dw")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("unix sockets unavailable:", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]ctr{container("whoami", "running", lbl("doorwarden.enable", "true"), []map[string]any{port(80, 8080)}, nil)})
	})}
	go srv.Serve(ln)
	defer srv.Close()
	s, err := New(Config{Endpoint: "unix://" + sock, TargetIP: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	got := list(t, s)
	if len(got) != 1 || got[0].Backend.Port != 8080 {
		t.Fatalf("got %+v", got)
	}
}

func TestUnreachable(t *testing.T) {
	srv := fake(t, nil)
	s := newSrc(t, srv, Config{})
	srv.Close()
	_, err := s.List(context.Background())
	if !errors.Is(err, source.ErrSourceUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := newSrc(t, srv, Config{}).List(context.Background())
	if !errors.Is(err, source.ErrSourceUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{")) }))
	defer srv.Close()
	_, err := newSrc(t, srv, Config{}).List(context.Background())
	if !errors.Is(err, source.ErrSourceUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestDuplicateNamesBothReturned(t *testing.T) {
	srv := fake(t, []ctr{
		container("one", "running", lbl("doorwarden.enable", "true", "doorwarden.name", "app"), []map[string]any{port(80, 8080)}, nil),
		container("two", "running", lbl("doorwarden.enable", "true", "doorwarden.name", "app"), []map[string]any{port(80, 8081)}, nil),
	})
	got := list(t, newSrc(t, srv, Config{TargetIP: "192.0.2.10"}))
	if len(got) != 2 || got[0].Name != "app" || got[1].Name != "app" || got[0].Key == got[1].Key {
		t.Fatalf("got %+v", got)
	}
}

func TestKeyStableAcrossRecreate(t *testing.T) {
	a := container("whoami", "running", lbl("doorwarden.enable", "true"), []map[string]any{port(80, 8080)}, nil)
	b := container("whoami", "running", lbl("doorwarden.enable", "true"), []map[string]any{port(80, 9090)}, nil)
	b["Id"] = "different-id"
	k1 := list(t, newSrc(t, fake(t, []ctr{a}), Config{TargetIP: "192.0.2.10"}))[0].Key
	k2 := list(t, newSrc(t, fake(t, []ctr{b}), Config{TargetIP: "192.0.2.10"}))[0].Key
	if k1 != k2 {
		t.Fatalf("%s != %s", k1, k2)
	}
}

func TestWarningsReset(t *testing.T) {
	var bad atomic.Bool
	bad.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := lbl("doorwarden.enable", "true")
		if bad.Load() {
			l["doorwarden.port"] = "x"
		}
		_ = json.NewEncoder(w).Encode([]ctr{container("whoami", "running", l, []map[string]any{port(80, 8080)}, nil)})
	}))
	defer srv.Close()
	s := newSrc(t, srv, Config{TargetIP: "192.0.2.10"})
	list(t, s)
	if len(s.Warnings()) != 1 {
		t.Fatal(s.Warnings())
	}
	bad.Store(false)
	list(t, s)
	if len(s.Warnings()) != 0 {
		t.Fatal(s.Warnings())
	}
}

func TestNameAndEndpointParsing(t *testing.T) {
	s, err := New(Config{Endpoint: "unix:///var/run/docker.sock"})
	if err != nil || s.Name() != "docker" || s.base != "http://docker" || s.sock != "/var/run/docker.sock" {
		t.Fatalf("%+v %v", s, err)
	}
	s, err = New(Config{Endpoint: "tcp://socket-proxy.example.test:2375", Name: "docker-b"})
	if err != nil || s.Name() != "docker-b" || s.base != "http://socket-proxy.example.test:2375" || s.sock != "" {
		t.Fatalf("%+v %v", s, err)
	}
	for _, bad := range []string{"", "ftp://x", "unix://", "tcp://"} {
		if _, err := New(Config{Endpoint: bad}); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}
