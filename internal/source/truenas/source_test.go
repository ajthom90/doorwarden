package truenas

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/source"
)

type fakeLookup struct {
	ports map[string][]int
	err   error
}

func (l fakeLookup) PublishedPorts(_ context.Context, app string) ([]int, error) {
	if l.err != nil {
		return nil, l.err
	}
	return l.ports[app], nil
}

func newSource(t *testing.T, f *fakeServer, lk PortLookup) *Source {
	t.Helper()
	s, err := New(Config{URL: f.url(), APIKey: secrets.Secret(testKey), TargetIP: "10.0.0.5"}, lk)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func list1(t *testing.T, apps string, lk PortLookup) (model.Service, *Source) {
	t.Helper()
	s := newSource(t, newFake(t, apps), lk)
	out, err := s.List(context.Background())
	if err != nil || len(out) != 1 {
		t.Fatalf("out=%v err=%v", out, err)
	}
	return out[0], s
}

func TestPortalZeroHost(t *testing.T) {
	svc, _ := list1(t, appsJSON(appJSON("a", "RUNNING", `{"Web UI":"http://0.0.0.0:30088/"}`)), nil)
	want := model.Backend{Scheme: "http", Host: "10.0.0.5", Port: 30088}
	if svc.Backend != want || svc.State != model.StateDiscovered || svc.Key != "truenas:a" ||
		svc.Name != "a" || svc.Source != "truenas" {
		t.Fatalf("%+v", svc)
	}
}

func TestPortalHTTPS(t *testing.T) {
	svc, _ := list1(t, appsJSON(appJSON("a", "RUNNING", `{"Web UI":"https://nas.example:30443/x"}`)), nil)
	if svc.Backend.Scheme != "https" || svc.Backend.Port != 30443 || svc.Backend.Host != "10.0.0.5" {
		t.Fatalf("%+v", svc)
	}
}

func TestPortalDefaultPorts(t *testing.T) {
	svc, _ := list1(t, appsJSON(appJSON("a", "RUNNING", `{"Web UI":"https://h/"}`)), nil)
	if svc.Backend.Port != 443 {
		t.Fatalf("%+v", svc)
	}
	svc, _ = list1(t, appsJSON(appJSON("a", "RUNNING", `{"Web UI":"http://h/"}`)), nil)
	if svc.Backend.Port != 80 {
		t.Fatalf("%+v", svc)
	}
}

func TestPortalSelection(t *testing.T) {
	svc, _ := list1(t, appsJSON(appJSON("a", "RUNNING", `{"Admin":"http://h:1/","Web UI":"http://h:2/"}`)), nil)
	if svc.Backend.Port != 2 {
		t.Fatalf("Web UI should win: %+v", svc)
	}
	svc, _ = list1(t, appsJSON(appJSON("a", "RUNNING", `{"HTTP":"http://h:3030/","HTTPS":"https://h:2974/"}`)), nil)
	if svc.Backend.Port != 3030 || svc.Backend.Scheme != "http" {
		t.Fatalf("first sorted should win: %+v", svc)
	}
}

func TestEmptyPortalLookup(t *testing.T) {
	apps := appsJSON(appJSON("a", "RUNNING", `{}`))
	svc, s := list1(t, apps, fakeLookup{ports: map[string][]int{"a": {31000, 30500, 32000}}})
	if svc.Backend != (model.Backend{Scheme: "http", Host: "10.0.0.5", Port: 30500}) || svc.State != model.StateDiscovered {
		t.Fatalf("lowest port expected: %+v", svc)
	}
	if len(s.Warnings()) != 0 {
		t.Fatal(s.Warnings())
	}
}

func TestEmptyPortalLookupMiss(t *testing.T) {
	apps := appsJSON(appJSON("a", "RUNNING", `{}`))
	for name, lk := range map[string]PortLookup{
		"empty": fakeLookup{}, "err": fakeLookup{err: errors.New("docker down")}, "nil": nil,
	} {
		t.Run(name, func(t *testing.T) {
			svc, s := list1(t, apps, lk)
			if svc.State != model.StateError || svc.Backend.Host != "" || svc.Backend.Port != 0 {
				t.Fatalf("%+v", svc)
			}
			if w := s.Warnings(); len(w) != 1 || !strings.Contains(w[0], `"a"`) {
				t.Fatalf("warnings = %v", w)
			}
		})
	}
}

func TestStoppedRetainedWithoutBackend(t *testing.T) {
	for _, st := range []string{"STOPPED", "DEPLOYING", "CRASHED"} {
		svc, _ := list1(t, appsJSON(appJSON("a", st, `{"Web UI":"http://0.0.0.0:30088/"}`)), nil)
		if svc.State != model.StateStopped || svc.Backend.Host != "" || svc.Backend.Port != 0 {
			t.Fatalf("%s: %+v", st, svc)
		}
	}
}

func TestUnexpectedSchemeIsError(t *testing.T) {
	svc, s := list1(t, appsJSON(appJSON("a", "RUNNING", `{"Web UI":"ftp://h:21/"}`)), fakeLookup{ports: map[string][]int{"a": {1}}})
	if svc.State != model.StateError || svc.Backend.Host != "" || svc.Backend.Port != 0 || len(s.Warnings()) != 1 {
		t.Fatalf("%+v %v", svc, s.Warnings())
	}
}

func TestSortedAndWarningsReset(t *testing.T) {
	f := newFake(t, appsJSON(appJSON("b", "RUNNING", `{}`), appJSON("a", "RUNNING", `{"Web UI":"http://h:1/"}`)))
	s := newSource(t, f, nil)
	out, err := s.List(context.Background())
	if err != nil || len(out) != 2 || out[0].Key != "truenas:a" || out[1].Key != "truenas:b" {
		t.Fatalf("%v %v", out, err)
	}
	if len(s.Warnings()) != 1 {
		t.Fatal(s.Warnings())
	}
	f.mu.Lock()
	f.rpcError = true
	f.mu.Unlock()
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if len(s.Warnings()) != 0 {
		t.Fatal("failed List must clear warnings")
	}
}

func TestListErrorsWrapUnavailable(t *testing.T) {
	t.Run("auth", func(t *testing.T) {
		f := newFake(t, `[]`)
		s, _ := New(Config{URL: f.url(), APIKey: "bad", TargetIP: "10.0.0.5"}, nil)
		defer s.Close()
		_, err := s.List(context.Background())
		if !errors.Is(err, source.ErrSourceUnavailable) {
			t.Fatal(err)
		}
	})
	t.Run("rpc error", func(t *testing.T) {
		f := newFake(t, `[]`)
		f.rpcError = true
		_, err := newSource(t, f, nil).List(context.Background())
		if !errors.Is(err, source.ErrSourceUnavailable) || strings.Contains(err.Error(), testKey) {
			t.Fatal(err)
		}
	})
	t.Run("down", func(t *testing.T) {
		f := newFake(t, `[]`)
		s := newSource(t, f, nil)
		f.srv.Close()
		_, err := s.List(context.Background())
		if !errors.Is(err, source.ErrSourceUnavailable) || strings.Contains(err.Error(), testKey) {
			t.Fatal(err)
		}
	})
	t.Run("bad payload", func(t *testing.T) {
		f := newFake(t, `{"not":"a list"}`)
		_, err := newSource(t, f, nil).List(context.Background())
		if !errors.Is(err, source.ErrSourceUnavailable) {
			t.Fatal(err)
		}
	})
	t.Run("ctx", func(t *testing.T) {
		f := newFake(t, `[]`)
		s := newSource(t, f, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := s.List(ctx)
		if !errors.Is(err, source.ErrSourceUnavailable) {
			t.Fatal(err)
		}
	})
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{TargetIP: "1.2.3.4"}, nil); err == nil {
		t.Fatal("URL required")
	}
	if _, err := New(Config{URL: "https://h"}, nil); err == nil {
		t.Fatal("TargetIP required")
	}
	s, err := New(Config{URL: "https://h", TargetIP: "1.2.3.4"}, nil)
	if err != nil || s.Name() != "truenas" {
		t.Fatal(err)
	}
}

func TestFixture(t *testing.T) {
	b, err := os.ReadFile("testdata/app_query.json")
	if err != nil {
		t.Fatal(err)
	}
	// The fixture is a full JSON-RPC response; serve its result field.
	res := extractResult(t, b)
	f := newFake(t, res)
	s := newSource(t, f, fakeLookup{ports: map[string][]int{"example-app-2": {30002}}})
	out, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		state, scheme, host string
		port                int
	}
	want := map[string]row{
		"truenas:example-app-1": {model.StateDiscovered, "http", "10.0.0.5", 30001},
		"truenas:example-app-2": {model.StateDiscovered, "http", "10.0.0.5", 30002},
		"truenas:example-app-3": {model.StateDiscovered, "http", "10.0.0.5", 30004}, // HTTP < HTTPS
		"truenas:example-app-4": {model.StateDiscovered, "http", "10.0.0.5", 30005}, // Web UI wins
		"truenas:example-app-5": {model.StateStopped, "http", "", 0},
		"truenas:example-app-6": {model.StateStopped, "http", "", 0},
	}
	if len(out) != len(want) {
		t.Fatalf("got %d services", len(out))
	}
	for _, s := range out {
		w := want[s.Key]
		if s.State != w.state || s.Backend.Scheme != w.scheme || s.Backend.Host != w.host || s.Backend.Port != w.port {
			t.Errorf("%s: %+v want %+v", s.Key, s, w)
		}
	}
}

func TestListCancelledMidLookupIsFailedList(t *testing.T) {
	f := newFake(t, appsJSON(appJSON("a", "RUNNING", `{}`), appJSON("b", "RUNNING", `{}`)))
	s := newSource(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	s.ports = cancelLookup{cancel: cancel}
	out, err := s.List(ctx)
	if out != nil || !errors.Is(err, source.ErrSourceUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("out=%v err=%v", out, err)
	}
	if len(s.Warnings()) != 0 {
		t.Fatalf("warnings = %v", s.Warnings())
	}
}

type cancelLookup struct{ cancel context.CancelFunc }

func (l cancelLookup) PublishedPorts(ctx context.Context, _ string) ([]int, error) {
	l.cancel()
	return nil, ctx.Err()
}

func TestListPreservesContextError(t *testing.T) {
	f := newFake(t, `[]`)
	s := newSource(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.List(ctx)
	if !errors.Is(err, source.ErrSourceUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
