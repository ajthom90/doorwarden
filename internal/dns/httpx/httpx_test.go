package httpx_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns/httpx"
)

func TestSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"x":"` + strings.Repeat("a", 5000) + `"}`))
	}))
	defer srv.Close()
	c, _ := httpx.New(srv.URL, false, 0)
	c.MaxBody = 1000
	var out map[string]any
	if _, err := c.Do(context.Background(), "GET", "/", nil, nil, nil, &out); !errors.Is(err, httpx.ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestStatusErrorScrubbed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"message":"bad key hunter2"}`))
	}))
	defer srv.Close()
	c, _ := httpx.New(srv.URL, false, 0)
	c.AddSecret("hunter2")
	_, err := c.Do(context.Background(), "GET", "/", nil, nil, nil, nil)
	var se *httpx.StatusError
	if !errors.As(err, &se) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v", err)
	}
}

func TestCtxCancelAndNoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer srv.Close()
	c, _ := httpx.New(srv.URL, false, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := c.Do(ctx, "GET", "/", nil, nil, nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	// without cancel the request must reach the server despite HTTP_PROXY
	if _, err := c.Do(context.Background(), "GET", "/", nil, nil, nil, nil); err != nil {
		t.Fatalf("proxy env honoured? %v", err)
	}
}

func TestRejectsCredentialsInURL(t *testing.T) {
	if _, err := httpx.New("https://user:pw@host", false, 0); err == nil {
		t.Fatal("want error")
	}
}

func TestCrossHostRedirectNotFollowed(t *testing.T) {
	var got string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-API-KEY")
	}))
	defer other.Close()
	// a different host name for the same loopback listener
	target := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer src.Close()
	c, _ := httpx.New(src.URL, false, 0)
	_, err := c.Do(context.Background(), "GET", "/", nil, http.Header{"X-API-KEY": {"k"}}, nil, nil)
	if err == nil || got != "" {
		t.Fatalf("redirect followed: err=%v key=%q", err, got)
	}
}

func TestCheckURL(t *testing.T) {
	ok := []struct {
		u     string
		allow bool
	}{
		{"https://dns.example.test", false}, {"http://10.0.0.5", false}, {"http://172.16.0.9:80", false},
		{"http://127.0.0.1:1", false}, {"http://nas", false}, {"http://[fe80::1]:80", false},
		{"http://dns.example.test", true},
	}
	for _, c := range ok {
		if err := httpx.CheckURL(c.u, c.allow); err != nil {
			t.Errorf("%s: %v", c.u, err)
		}
	}
	bad := []string{"http://dns.example.test", "http://198.51.100.1", "http://192.0.2.1:8080", "ftp://x", "https://u:p@host", "https://", "host"}
	for _, u := range bad {
		if err := httpx.CheckURL(u, false); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestBoolOptionAcceptsBoolsAndTrueFalseStrings(t *testing.T) {
	ok := map[any]bool{true: true, false: false, "true": true, "TRUE": true, "False": false, "false": false}
	for in, want := range ok {
		got, err := httpx.BoolOption(map[string]any{"k": in}, "k")
		if err != nil || got != want {
			t.Errorf("%v: got %v err %v", in, got, err)
		}
	}
	for _, bad := range []any{"yes", "1", 1, 0, "", "tru", 1.5, []string{"true"}} {
		if _, err := httpx.BoolOption(map[string]any{"k": bad}, "k"); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if got, err := httpx.BoolOption(map[string]any{}, "k"); err != nil || got {
		t.Errorf("absent: %v %v", got, err)
	}
}

func TestScrubbedErrorDoesNotExposeRawError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer srv.Close()
	c, _ := httpx.New(srv.URL, false, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := c.Do(ctx, "GET", "/", nil, nil, nil, nil)
	if err == nil {
		t.Fatal("want error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Is must delegate: %v", err)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		t.Fatal("the raw *url.Error must not be reachable through As")
	}
	var perr *net.OpError
	if errors.As(err, &perr) {
		t.Fatal("a raw net.OpError must not be reachable")
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if _, raw := e.(*url.Error); raw {
			t.Fatal("raw error reachable through Unwrap")
		}
	}
	// allowlisted: net.Error (timeouts) and *StatusError
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer srv2.Close()
	c2, _ := httpx.New(srv2.URL, false, 0)
	_, err = c2.Do(context.Background(), "GET", "/", nil, nil, nil, nil)
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.Status != 500 {
		t.Fatalf("StatusError must stay reachable: %v", err)
	}
	// connection refused: the text is scrubbed and a net.Error is reachable
	srv3 := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url3 := srv3.URL
	srv3.Close()
	c3, _ := httpx.New(url3, false, 0)
	c3.AddSecret("127.0.0.1")
	_, err = c3.Do(context.Background(), "GET", "/", nil, nil, nil, nil)
	var ne net.Error
	if err == nil || !errors.As(err, &ne) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("err = %v", err)
	}
}
