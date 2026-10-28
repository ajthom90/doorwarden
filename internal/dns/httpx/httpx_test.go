package httpx_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	c.Secrets = []string{"hunter2"}
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
