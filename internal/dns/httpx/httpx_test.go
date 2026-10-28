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
