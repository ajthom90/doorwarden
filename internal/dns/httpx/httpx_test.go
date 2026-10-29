package httpx_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns/httpx"
	"github.com/ajthom90/doorwarden/internal/secrets"
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

// TestWriteOutcomeClassification pins which failures prove a request was NOT
// applied (NotApplied: never sent, or a 4xx answer) and which leave the outcome
// unknown (5xx answers, failures after the request reached the wire).
func TestWriteOutcomeClassification(t *testing.T) {
	ctx := context.Background()
	post := func(c *httpx.Client, cx context.Context) error {
		_, err := c.Do(cx, "POST", "/w", nil, nil, map[string]string{"k": "v"}, nil)
		return err
	}
	// dial refused: nothing was sent
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	c, _ := httpx.New("http://"+addr, false, 0)
	if err := post(c, ctx); err == nil || !httpx.NotApplied(err) || !errors.Is(err, httpx.ErrNotSent) {
		t.Errorf("dial refused must be not-applied: %v", err)
	}
	// context cancelled before Do: nothing was sent
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c, _ = httpx.New(srv.URL, false, 0)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := post(c, cctx); err == nil || !httpx.NotApplied(err) || !errors.Is(err, context.Canceled) {
		t.Errorf("pre-cancelled ctx must be not-applied: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("a cancelled request reached the server")
	}
	// an unencodable body and an invalid path fail before sending
	if _, err := c.Do(ctx, "POST", "/w", nil, nil, map[string]any{"f": func() {}}, nil); err == nil || !httpx.NotApplied(err) {
		t.Errorf("marshal error must be not-applied: %v", err)
	}
	if _, err := c.Do(ctx, "POST", "/%zz", nil, nil, nil, nil); err == nil || !httpx.NotApplied(err) {
		t.Errorf("bad path must be not-applied: %v", err)
	}
	if _, err := c.Do(ctx, "BAD METHOD", "/w", nil, nil, nil, nil); err == nil || !httpx.NotApplied(err) {
		t.Errorf("NewRequest error must be not-applied: %v", err)
	}
	// the server reads (applies) the request, then cuts the connection
	var applied atomic.Bool
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		applied.Store(true)
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	defer cut.Close()
	c, _ = httpx.New(cut.URL, false, 0)
	if err := post(c, ctx); err == nil || httpx.NotApplied(err) || !applied.Load() {
		t.Errorf("applied-then-cut must be ambiguous: %v (applied %v)", err, applied.Load())
	}
	// the connection is reset right after the request headers arrive
	reset := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetLinger(0) // RST instead of FIN
			}
			_ = conn.Close()
		}
	}))
	defer reset.Close()
	c, _ = httpx.New(reset.URL, false, 0)
	if err := post(c, ctx); err == nil || httpx.NotApplied(err) {
		t.Errorf("reset after headers must be ambiguous: %v", err)
	}
	// the caller's deadline expires while the server holds the request
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	c, _ = httpx.New(slow.URL, false, 0)
	tctx, tcancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer tcancel()
	if err := post(c, tctx); err == nil || httpx.NotApplied(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("timeout in flight must be ambiguous: %v", err)
	}
	// status answers: 4xx is a refusal, 5xx (including a proxy's HTML page) is not
	for _, tc := range []struct {
		status     int
		ctype      string
		body       string
		notApplied bool
	}{
		{400, "application/json", `{"message":"bad"}`, true},
		{404, "application/json", `{"message":"nope"}`, true},
		{409, "application/json", `{"message":"conflict"}`, true},
		{422, "application/json", `{"message":"invalid"}`, true},
		{500, "application/json", `{"message":"boom"}`, false},
		{502, "text/html", `<html><body><h1>502 Bad Gateway</h1></body></html>`, false},
		{503, "text/plain", `unavailable`, false},
		{504, "text/html", `<html><body><h1>504 Gateway Time-out</h1></body></html>`, false},
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", tc.ctype)
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		c, _ := httpx.New(s.URL, false, 0)
		err := post(c, ctx)
		var se *httpx.StatusError
		if !errors.As(err, &se) || se.Status != tc.status || httpx.NotApplied(err) != tc.notApplied {
			t.Errorf("status %d: NotApplied=%v want %v (%v)", tc.status, httpx.NotApplied(err), tc.notApplied, err)
		}
		s.Close()
	}
	if httpx.NotApplied(nil) {
		t.Error("nil is not a failure")
	}
}

// The whole message is redacted before it is whitespace-normalized and
// truncated: a secret straddling the 200-byte cut, or one containing
// whitespace runs, leaves no fragment behind.
func TestStatusErrorRedactedBeforeTruncation(t *testing.T) {
	secret := "S3CRETTOKENabcdefghijklmnopqrstuvwxyz0123456789"
	ws := "pass  word\twith\nspace"
	for name, msg := range map[string]string{
		"straddle":   strings.Repeat("x", 180) + secret + " tail",
		"whitespace": "bad credentials: " + ws,
	} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"message": msg})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(401)
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			c, _ := httpx.New(srv.URL, false, 0)
			c.AddSecret(secrets.Secret(secret), secrets.Secret(ws))
			_, err := c.Do(context.Background(), "GET", "/", nil, nil, nil, nil)
			if err == nil {
				t.Fatal("no error")
			}
			for _, frag := range []string{secret[:12], "S3CRET", "pass word", "pass"} {
				if strings.Contains(err.Error(), frag) {
					t.Fatalf("fragment %q leaked: %v", frag, err)
				}
			}
			if !strings.Contains(err.Error(), "[redacted]") {
				t.Fatalf("not redacted: %v", err)
			}
		})
	}
}
