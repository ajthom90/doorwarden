package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

func ntfyCfg(server string) config.NtfyCfg {
	return config.NtfyCfg{NotifyCommon: config.NotifyCommon{Name: "nt"}, Server: server, Topic: "alerts", AllowInsecureHTTP: true}
}

func TestNtfyPublishes(t *testing.T) {
	var path, body string
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		path, body, hdr = r.URL.Path, string(b), r.Header.Clone()
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
	}))
	defer srv.Close()
	n, err := NewNtfy(ntfyCfg(srv.URL+"/"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), testEvent); err != nil {
		t.Fatal(err)
	}
	if path != "/alerts" {
		t.Fatalf("path %q", path)
	}
	if hdr.Get("Title") != testEvent.Subject || hdr.Get("Priority") != "5" {
		t.Fatalf("headers %v", hdr)
	}
	if !strings.Contains(hdr.Get("Tags"), "rotating_light") || !strings.Contains(hdr.Get("Tags"), "cert_renewal_failed") {
		t.Fatalf("tags %q", hdr.Get("Tags"))
	}
	if !strings.HasPrefix(hdr.Get("Content-Type"), "text/plain") {
		t.Fatalf("content-type %q", hdr.Get("Content-Type"))
	}
	if !strings.HasPrefix(body, "ACME order failed") || !strings.Contains(body, "zone: example.test") {
		t.Fatalf("body %q", body)
	}
	if hdr.Get("Authorization") != "" {
		t.Fatal("auth sent unconfigured")
	}
}

func TestNtfyPriorityMapping(t *testing.T) {
	want := map[Severity]string{Info: "3", Warning: "4", Critical: "5", "": "3", "bogus": "3"}
	for sev, p := range want {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("Priority") }))
		n, _ := NewNtfy(ntfyCfg(srv.URL), time.Second)
		e := testEvent
		e.Severity = sev
		if err := n.Send(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		if got != p {
			t.Errorf("severity %q: priority %q want %q", sev, got, p)
		}
	}
}

func TestNtfyAuth(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { auth = r.Header.Get("Authorization") }))
	defer srv.Close()
	c := ntfyCfg(srv.URL)
	c.Token = "tk_SENTINEL"
	n, _ := NewNtfy(c, time.Second)
	if err := n.Send(context.Background(), testEvent); err != nil || auth != "Bearer tk_SENTINEL" {
		t.Fatalf("err=%v auth=%q", err, auth)
	}
	c = ntfyCfg(srv.URL)
	c.Username, c.Password = "user", "pw"
	n, _ = NewNtfy(c, time.Second)
	if err := n.Send(context.Background(), testEvent); err != nil || auth != "Basic dXNlcjpwdw==" {
		t.Fatalf("err=%v auth=%q", err, auth)
	}
}

func TestNtfyRefusesCrossHostRedirectWithoutLeakingToken(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := ntfyCfg(srv.URL)
	c.Token = "tk_SENTINEL"
	n, _ := NewNtfy(c, time.Second)
	err := n.Send(context.Background(), testEvent)
	if err == nil || leaked.Load() != 0 || strings.Contains(err.Error(), "tk_SENTINEL") {
		t.Fatalf("err=%v leaked=%d", err, leaked.Load())
	}
}

func TestNtfyErrorsDoNotLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("bad token " + r.Header.Get("Authorization")))
	}))
	defer srv.Close()
	c := ntfyCfg(srv.URL)
	c.Token = "tk_SENTINEL"
	n, _ := NewNtfy(c, time.Second)
	err := n.Send(context.Background(), testEvent)
	if err == nil || strings.Contains(err.Error(), "tk_SENTINEL") || !IsPermanent(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestNtfyTitleEncodingAndInjection(t *testing.T) {
	var title string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { title = r.Header.Get("Title") }))
	defer srv.Close()
	n, _ := NewNtfy(ntfyCfg(srv.URL), time.Second)
	e := testEvent
	e.Subject = "Zertifikat läuft ab"
	if err := n.Send(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(title, "=?UTF-8?") {
		t.Fatalf("title not RFC 2047 encoded: %q", title)
	}
	title = ""
	e.Subject = "ok\r\nX-Evil: 1"
	if err := n.Send(context.Background(), e); err == nil || title != "" {
		t.Fatalf("CRLF subject accepted: err=%v title=%q", err, title)
	}
}

func TestNewNtfyValidation(t *testing.T) {
	c := ntfyCfg("http://ntfy.example.test")
	c.AllowInsecureHTTP = false
	if _, err := NewNtfy(c, time.Second); err == nil {
		t.Error("public http accepted")
	}
	c = ntfyCfg("https://ntfy.example.test")
	c.Topic = "a/b"
	if _, err := NewNtfy(c, time.Second); err == nil {
		t.Error("bad topic accepted")
	}
	c = ntfyCfg("https://ntfy.example.test")
	c.Token, c.Username, c.Password = secrets.Secret("t"), "u", "p"
	if _, err := NewNtfy(c, time.Second); err == nil {
		t.Error("token+basic accepted")
	}
}
