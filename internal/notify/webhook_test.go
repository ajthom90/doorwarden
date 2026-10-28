package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

var testEvent = Event{
	Kind: "cert.renewal_failed", Severity: Critical, Subject: "Renewal failed for example.test",
	Message: "ACME order failed", Fields: map[string]string{"zone": "example.test"},
	At: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC), DedupeKey: "cert:example.test",
}

func webhookCfg(url string) config.WebhookCfg {
	return config.WebhookCfg{
		NotifyCommon:      config.NotifyCommon{Name: "wh"},
		URL:               secrets.Secret(url),
		AllowInsecureHTTP: true,
	}
}

func TestWebhookPostsJSONAndSignature(t *testing.T) {
	const key = "hmac-key-SENTINEL"
	var gotBody []byte
	var gotHdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotHdr = r.Header.Clone()
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
	}))
	defer srv.Close()
	cfg := webhookCfg(srv.URL + "/hook")
	cfg.Secret = key
	cfg.Headers = map[string]secrets.Secret{"X-Custom": "v1", "Authorization": "Bearer tok"}
	w, err := NewWebhook(cfg, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Send(context.Background(), testEvent); err != nil {
		t.Fatal(err)
	}
	if ct := gotHdr.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	if gotHdr.Get("X-Custom") != "v1" || gotHdr.Get("Authorization") != "Bearer tok" {
		t.Fatalf("custom headers missing: %v", gotHdr)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := gotHdr.Get("X-Doorwarden-Signature"); got != want {
		t.Fatalf("signature %q want %q", got, want)
	}
	var m map[string]any
	if err := json.Unmarshal(gotBody, &m); err != nil {
		t.Fatal(err)
	}
	if m["kind"] != "cert.renewal_failed" || m["severity"] != "critical" || m["subject"] != testEvent.Subject ||
		m["message"] != "ACME order failed" || m["at"] != "2026-10-28T12:00:00Z" {
		t.Fatalf("body %v", m)
	}
	if f := m["fields"].(map[string]any); f["zone"] != "example.test" {
		t.Fatalf("fields %v", f)
	}
	if _, leaked := m["dedupe_key"]; leaked {
		t.Fatal("dedupe key exposed")
	}
}

func TestWebhookNoSignatureWithoutSecret(t *testing.T) {
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hdr = r.Header.Clone() }))
	defer srv.Close()
	w, _ := NewWebhook(webhookCfg(srv.URL), time.Second)
	if err := w.Send(context.Background(), testEvent); err != nil {
		t.Fatal(err)
	}
	if _, ok := hdr["X-Doorwarden-Signature"]; ok {
		t.Fatal("signature header sent without secret")
	}
}

func TestWebhookErrorMappingNoSecretLeak(t *testing.T) {
	const tok = "URLTOKEN-SENTINEL"
	for _, code := range []int{400, 401, 429, 500, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte("echo " + tok + " " + r.Header.Get("Authorization")))
		}))
		cfg := webhookCfg(srv.URL + "/" + tok)
		cfg.Secret = "hmac-SENTINEL"
		cfg.Headers = map[string]secrets.Secret{"Authorization": "Bearer HDR-SENTINEL"}
		w, _ := NewWebhook(cfg, time.Second)
		err := w.Send(context.Background(), testEvent)
		srv.Close()
		if err == nil {
			t.Fatalf("%d: no error", code)
		}
		for _, s := range []string{tok, "hmac-SENTINEL", "HDR-SENTINEL"} {
			if strings.Contains(err.Error(), s) {
				t.Fatalf("%d: error leaks %q: %v", code, s, err)
			}
		}
		if !strings.Contains(err.Error(), http.StatusText(code)) && !strings.Contains(err.Error(), "HTTP") {
			t.Fatalf("error lacks status: %v", err)
		}
		if got, want := IsPermanent(err), code >= 400 && code < 500 && code != 429; got != want {
			t.Fatalf("%d: permanent=%v want %v", code, got, want)
		}
	}
}

func TestWebhookConnectionErrorRedactsURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/PATHTOKEN-SENTINEL"
	srv.Close() // connection refused
	w, _ := NewWebhook(webhookCfg(url), time.Second)
	err := w.Send(context.Background(), testEvent)
	if err == nil || strings.Contains(err.Error(), "PATHTOKEN-SENTINEL") {
		t.Fatalf("err = %v", err)
	}
}

func TestWebhookRefusesCrossHostRedirect(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	cfg := webhookCfg(srv.URL)
	cfg.Secret = "k"
	cfg.Headers = map[string]secrets.Secret{"X-Token": "T"}
	w, _ := NewWebhook(cfg, time.Second)
	err := w.Send(context.Background(), testEvent)
	if err == nil || hits.Load() != 0 {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v", err)
	}
}

func TestWebhookSameHostRedirectOK(t *testing.T) {
	var final atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusTemporaryRedirect) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) { final.Add(1) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	w, _ := NewWebhook(webhookCfg(srv.URL+"/a"), time.Second)
	if err := w.Send(context.Background(), testEvent); err != nil || final.Load() != 1 {
		t.Fatalf("err=%v final=%d", err, final.Load())
	}
}

func TestWebhookTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	w, _ := NewWebhook(webhookCfg(srv.URL), 50*time.Millisecond)
	start := time.Now()
	if err := w.Send(context.Background(), testEvent); err == nil {
		t.Fatal("no timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestWebhookResponseBodyBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		chunk := strings.Repeat("x", 1<<16)
		for i := 0; i < 1024; i++ { // 64 MiB offered
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	w, _ := NewWebhook(webhookCfg(srv.URL), 5*time.Second)
	err := w.Send(context.Background(), testEvent)
	if err == nil || len(err.Error()) > 512 {
		t.Fatalf("err = %v", err)
	}
}

func TestWebhookRequestSizeAndFieldTruncation(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { body, _ = io.ReadAll(r.Body) }))
	defer srv.Close()
	w, _ := NewWebhook(webhookCfg(srv.URL), time.Second)
	e := testEvent
	e.Message = strings.Repeat("m", 1<<20)
	e.Fields = map[string]string{}
	for i := 0; i < 500; i++ {
		e.Fields["k"+strings.Repeat("0", 3)+string(rune('a'+i%26))+strings.Repeat("z", i)] = strings.Repeat("v", 5000)
	}
	if err := w.Send(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if len(body) > 64<<10 {
		t.Fatalf("body %d bytes", len(body))
	}
	var m struct {
		Message string
		Fields  map[string]string
	}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Message) > MaxMessageBytes+8 || len(m.Fields) > MaxFields {
		t.Fatalf("not truncated: %d %d", len(m.Message), len(m.Fields))
	}
	for _, v := range m.Fields {
		if len(v) > MaxFieldValueBytes+8 {
			t.Fatalf("field value %d", len(v))
		}
	}
}

func TestNewWebhookValidatesURL(t *testing.T) {
	for _, u := range []string{"", "ftp://x.example.test", "https://u:p@x.example.test", "http://x.example.test/p"} {
		cfg := webhookCfg(u)
		cfg.AllowInsecureHTTP = false
		if _, err := NewWebhook(cfg, time.Second); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
}

func TestWebhookIgnoresAmbientProxy(t *testing.T) {
	hit := make(chan struct{}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit <- struct{}{} }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	w, _ := NewWebhook(webhookCfg(srv.URL), time.Second)
	_ = w.Send(context.Background(), testEvent)
	select {
	case <-hit:
		t.Fatal("request went through ambient proxy")
	default:
	}
}
