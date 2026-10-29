package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// getAuth is get with an authenticated principal (full body).
func getAuth(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, &Principal{User: "admin", Role: RoleViewer}))
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) HealthStatus {
	t.Helper()
	var hs HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &hs); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return hs
}

func TestHealthOK(t *testing.T) {
	h := Health{Probe: func(context.Context) error { return nil },
		Status: func() HealthStatus { return HealthStatus{Sources: map[string]bool{"docker": true}} }}
	rec := getAuth(t, h, http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type %q", ct)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control %q", rec.Header().Get("Cache-Control"))
	}
	hs := decode(t, rec)
	if hs.Status != "ok" || hs.Store != "ok" || hs.Degraded {
		t.Fatalf("status %+v", hs)
	}
}

func TestHealthDegradedWhenSourceDownStillOK(t *testing.T) {
	h := Health{Probe: func(context.Context) error { return nil },
		Status: func() HealthStatus {
			return HealthStatus{Sources: map[string]bool{"docker": true, "truenas": false}}
		}}
	rec := get(t, h, http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("a source outage must not fail health: code %d", rec.Code)
	}
	hs := decode(t, rec)
	if !hs.Degraded || hs.Status != "ok" || hs.Sources["truenas"] {
		t.Fatalf("want degraded ok, got %+v", hs)
	}
}

func TestHealthDegradedFlagFromStatusKept(t *testing.T) {
	h := Health{Probe: func(context.Context) error { return nil },
		Status: func() HealthStatus { return HealthStatus{Degraded: true, LastResult: "error"} }}
	hs := decode(t, get(t, h, http.MethodGet, "/healthz"))
	if !hs.Degraded {
		t.Fatalf("degraded flag lost: %+v", hs)
	}
}

func TestHealthFailsWhenStoreUnusable(t *testing.T) {
	secret := "sqlite: disk I/O error at /very/secret/path"
	h := Health{Probe: func(context.Context) error { return errors.New(secret) },
		Status: func() HealthStatus { return HealthStatus{} }}
	rec := getAuth(t, h, http.MethodGet, "/healthz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", rec.Code)
	}
	hs := decode(t, rec)
	if hs.Status != "fail" || hs.Store != "unusable" {
		t.Fatalf("status %+v", hs)
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("error text leaked into the unauthenticated body: %s", rec.Body.String())
	}
}

func TestHealthProbeTimeout(t *testing.T) {
	h := Health{Timeout: 20 * time.Millisecond, Probe: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	start := time.Now()
	rec := get(t, h, http.MethodGet, "/healthz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", rec.Code)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("probe timeout not applied")
	}
}

func TestHealthNoProbeIsUnusable(t *testing.T) {
	rec := get(t, Health{}, http.MethodGet, "/healthz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestHealthMethods(t *testing.T) {
	h := Health{Probe: func(context.Context) error { return nil }}
	if rec := get(t, h, http.MethodHead, "/healthz"); rec.Code != http.StatusOK {
		t.Fatalf("HEAD code %d", rec.Code)
	}
	rec := get(t, h, http.MethodPost, "/healthz")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST code %d", rec.Code)
	}
}

func TestNewMuxHealthOnlyByDefault(t *testing.T) {
	mux := NewMux(MuxOptions{Health: Health{Probe: func(context.Context) error { return nil }}})
	if rec := get(t, mux, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Fatalf("/healthz code %d", rec.Code)
	}
	if rec := get(t, mux, http.MethodGet, "/metrics"); rec.Code != http.StatusNotFound {
		t.Fatalf("/metrics must not be served unless explicitly mounted: code %d", rec.Code)
	}
}

func TestNewMuxMountsMetricsWhenGiven(t *testing.T) {
	m := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("m")) })
	mux := NewMux(MuxOptions{Health: Health{Probe: func(context.Context) error { return nil }}, Metrics: m})
	if rec := get(t, mux, http.MethodGet, "/metrics"); rec.Code != http.StatusOK || rec.Body.String() != "m" {
		t.Fatalf("/metrics code %d body %q", rec.Code, rec.Body.String())
	}
}

// The public /healthz body is only status and degraded: source names,
// dry-run state and reconcile times need an authenticated caller.
func TestHealthPublicBodyMinimal(t *testing.T) {
	when := time.Unix(1_800_000_000, 0)
	h := Health{Probe: func(context.Context) error { return nil },
		Status: func() HealthStatus {
			return HealthStatus{DryRun: true, Sources: map[string]bool{"truenas-nas1": false}, LastReconcile: &when, LastResult: "error"}
		}}
	rec := get(t, h, http.MethodGet, "/healthz")
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["status"] != "ok" || m["degraded"] != true {
		t.Fatalf("public body = %s", rec.Body)
	}

	rec = getAuth(t, h, http.MethodGet, "/healthz")
	hs := decode(t, rec)
	if !hs.DryRun || hs.Store != "ok" || len(hs.Sources) != 1 || hs.LastResult != "error" {
		t.Fatalf("authenticated body = %s", rec.Body)
	}
}

// Through the server: anonymous callers get the minimal body, a signed-in
// session the full one.
func TestHealthDetailNeedsAuth(t *testing.T) {
	e := newTestEnv(t, func(o *Options) {
		o.Health = Health{Probe: func(context.Context) error { return nil },
			Status: func() HealthStatus { return HealthStatus{Sources: map[string]bool{"docker": true}} }}
	})
	if w := e.anon().do("GET", "/healthz", nil); strings.Contains(w.Body.String(), "docker") || w.Code != 200 {
		t.Fatalf("anonymous healthz = %d %s", w.Code, w.Body)
	}
	e.setupAdmin()
	c, _ := e.login("admin", testPassword)
	if w := c.do("GET", "/healthz", nil); !strings.Contains(w.Body.String(), "docker") {
		t.Fatalf("authenticated healthz = %s", w.Body)
	}
}
