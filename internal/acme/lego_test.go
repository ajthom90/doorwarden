package acme

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
)

// fakeACME is a minimal ACME server: directory, nonces, newAccount (201),
// and newOrder answering 429 rateLimited with Retry-After, the canned
// Let's Encrypt response shape. It exercises the real lego client path.
type fakeACME struct {
	srv      *httptest.Server
	mu       sync.Mutex
	accounts []map[string]any // decoded newAccount JWS payloads
	acctHdr  []map[string]any // decoded newAccount JWS protected headers
	orders   int
	kids     []any // JWS "kid" of each newOrder request
}

func newFakeACME(t *testing.T) *fakeACME {
	f := &fakeACME{}
	mux := http.NewServeMux()
	nonce := 0
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		nonce++
		w.Header().Set("Replay-Nonce", "nonce"+strings.Repeat("x", 8)+string(rune('a'+nonce%26)))
		f.mu.Unlock()
		base := f.srv.URL
		switch r.URL.Path {
		case "/dir":
			json.NewEncoder(w).Encode(map[string]any{
				"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/order",
				"revokeCert": base + "/revoke", "keyChange": base + "/key", "meta": map[string]any{"externalAccountRequired": true},
			})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/acct":
			hdr, payload := decodeJWS(t, r.Body)
			f.mu.Lock()
			f.accounts = append(f.accounts, payload)
			f.acctHdr = append(f.acctHdr, hdr)
			f.mu.Unlock()
			w.Header().Set("Location", base+"/acct/1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
		case "/order":
			hdr, _ := decodeJWS(t, r.Body)
			f.mu.Lock()
			f.kids = append(f.kids, hdr["kid"])
			f.orders++
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/problem+json")
			w.Header().Set("Retry-After", "5400")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s","status":429}`)
		default:
			http.NotFound(w, r)
		}
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func decodeJWS(t *testing.T, body io.Reader) (hdr, payload map[string]any) {
	var jws struct{ Protected, Payload string }
	if err := json.NewDecoder(body).Decode(&jws); err != nil {
		t.Error(err)
		return nil, nil
	}
	dec := func(s string, v any) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err == nil {
			err = json.Unmarshal(b, v)
		}
		if err != nil {
			t.Error(err)
		}
	}
	dec(jws.Protected, &hdr)
	dec(jws.Payload, &payload)
	return hdr, payload
}

func legoHarness(t *testing.T, f *fakeACME, eab bool) *harness {
	cfg := testConfig()
	iss := config.Issuer{Directory: f.srv.URL + "/dir", Email: "admin@example.test"}
	if eab {
		k := make([]byte, 32)
		rand.Read(k)
		iss.EABKid, iss.EABHMAC = "kid-1", base64.RawURLEncoding.EncodeToString(k)
	}
	cfg.Issuers["le"] = iss
	h := newHarness(t, cfg, func(mc *ManagerConfig) { mc.HTTPClient = f.srv.Client() })
	h.m.obtain = h.m.legoObtain
	return h
}

// Through real lego: EAB is sent, the account key is stored sealed, the
// registration is reused, and a 429 rateLimited parks the set until
// Retry-After without contacting the CA again.
func TestLegoEABAccountAndRateLimitPark(t *testing.T) {
	f := newFakeACME(t)
	h := legoHarness(t, f, true)
	_, err := h.m.Issue(ctx, wildcardReq())
	if err == nil {
		t.Fatal("want rate limited")
	}
	if contains(err.Error(), "PRIVATE KEY") {
		t.Fatal("key in error")
	}
	if len(f.accounts) != 1 {
		t.Fatalf("%d newAccount calls", len(f.accounts))
	}
	eabv, ok := f.accounts[0]["externalAccountBinding"].(map[string]any)
	if !ok {
		t.Fatalf("no EAB in newAccount payload: %v", f.accounts[0])
	}
	var inner map[string]any
	b, _ := base64.RawURLEncoding.DecodeString(eabv["protected"].(string))
	json.Unmarshal(b, &inner)
	if inner["kid"] != "kid-1" || inner["alg"] != "HS256" {
		t.Fatalf("EAB protected header %v", inner)
	}
	if f.acctHdr[0]["jwk"] == nil {
		t.Fatal("newAccount without jwk")
	}

	// Account key: sealed, not PEM plaintext, and opens with the box.
	s, ok, err := h.st.GetSetting(ctx, accountKeyKey("le"))
	if err != nil || !ok {
		t.Fatal("account key not stored", err)
	}
	if contains(s, "PRIVATE KEY") {
		t.Fatal("account key stored in plaintext")
	}
	raw, _ := base64.StdEncoding.DecodeString(s)
	if contains(string(raw), "PRIVATE KEY") {
		t.Fatal("account key stored in plaintext")
	}
	plain, err := h.box.Open(raw)
	if err != nil || !contains(string(plain), "EC PRIVATE KEY") {
		t.Fatal("sealed account key does not open", err)
	}

	// Parked until now+Retry-After (5400s): no further CA contact.
	_, err = h.m.Issue(ctx, wildcardReq())
	var de *DeferredError
	if !errors.As(err, &de) || !de.Until.Equal(t0.Add(5400*time.Second)) {
		t.Fatalf("want parked until +5400s, got %v", err)
	}
	if f.orders != 1 {
		t.Fatalf("%d orders while parked", f.orders)
	}
	if r := h.row(t, certID("example.test", []string{"*.example.test", "example.test"})); r.LastResult != "rate-limited" {
		t.Fatalf("row %+v", r)
	}

	// After the park: registration reused (no second newAccount), same key.
	h.clock.Add(5401 * time.Second)
	if _, err := h.m.Issue(ctx, wildcardReq()); err == nil {
		t.Fatal("want rate limited again")
	}
	if len(f.accounts) != 1 || f.orders != 2 {
		t.Fatalf("accounts %d orders %d", len(f.accounts), f.orders)
	}
	// Both orders are signed with the account URL as kid, including the
	// one using the stored registration (found by the Pebble run).
	for i, k := range f.kids {
		if k != f.srv.URL+"/acct/1" {
			t.Errorf("order %d kid %v", i, k)
		}
	}
	s2, _, _ := h.st.GetSetting(ctx, accountKeyKey("le"))
	if s2 != s {
		t.Fatal("account key regenerated")
	}
}

func TestLegoNoEABWhenNotConfigured(t *testing.T) {
	f := newFakeACME(t)
	h := legoHarness(t, f, false)
	h.m.Issue(ctx, wildcardReq())
	if len(f.accounts) != 1 {
		t.Fatalf("%d accounts", len(f.accounts))
	}
	if _, ok := f.accounts[0]["externalAccountBinding"]; ok {
		t.Fatal("EAB sent without config")
	}
	if f.accounts[0]["termsOfServiceAgreed"] != true {
		t.Fatal("ToS not agreed")
	}
}
