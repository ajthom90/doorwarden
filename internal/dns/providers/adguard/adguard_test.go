package adguard_test

import (
	"context"
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

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/dnstest"
	"github.com/ajthom90/doorwarden/internal/dns/providers/adguard"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const (
	user     = "admin"
	password = "adguard-PASSWORD-do-not-leak-1"
)

type rw struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled *bool  `json:"enabled,omitempty"`
}

func eq(a, b rw) bool {
	if a.Domain != b.Domain || a.Answer != b.Answer || (a.Enabled == nil) != (b.Enabled == nil) {
		return false
	}
	return a.Enabled == nil || *a.Enabled == *b.Enabled
}

type backend struct {
	rawList   string
	hasRaw    bool
	mu        sync.Mutex
	rws       []rw
	status    int
	slow      time.Duration
	noUpdate  bool
	sawHeader string
	calls     []string
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.slow > 0 {
		time.Sleep(b.slow)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sawHeader = r.Header.Get("Authorization")
	b.calls = append(b.calls, r.Method+" "+r.URL.Path)
	if b.status != 0 {
		w.WriteHeader(b.status)
		_, _ = w.Write([]byte(`{"message":"boom ` + password + `"}`))
		return
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	if r.Header.Get("Authorization") != want {
		w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
		http.Error(w, "Unauthorized", 401)
		return
	}
	dec := func(v any) { _ = json.NewDecoder(r.Body).Decode(v) }
	switch r.URL.Path {
	case "/control/status":
		_, _ = w.Write([]byte(`{"running":true,"version":"v0.107.50"}`))
	case "/control/rewrite/list":
		if b.hasRaw {
			_, _ = w.Write([]byte(b.rawList))
			return
		}
		out := b.rws
		if out == nil {
			out = []rw{}
		}
		_ = json.NewEncoder(w).Encode(out)
	case "/control/rewrite/add":
		var in rw
		dec(&in)
		for _, e := range b.rws {
			if eq(e, in) {
				http.Error(w, "rewrite already exists", 400)
				return
			}
		}
		b.rws = append(b.rws, in)
	case "/control/rewrite/delete":
		var in rw
		dec(&in)
		for i, e := range b.rws {
			if eq(e, in) {
				b.rws = append(b.rws[:i], b.rws[i+1:]...)
				return
			}
		}
	case "/control/rewrite/update":
		if b.noUpdate || r.Method != "PUT" {
			http.NotFound(w, r)
			return
		}
		var in struct{ Target, Update rw }
		dec(&in)
		for i, e := range b.rws {
			if eq(e, in.Target) {
				b.rws[i] = in.Update
				return
			}
		}
		http.Error(w, "not found", 400)
	default:
		http.NotFound(w, r)
	}
}

func newProvider(t *testing.T, b *backend, pw string) *adguard.Provider {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	p, err := adguard.New(adguard.Config{URL: srv.URL, Username: user, Password: secrets.Secret(pw)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformance(t *testing.T) {
	b := &backend{}
	p := newProvider(t, b, password)
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test",
		SeedMultiValue: func(_ context.Context, _, name string, values ...string) error {
			b.mu.Lock()
			defer b.mu.Unlock()
			for _, v := range values {
				b.rws = append(b.rws, rw{Domain: name, Answer: v})
			}
			return nil
		}})
	if !p.Capabilities().WildcardA {
		t.Fatal("wildcard must be supported")
	}
}

func TestConformanceLegacyUpdateFallback(t *testing.T) {
	b := &backend{noUpdate: true}
	p := newProvider(t, b, password)
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test"})
}

func TestBasicAuthHeader(t *testing.T) {
	b := &backend{}
	p := newProvider(t, b, password)
	if err := p.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	if b.sawHeader != want {
		t.Fatalf("Authorization = %q", b.sawHeader)
	}
}

func TestTypeInferenceAndWildcard(t *testing.T) {
	ctx := context.Background()
	b := &backend{rws: []rw{{Domain: "a.example.test", Answer: "192.0.2.1"}, {Domain: "v6.example.test", Answer: "2001:db8::1"}, {Domain: "*.example.test", Answer: "192.0.2.2"}, {Domain: "c.example.test", Answer: "a.example.test"}}}
	p := newProvider(t, b, password)
	recs, err := p.ListRecords(ctx, "example.test")
	if err != nil || len(recs) != 4 {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
	got := map[string]string{}
	for _, r := range recs {
		got[r.Name] = r.Type
	}
	if got["a.example.test"] != "A" || got["v6.example.test"] != "AAAA" || got["*.example.test"] != "A" || got["c.example.test"] != "CNAME" {
		t.Fatalf("types = %v", got)
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "x.example.test", Type: "A", Value: "not-an-ip"}); err == nil {
		t.Fatal("mismatched value accepted")
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "x.example.test", Type: "TXT", Value: "v"}); err == nil {
		t.Fatal("TXT accepted")
	}
}

func TestErrorMappingNoLeak(t *testing.T) {
	ctx := context.Background()
	b := &backend{}
	bad := newProvider(t, b, "wrong-"+password)
	err := bad.Test(ctx)
	if err == nil || !strings.Contains(err.Error(), "authentication failed") || strings.Contains(err.Error(), password) {
		t.Fatalf("err = %v", err)
	}
	p := newProvider(t, b, password)
	for status, want := range map[int]string{429: "rate limited", 500: "status 500"} {
		b.status = status
		err := p.Test(ctx)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), password) {
			t.Fatalf("%d: err = %v", status, err)
		}
	}
}

func TestContextAndConfig(t *testing.T) {
	b := &backend{slow: 500 * time.Millisecond}
	p := newProvider(t, b, password)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Test(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if _, err := adguard.New(adguard.Config{URL: "http://dns.example.test", Username: "u", Password: "p"}); err == nil {
		t.Fatal("plain http to public name accepted")
	}
	if _, err := adguard.New(adguard.Config{URL: "https://a.example.test", Username: "u"}); err == nil {
		t.Fatal("missing password accepted")
	}
}

func TestRawStringsSentOnDeleteAndUpdate(t *testing.T) {
	ctx := context.Background()
	b := &backend{rws: []rw{{Domain: "Mixed.Example.Test.", Answer: "Target.Example.Test."}, {Domain: "keep.example.test", Answer: "A"}}}
	p := newProvider(t, b, password)
	recs, _ := p.ListRecords(ctx, "example.test")
	got := map[string]string{}
	for _, r := range recs {
		got[r.Name] = r.Type
	}
	if got["mixed.example.test"] != "CNAME" || got["keep.example.test"] != "KEEP" {
		t.Fatalf("types = %v", got)
	}
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "mixed.example.test", Type: "CNAME", Value: "other.example.test"}); err != nil {
		t.Fatal(err)
	}
	if b.rws[0].Answer != "other.example.test" {
		t.Fatalf("raw target not matched: %+v", b.rws)
	}
	b.rws[0] = rw{Domain: "Mixed.Example.Test.", Answer: "Other.Example.Test."}
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: "mixed.example.test", Type: "CNAME", Value: "other.example.test"}); err != nil {
		t.Fatal(err)
	}
	if len(b.rws) != 1 {
		t.Fatalf("delete with normalised strings left the rewrite: %+v", b.rws)
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "keep.example.test", Type: "KEEP", Value: "A"}); err == nil {
		t.Fatal("KEEP is not writable")
	}
}

func TestListingFailsClosed(t *testing.T) {
	ctx := context.Background()
	for name, raw := range map[string]string{"empty body": ``, "empty object": `{}`, "string": `"x"`, "blank entry": `[{"domain":"","answer":""}]`} {
		b := &backend{hasRaw: true, rawList: raw}
		p := newProvider(t, b, password)
		if recs, err := p.ListRecords(ctx, "example.test"); err == nil {
			t.Errorf("%s: accepted %v", name, recs)
		}
	}
	b := &backend{hasRaw: true, rawList: `null`}
	p := newProvider(t, b, password)
	if recs, err := p.ListRecords(ctx, "example.test"); err != nil || len(recs) != 0 {
		t.Fatalf("null list: recs=%v err=%v", recs, err)
	}
	if _, err := dns.New("adguard", map[string]any{"url": "https://a.lan", "username": "u", "password": "p", "allow_insecure_http": 1}, nil); err == nil {
		t.Fatal("non-bool flag accepted")
	}
}

func TestMultiValueUpdateRefused(t *testing.T) {
	b := &backend{rws: []rw{{Domain: "m.example.test", Answer: "192.0.2.1"}, {Domain: "m.example.test", Answer: "192.0.2.2"}}}
	p := newProvider(t, b, password)
	_, err := p.UpdateRecord(context.Background(), "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.9"})
	if !errors.Is(err, dns.ErrRecordExists) || len(b.rws) != 2 {
		t.Fatalf("err=%v rws=%v", err, b.rws)
	}
}

func TestWholeRawObjectSentBack(t *testing.T) {
	ctx := context.Background()
	off := false
	b := &backend{rws: []rw{{Domain: "x.example.test", Answer: "192.0.2.1", Enabled: &off}}}
	p := newProvider(t, b, password)
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "x.example.test", Type: "A", Value: "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	if len(b.rws) != 1 || b.rws[0].Answer != "192.0.2.2" || b.rws[0].Enabled == nil || *b.rws[0].Enabled {
		t.Fatalf("enabled flag lost on update: %+v", b.rws)
	}
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: "x.example.test", Type: "A", Value: "192.0.2.2"}); err != nil || len(b.rws) != 0 {
		t.Fatalf("delete with unmodelled field: err=%v rws=%+v", err, b.rws)
	}
}

func TestCNAMEBlocksARecord(t *testing.T) {
	ctx := context.Background()
	b := &backend{rws: []rw{{Domain: "c.example.test", Answer: "t.example.test"}, {Domain: "a.example.test", Answer: "192.0.2.1"}}}
	p := newProvider(t, b, password)
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "c.example.test", Type: "A", Value: "192.0.2.2"}); !errors.Is(err, dns.ErrRecordExists) {
		t.Fatalf("err = %v", err)
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "CNAME", Value: "x.example.test"}); !errors.Is(err, dns.ErrRecordExists) {
		t.Fatalf("err = %v", err)
	}
	if len(b.rws) != 2 {
		t.Fatal("conflicting rewrite created")
	}
}

func TestUpdateBodyIsByteFaithful(t *testing.T) {
	const stored = `{"zeta":1,"domain":"Mixed.Example.Test.","answer":"192.0.2.1","big":12345678901234567890,"enabled":false,"nested":{"b":2,"a":[1,2]}}`
	var got struct{ Target, Update json.RawMessage }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/rewrite/list":
			_, _ = w.Write([]byte("[" + stored + "]"))
		case "/control/rewrite/update":
			_ = json.NewDecoder(r.Body).Decode(&got)
		}
	}))
	defer srv.Close()
	p, err := adguard.New(adguard.Config{URL: srv.URL, Username: user, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpdateRecord(context.Background(), "example.test", dns.Record{Name: "mixed.example.test", Type: "A", Value: "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	if string(got.Target) != stored {
		t.Fatalf("target not sent unchanged:\n got %s\nwant %s", got.Target, stored)
	}
	want := strings.Replace(stored, `"answer":"192.0.2.1"`, `"answer":"192.0.2.2"`, 1)
	if string(got.Update) != want {
		t.Fatalf("update changed more than the answer:\n got %s\nwant %s", got.Update, want)
	}
}

func TestKeepRewriteBlocksARecord(t *testing.T) {
	b := &backend{rws: []rw{{Domain: "k.example.test", Answer: "A"}, {Domain: "k6.example.test", Answer: "AAAA"}}}
	p := newProvider(t, b, password)
	for _, n := range []string{"k.example.test", "k6.example.test"} {
		_, err := p.CreateRecord(context.Background(), "example.test", dns.Record{Name: n, Type: "A", Value: "192.0.2.1"})
		if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "KEEP") {
			t.Fatalf("%s: err = %v", n, err)
		}
	}
	if len(b.rws) != 2 {
		t.Fatal("rewrite created over a KEEP rewrite")
	}
}

func TestUpdateSplicesWithoutReescaping(t *testing.T) {
	// escapes and spacing in the stored object, "é" and "&" in values
	const stored = `{ "dom\u0061in" : "Caf\u00e9.Example.Test." , "note":"a&b <é>", "answer" : "old.example.test" , "z":[1,  2] }`
	var got struct{ Target, Update json.RawMessage }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/rewrite/list":
			_, _ = w.Write([]byte("[" + stored + "]"))
		case "/control/rewrite/update":
			_ = json.NewDecoder(r.Body).Decode(&got)
		}
	}))
	defer srv.Close()
	p, err := adguard.New(adguard.Config{URL: srv.URL, Username: user, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	// the listing normalises the name, so ask for the normalised form
	if _, err := p.UpdateRecord(context.Background(), "example.test", dns.Record{Name: "café.example.test", Type: "CNAME", Value: "new&é.example.test"}); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(stored, `"old.example.test"`, `"new&é.example.test"`, 1)
	if string(got.Update) != want {
		t.Fatalf("update:\n got %s\nwant %s", got.Update, want)
	}
	// json.NewDecoder re-wraps the RawMessage as-is, so the target must be the stored text
	if string(got.Target) != stored {
		t.Fatalf("target changed:\n got %s\nwant %s", got.Target, stored)
	}
}

func TestDeleteBodyIsTheStoredTextVerbatim(t *testing.T) {
	const stored = `{ "domain" : "a.example.test" , "answer":"192.0.2.1", "note":"x&y <é>" }`
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/rewrite/list":
			_, _ = w.Write([]byte("[" + stored + "]"))
		case "/control/rewrite/delete":
			body, _ = io.ReadAll(r.Body)
		}
	}))
	defer srv.Close()
	p, _ := adguard.New(adguard.Config{URL: srv.URL, Username: user, Password: password})
	if err := p.DeleteRecord(context.Background(), "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if string(body) != stored {
		t.Fatalf("delete body re-encoded:\n got %s\nwant %s", body, stored)
	}
}
