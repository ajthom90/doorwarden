package cloudflare_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/dnstest"
	"github.com/ajthom90/doorwarden/internal/dns/providers/cloudflare"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const fakeToken = "cf-TOKEN-do-not-leak-123"

type rec struct {
	ID, Name, Type, Content, zone string
	TTL                           int
}

type backend struct {
	getByID400 bool   // GET of a record by ID answers 400 (a malformed request, not "not found")
	zeroPages  bool   // report total_pages: 0
	delFail    bool   // DELETE answers success:false
	raw        string // when set, replaces the dns_records list response body (HTTP 200)
	noInfo     bool   // omit result_info from list responses
	perPage    int    // page size (default 3)
	mu         sync.Mutex
	n          int
	recs       []rec
	zones      map[string]string
	status     int // when non-zero, every request fails with it
	slow       time.Duration
}

func newBackend() *backend {
	return &backend{zones: map[string]string{"example.test": "zid-1", "other.test": "zid-2"}}
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.slow > 0 {
		b.mu.Unlock()
		time.Sleep(b.slow)
		b.mu.Lock()
	}
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(code int, msg string) {
		reply(code, map[string]any{"success": false, "errors": []map[string]any{{"code": 1, "message": msg}}})
	}
	if b.status != 0 {
		fail(b.status, "forced failure "+r.Header.Get("Authorization"))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		fail(403, "invalid token")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/client/v4")
	if p == "/zones" {
		res := []map[string]string{}
		for n, id := range b.zones {
			if q := r.URL.Query().Get("name"); q == "" || q == n {
				res = append(res, map[string]string{"id": id, "name": n})
			}
		}
		reply(200, map[string]any{"success": true, "result": res})
		return
	}
	parts := strings.Split(strings.TrimPrefix(p, "/zones/"), "/")
	zone := ""
	for n, id := range b.zones {
		if id == parts[0] {
			zone = n
		}
	}
	if zone == "" || len(parts) < 2 || parts[1] != "dns_records" {
		fail(404, "no route")
		return
	}
	toJSON := func(x rec) map[string]any {
		return map[string]any{"id": x.ID, "name": x.Name, "type": x.Type, "content": x.Content, "ttl": x.TTL}
	}
	find := func(id string) int {
		for i, x := range b.recs {
			if x.ID == id && x.zone == zone {
				return i
			}
		}
		return -1
	}
	if len(parts) == 2 {
		switch r.Method {
		case "GET":
			q := r.URL.Query()
			var match []rec
			for _, x := range b.recs {
				if x.zone != zone || (q.Get("name.exact") != "" && x.Name != q.Get("name.exact")) || (q.Get("type") != "" && x.Type != q.Get("type")) {
					continue
				}
				match = append(match, x)
			}
			page, _ := strconv.Atoi(q.Get("page"))
			per := 3 // force pagination regardless of per_page
			if b.perPage > 0 {
				per = b.perPage
			}
			if b.raw != "" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(b.raw))
				return
			}
			total := (len(match) + per - 1) / per
			lo, hi := (page-1)*per, page*per
			if lo > len(match) {
				lo = len(match)
			}
			if hi > len(match) {
				hi = len(match)
			}
			res := []map[string]any{}
			for _, x := range match[lo:hi] {
				res = append(res, toJSON(x))
			}
			resp := map[string]any{"success": true, "result": res}
			if !b.noInfo {
				if b.zeroPages {
					total = 0
				}
				resp["result_info"] = map[string]int{"page": page, "total_pages": total}
			}
			reply(200, resp)
		case "POST":
			var in struct {
				Type, Name, Content string
				TTL                 int
				Proxied             bool
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Proxied {
				fail(400, "proxied must be false")
				return
			}
			b.n++
			x := rec{ID: fmt.Sprintf("r%d", b.n), Name: in.Name, Type: in.Type, Content: in.Content, TTL: in.TTL, zone: zone}
			b.recs = append(b.recs, x)
			reply(200, map[string]any{"success": true, "result": toJSON(x)})
		}
		return
	}
	i := find(parts[2])
	if i < 0 {
		fail(404, "record not found")
		return
	}
	switch r.Method {
	case "GET":
		if b.getByID400 {
			fail(400, "Invalid request")
			return
		}
		reply(200, map[string]any{"success": true, "result": toJSON(b.recs[i])})
	case "PATCH":
		var in struct {
			Content string
			TTL     int
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		b.recs[i].Content, b.recs[i].TTL = in.Content, in.TTL
		reply(200, map[string]any{"success": true, "result": toJSON(b.recs[i])})
	case "DELETE":
		if b.delFail {
			reply(200, map[string]any{"success": false, "errors": []map[string]any{{"message": "cannot delete"}}})
			return
		}
		b.recs = append(b.recs[:i], b.recs[i+1:]...)
		reply(200, map[string]any{"success": true, "result": map[string]string{"id": parts[2]}})
	}
}

func newProvider(t *testing.T, b *backend, token string) *cloudflare.Provider {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	p, err := cloudflare.New(cloudflare.Config{APIToken: secrets.Secret(token), BaseURL: srv.URL + "/client/v4"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformance(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, fakeToken)
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test",
		Apex: true,
		ApexForeign: func(context.Context, string) (func() error, error) {
			b.mu.Lock()
			defer b.mu.Unlock()
			seeded := []rec{
				{ID: "apex-ns", Name: "example.test", Type: "NS", Content: "ns1.example.test", TTL: 1, zone: "example.test"},
				{ID: "apex-mx", Name: "example.test", Type: "MX", Content: "mail.example.test", TTL: 1, zone: "example.test"},
				{ID: "apex-txt", Name: "example.test", Type: "TXT", Content: "v=spf1 -all", TTL: 1, zone: "example.test"},
			}
			b.recs = append(b.recs, seeded...)
			return func() error {
				b.mu.Lock()
				defer b.mu.Unlock()
				for _, w := range seeded {
					if !slices.Contains(b.recs, w) {
						return fmt.Errorf("foreign apex record %s %s changed or removed", w.Type, w.Content)
					}
				}
				return nil
			}, nil
		},
		SeedMultiValue: func(_ context.Context, _, name string, values ...string) error {
			b.mu.Lock()
			defer b.mu.Unlock()
			for _, v := range values {
				b.n++
				b.recs = append(b.recs, rec{ID: fmt.Sprintf("s%d", b.n), Name: name, Type: "A", Content: v, TTL: 1, zone: "example.test"})
			}
			return nil
		}})
}

func TestRegisteredAndSecretResolution(t *testing.T) {
	if c, ok := dns.CapsFor("cloudflare"); !ok || !c.WildcardA || !c.TTL {
		t.Fatalf("caps %+v", c)
	}
	if _, err := dns.New("cloudflare", map[string]any{}, nil); err == nil {
		t.Fatal("missing token accepted")
	}
	p, err := dns.New("cloudflare", map[string]any{"api_token": "x"}, nil)
	if err != nil || p.Type() != "cloudflare" {
		t.Fatal(err)
	}
}

func TestErrorMappingNoSecretLeak(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	// wrong token -> 403
	p := newProvider(t, b, "wrong-"+fakeToken)
	err := p.Test(ctx)
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Fatal("secret leaked")
	}
	// rate limit, with the backend echoing the Authorization header in its body
	b.status = 429
	p = newProvider(t, b, fakeToken)
	err = p.Test(ctx)
	if err == nil || !strings.Contains(err.Error(), "rate limited") || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("err = %v", err)
	}
	b.status = 500
	err = p.Test(ctx)
	if err == nil || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("500 err leaked: %v", err)
	}
	// unknown zone
	b.status = 0
	_, err = p.ListRecords(ctx, "nope.test")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("zone err = %v", err)
	}
}

func TestPaginationAndForeignRecords(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	p := newProvider(t, b, fakeToken)
	for i := 0; i < 8; i++ {
		b.recs = append(b.recs, rec{ID: fmt.Sprint("f", i), Name: fmt.Sprintf("h%d.example.test", i), Type: "A", Content: "192.0.2.1", TTL: 1, zone: "example.test"})
	}
	recs, err := p.ListRecords(ctx, "example.test")
	if err != nil || len(recs) != 8 {
		t.Fatalf("recs=%d err=%v", len(recs), err)
	}
	if recs[0].TTL != 0 {
		t.Fatalf("automatic ttl should map to 0, got %d", recs[0].TTL)
	}
}

func TestContextTimeout(t *testing.T) {
	b := newBackend()
	b.slow = 500 * time.Millisecond
	p := newProvider(t, b, fakeToken)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Test(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIURLRejectedFromConfig(t *testing.T) {
	_, err := dns.New("cloudflare", map[string]any{"api_token": fakeToken, "api_url": "https://evil.example.test"}, nil)
	if err == nil || !strings.Contains(err.Error(), "api_url") || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("err = %v", err)
	}
	sch, _ := dns.SchemaFor("cloudflare")
	for _, f := range sch.Fields {
		if f.Name == "api_url" {
			t.Fatal("api_url in schema")
		}
	}
}

func seedMulti(b *backend) {
	for i, v := range []string{"192.0.2.1", "192.0.2.2"} {
		b.recs = append(b.recs, rec{ID: fmt.Sprint("m", i), Name: "m.example.test", Type: "A", Content: v, TTL: 1, zone: "example.test"})
	}
}

func TestMultiRecordUpdateRefusedDeleteFindsExactValue(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	seedMulti(b)
	p := newProvider(t, b, fakeToken)
	_, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.99"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "2 records") {
		t.Fatalf("err = %v", err)
	}
	// the exact value is the SECOND match; it must still be found and removed
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	if len(b.recs) != 1 || b.recs[0].Content != "192.0.2.1" {
		t.Fatalf("recs = %+v", b.recs)
	}
}

func TestListingHardening(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		mod  func(*backend)
		want string
	}{
		"empty object":  {func(b *backend) { b.raw = `{}` }, "malformed"},
		"success false": {func(b *backend) { b.raw = `{"success":false,"errors":[{"message":"bad things"}],"result":[]}` }, "bad things"},
		"no result":     {func(b *backend) { b.raw = `{"success":true}` }, "no result"},
		"full page no info": {func(b *backend) {
			b.noInfo, b.perPage = true, 100
			for i := 0; i < 100; i++ {
				b.recs = append(b.recs, rec{ID: fmt.Sprint("r", i), Name: fmt.Sprintf("h%d.example.test", i), Type: "A", Content: "192.0.2.1", zone: "example.test"})
			}
		}, "total_pages"},
	} {
		b := newBackend()
		tc.mod(b)
		p := newProvider(t, b, fakeToken)
		_, err := p.ListRecords(ctx, "example.test")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// a short single page without result_info is fine
	b := newBackend()
	b.noInfo = true
	b.recs = append(b.recs, rec{ID: "x", Name: "a.example.test", Type: "A", Content: "192.0.2.1", zone: "example.test"})
	p := newProvider(t, b, fakeToken)
	if recs, err := p.ListRecords(ctx, "example.test"); err != nil || len(recs) != 1 {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
}

func TestCNAMEBlocksARecord(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.recs = append(b.recs, rec{ID: "c1", Name: "c.example.test", Type: "CNAME", Content: "t.example.test", TTL: 1, zone: "example.test"},
		rec{ID: "a1", Name: "a.example.test", Type: "A", Content: "192.0.2.1", TTL: 1, zone: "example.test"})
	p := newProvider(t, b, fakeToken)
	_, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "c.example.test", Type: "A", Value: "192.0.2.2"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "CNAME") {
		t.Fatalf("err = %v", err)
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "CNAME", Value: "x.example.test"}); !errors.Is(err, dns.ErrRecordExists) {
		t.Fatalf("err = %v", err)
	}
	if len(b.recs) != 2 {
		t.Fatal("conflicting record was created")
	}
}

func TestZeroTotalPagesWithFullPageIsError(t *testing.T) {
	b := newBackend()
	b.zeroPages, b.perPage = true, 100
	for i := 0; i < 100; i++ {
		b.recs = append(b.recs, rec{ID: fmt.Sprint("r", i), Name: fmt.Sprintf("h%d.example.test", i), Type: "A", Content: "192.0.2.1", zone: "example.test"})
	}
	if _, err := newProvider(t, b, fakeToken).ListRecords(context.Background(), "example.test"); err == nil {
		t.Fatal("total_pages 0 with a full page accepted")
	}
}

func TestDeleteByIDVerifiesNameAndCheckSuccess(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.recs = append(b.recs, rec{ID: "a1", Name: "a.example.test", Type: "A", Content: "192.0.2.1", TTL: 1, zone: "example.test"})
	p := newProvider(t, b, fakeToken)
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{ID: "a1", Name: "other.example.test", Type: "A"}); err == nil || len(b.recs) != 1 {
		t.Fatalf("id with the wrong name deleted: err=%v recs=%d", err, len(b.recs))
	}
	b.delFail = true
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{ID: "a1"}); err == nil || !strings.Contains(err.Error(), "cannot delete") {
		t.Fatalf("success:false on DELETE accepted: %v", err)
	}
	b.delFail = false
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{ID: "a1", Name: "a.example.test", Type: "A"}); err != nil || len(b.recs) != 0 {
		t.Fatalf("err=%v recs=%d", err, len(b.recs))
	}
}

func TestOnly404MeansNotFoundByID(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.recs = append(b.recs, rec{ID: "a1", Name: "a.example.test", Type: "A", Content: "192.0.2.1", TTL: 1, zone: "example.test"})
	p := newProvider(t, b, fakeToken)
	// unknown ID: 404 => ErrNotFound / no-op delete
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{ID: "nope", Name: "a.example.test", Type: "A", Value: "192.0.2.2"}); !errors.Is(err, dns.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{ID: "nope"}); err != nil {
		t.Fatal(err)
	}
	// a 400 is NOT "not found": Delete must not silently succeed
	b.getByID400 = true
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{ID: "a1"}); err == nil {
		t.Fatal("400 on get-by-ID treated as not found")
	}
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{ID: "a1", Name: "a.example.test", Type: "A", Value: "192.0.2.2"}); err == nil || errors.Is(err, dns.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// applyThenDrop serves mutating requests (selected by match) by applying them to
// the backend and then cutting the connection without answering: the write
// happened but the client cannot know.
func applyThenDrop(inner http.Handler, match func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !match(r) {
			inner.ServeHTTP(w, r)
			return
		}
		inner.ServeHTTP(httptest.NewRecorder(), r)
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
			}
		}
	})
}

func TestAmbiguousWriteIsUnconfirmedDefinitiveIsPlain(t *testing.T) {
	ctx := context.Background()
	rec := dns.Record{Name: "amb.example.test", Type: "A", Value: "192.0.2.1"}
	b := newBackend()
	srv := httptest.NewServer(applyThenDrop(b, func(r *http.Request) bool { return r.Method != "GET" }))
	defer srv.Close()
	p, _ := cloudflare.New(cloudflare.Config{APIToken: secrets.Secret(fakeToken), BaseURL: srv.URL + "/client/v4"})
	got, err := p.CreateRecord(ctx, "example.test", rec)
	if !errors.Is(err, dns.ErrUnconfirmed) || got.Name != rec.Name || got.Value != rec.Value {
		t.Fatalf("create: got %+v err %v", got, err)
	}
	b.mu.Lock()
	n := len(b.recs)
	b.mu.Unlock()
	if n != 1 {
		t.Fatalf("the dropped create was applied: %d records", n)
	}
	if got, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: rec.Name, Type: "A", Value: "192.0.2.2"}); !errors.Is(err, dns.ErrUnconfirmed) || got.Value != "192.0.2.2" || got.ID == "" {
		t.Fatalf("update: got %+v err %v", got, err)
	}
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: rec.Name, Type: "A", Value: "192.0.2.2"}); !errors.Is(err, dns.ErrUnconfirmed) {
		t.Fatalf("delete: %v", err)
	}
}

// TestWriteStatusClassification answers ONLY the mutating request with each
// error status: a 4xx is a plain error with an empty Record, every 5xx
// (including an HTML proxy page) wraps dns.ErrUnconfirmed with the record.
func TestWriteStatusClassification(t *testing.T) {
	dnstest.CheckWriteStatuses(t, dnstest.WriteStatusHarness{
		Zone: "example.test",
		New: func(t *testing.T, wrap func(http.Handler) http.Handler) (dns.Provider, dns.Provider) {
			b := newBackend()
			srv := httptest.NewServer(wrap(b))
			t.Cleanup(srv.Close)
			p, err := cloudflare.New(cloudflare.Config{APIToken: secrets.Secret(fakeToken), BaseURL: srv.URL + "/client/v4"})
			if err != nil {
				t.Fatal(err)
			}
			return newProvider(t, b, fakeToken), p
		},
		IsWrite:     func(r *http.Request) bool { return r.Method != "GET" },
		Create:      dns.Record{Name: "new.example.test", Type: "A", Value: "192.0.2.10"},
		Existing:    dns.Record{Name: "old.example.test", Type: "A", Value: "192.0.2.11"},
		UpdateValue: "192.0.2.12",
	})
}
