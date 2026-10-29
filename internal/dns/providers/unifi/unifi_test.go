package unifi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/dnstest"
	"github.com/ajthom90/doorwarden/internal/dns/providers/unifi"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const (
	fakeKey = "unifi-KEY-do-not-leak-987"
	siteID  = "11111111-2222-4333-8444-555555555555"
)

type backend struct {
	driftOnce, driftAlways bool   // totalCount changes on later pages
	listRaw                string // replaces list responses (HTTP 200) when set
	ignoreOffset           bool
	failOffset             int // fail list requests at this offset when >0
	postEmpty              bool
	mu                     sync.Mutex
	sites                  []map[string]any
	pols                   []map[string]any
	n                      int
	status                 int
	slow                   time.Duration
	huge                   bool
	requests               []string // "METHOD path"
	otherKey               string   // key seen at a redirect target
}

func fixture(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func newBackend(t *testing.T) *backend {
	b := &backend{}
	for _, s := range fixture(t, "sites.json")["data"].([]any) {
		b.sites = append(b.sites, s.(map[string]any))
	}
	for _, s := range fixture(t, "policies.json")["data"].([]any) {
		b.pols = append(b.pols, s.(map[string]any))
	}
	return b
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.slow > 0 {
		time.Sleep(b.slow)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.requests = append(b.requests, r.Method+" "+r.URL.Path)
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	if b.status != 0 {
		reply(b.status, map[string]any{"message": "failed with key " + r.Header.Get("X-API-KEY")})
		return
	}
	if r.Header.Get("X-API-KEY") != fakeKey {
		reply(401, map[string]any{"message": "unauthorized"})
		return
	}
	if b.huge {
		_, _ = w.Write([]byte(`{"data":"` + strings.Repeat("a", 5<<20) + `"}`))
		return
	}
	root := "/proxy/network/integration/v1"
	paged := func(items []map[string]any) {
		if b.listRaw != "" {
			_, _ = w.Write([]byte(b.listRaw))
			return
		}
		off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if b.failOffset > 0 && off == b.failOffset {
			reply(500, map[string]any{"message": "boom"})
			return
		}
		if b.ignoreOffset {
			off = 0
		}
		if off > len(items) {
			off = len(items)
		}
		end := off + 3 // server caps page size at 3
		if end > len(items) {
			end = len(items)
		}
		data := append([]map[string]any{}, items[off:end]...)
		total := len(items)
		if off > 0 && (b.driftOnce || b.driftAlways) {
			total++
			b.driftOnce = false
		}
		reply(200, map[string]any{"offset": off, "limit": 3, "count": end - off, "totalCount": total, "data": data})
	}
	if r.URL.Path == root+"/sites" {
		paged(b.sites)
		return
	}
	pre := root + "/sites/" + siteID + "/dns/policies"
	switch {
	case r.URL.Path == pre && r.Method == "GET":
		paged(b.pols)
	case r.URL.Path == pre && r.Method == "POST":
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		b.n++
		in["id"] = fmt.Sprintf("bbbbbbbb-0000-4000-8000-%012d", b.n)
		in["metadata"] = map[string]any{"origin": "USER_DEFINED"}
		b.pols = append(b.pols, in)
		if b.postEmpty {
			w.WriteHeader(201)
			return
		}
		reply(201, in)
	case strings.HasPrefix(r.URL.Path, pre+"/"):
		id := strings.TrimPrefix(r.URL.Path, pre+"/")
		for i, p := range b.pols {
			if p["id"] != id {
				continue
			}
			switch r.Method {
			case "PUT":
				var in map[string]any
				_ = json.NewDecoder(r.Body).Decode(&in)
				in["id"], in["metadata"] = id, p["metadata"]
				b.pols[i] = in
				reply(200, in)
			case "DELETE":
				b.pols = append(b.pols[:i], b.pols[i+1:]...)
				w.WriteHeader(200)
			}
			return
		}
		reply(404, map[string]any{"message": "not found"})
	default:
		reply(404, map[string]any{"message": "no route"})
	}
}

func newProvider(t *testing.T, b http.Handler, mod func(*unifi.Config)) *unifi.Provider {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	cfg := unifi.Config{URL: srv.URL, APIKey: secrets.Secret(fakeKey), Wildcard: true}
	if mod != nil {
		mod(&cfg)
	}
	p, err := unifi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformance(t *testing.T) {
	b := newBackend(t)
	p := newProvider(t, b, nil)
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test",
		Apex: true,
		ApexForeign: func(context.Context, string) (func() error, error) {
			b.mu.Lock()
			defer b.mu.Unlock()
			seeded := []map[string]any{
				{"type": "MX_RECORD", "id": "dddddddd-0000-4000-8000-000000000001", "enabled": true, "domain": "example.test", "mailServerDomain": "mail.example.test", "priority": 10},
				{"type": "TXT_RECORD", "id": "dddddddd-0000-4000-8000-000000000002", "enabled": true, "domain": "example.test", "text": "v=spf1 -all"},
			}
			b.pols = append(b.pols, seeded...)
			return func() error {
				b.mu.Lock()
				defer b.mu.Unlock()
				for _, w := range seeded {
					found := false
					for _, p := range b.pols {
						found = found || reflect.DeepEqual(p, w)
					}
					if !found {
						return fmt.Errorf("foreign apex policy %v changed or removed", w["id"])
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
				b.pols = append(b.pols, map[string]any{"type": "A_RECORD", "id": fmt.Sprintf("cccccccc-0000-4000-8000-%012d", b.n), "enabled": true, "domain": name, "ipv4Address": v, "ttlSeconds": 0})
			}
			return nil
		}})
}

func TestConformanceNoWildcard(t *testing.T) {
	b := newBackend(t)
	p := newProvider(t, b, func(c *unifi.Config) { c.Wildcard = false })
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test"})
}

func TestWildcardRefusedUnlessEnabled(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	p := newProvider(t, b, func(c *unifi.Config) { c.Wildcard = false })
	if p.Capabilities().WildcardA {
		t.Fatal("instance must not claim wildcard")
	}
	before := len(b.pols)
	_, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "*.example.test", Type: "A", Value: "192.0.2.9"})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("err = %v", err)
	}
	if len(b.pols) != before {
		t.Fatal("wildcard policy was created")
	}
	for _, r := range b.requests {
		if strings.HasPrefix(r, "POST") {
			t.Fatal("POST sent for refused wildcard")
		}
	}
	on := newProvider(t, b, nil)
	if !on.Capabilities().WildcardA {
		t.Fatal("wildcard: true must enable")
	}
	// via registry: flag parsed
	srv := httptest.NewServer(b)
	defer srv.Close()
	rp, err := dns.New("unifi", map[string]any{"url": srv.URL, "api_key": fakeKey, "wildcard": true}, nil)
	if err != nil || !rp.Capabilities().WildcardA {
		t.Fatalf("registry wildcard: %v", err)
	}
}

func TestForeignRecordsAnyTypeAndUnsupportedWrites(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	p := newProvider(t, b, nil)
	recs, err := p.ListRecords(ctx, "example.test")
	if err != nil || len(recs) != 3 {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
	types := map[string]string{}
	for _, r := range recs {
		types[r.Type] = r.Value
	}
	if types["A"] != "192.0.2.10" || types["CNAME"] != "app.example.test" || types["FORWARD_DOMAIN"] != "198.51.100.53" {
		t.Fatalf("types = %v", types)
	}
	for _, typ := range []string{"AAAA", "CNAME", "TXT"} {
		_, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "x.example.test", Type: typ, Value: "v"})
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("%s: err = %v", typ, err)
		}
	}
	// a user-origin foreign A record is returned unfiltered and can be conflicted with
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "app.example.test", Type: "A", Value: "192.0.2.99"}); !errors.Is(err, dns.ErrRecordExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestPaginationIteratesAll(t *testing.T) {
	b := newBackend(t)
	for i := 0; i < 10; i++ {
		b.pols = append(b.pols, map[string]any{"type": "A_RECORD", "id": fmt.Sprint("p", i), "enabled": true, "domain": fmt.Sprintf("h%d.example.test", i), "ipv4Address": "192.0.2.1", "ttlSeconds": 0})
	}
	p := newProvider(t, b, nil)
	recs, err := p.ListRecords(context.Background(), "example.test")
	if err != nil || len(recs) != 13 {
		t.Fatalf("got %d recs err %v", len(recs), err)
	}
}

func TestSiteDiscovery(t *testing.T) {
	ctx := context.Background()
	mk := func(refs ...string) *backend {
		b := newBackend(t)
		b.sites = nil
		for i, r := range refs {
			id := siteID
			if i > 0 {
				id = fmt.Sprintf("22222222-0000-4000-8000-%012d", i)
			}
			b.sites = append(b.sites, map[string]any{"id": id, "internalReference": r, "name": r})
		}
		return b
	}
	// default among several is chosen
	b := mk("default", "other")
	p := newProvider(t, b, nil)
	if _, err := p.ListRecords(ctx, "example.test"); err != nil {
		t.Fatalf("default site not chosen: %v", err)
	}
	// ambiguous: no default
	p = newProvider(t, mk("a", "b"), nil)
	if err := p.Test(ctx); err == nil || !strings.Contains(err.Error(), "site_id") || !strings.Contains(err.Error(), "none is \"default\"") {
		t.Fatalf("err = %v", err)
	}
	// none
	p = newProvider(t, mk(), nil)
	if err := p.Test(ctx); err == nil || !strings.Contains(err.Error(), "no sites") {
		t.Fatalf("err = %v", err)
	}
	// explicit site_id skips discovery
	b = mk("a", "b")
	p = newProvider(t, b, func(c *unifi.Config) { c.SiteID = siteID })
	if _, err := p.ListRecords(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	for _, r := range b.requests {
		if strings.HasSuffix(r, "/sites") {
			t.Fatal("site list requested despite site_id")
		}
	}
}

func TestErrorMappingNoSecretLeak(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	wrong := newProvider(t, b, func(c *unifi.Config) { c.APIKey = "wrong-" + fakeKey })
	err := wrong.Test(ctx)
	if err == nil || !strings.Contains(err.Error(), "authentication failed") || strings.Contains(err.Error(), fakeKey) {
		t.Fatalf("err = %v", err)
	}
	p := newProvider(t, b, nil)
	for status, want := range map[int]string{429: "rate limited", 500: "status 500"} {
		b.status = status
		err := p.Test(ctx)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), fakeKey) {
			t.Fatalf("%d: err = %v", status, err)
		}
	}
}

func TestSizeLimitAndContext(t *testing.T) {
	b := newBackend(t)
	b.huge = true
	p := newProvider(t, b, nil)
	if err := p.Test(context.Background()); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("err = %v", err)
	}
	b.huge = false
	b.slow = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Test(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestURLValidationAndRedirect(t *testing.T) {
	for _, u := range []string{"http://dns.example.test", "ftp://x", "https://user:pw@host", ""} {
		if _, err := unifi.New(unifi.Config{URL: u, APIKey: "k"}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, err := unifi.New(unifi.Config{URL: "http://dns.example.test", APIKey: "k", AllowInsecureHTTP: true}); err != nil {
		t.Errorf("allow_insecure_http ignored: %v", err)
	}
	// a redirect to another host must not receive the key
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-API-KEY") }))
	defer other.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1), http.StatusFound)
	}))
	defer src.Close()
	p, _ := unifi.New(unifi.Config{URL: src.URL, APIKey: fakeKey})
	if err := p.Test(context.Background()); err == nil || leaked != "" {
		t.Fatalf("redirect followed: err=%v leaked=%q", err, leaked)
	}
}

func TestSecretRefViaResolver(t *testing.T) {
	if _, err := dns.New("unifi", map[string]any{"url": "https://gw.example.test", "api_key": "secret:k"}, nil); err == nil {
		t.Fatal("secret ref without resolver accepted")
	}
}

func TestListingFailsClosed(t *testing.T) {
	ctx := context.Background()
	many := func(b *backend) {
		for i := 0; i < 7; i++ {
			b.pols = append(b.pols, map[string]any{"type": "A_RECORD", "id": fmt.Sprint("p", i), "enabled": true, "domain": fmt.Sprintf("h%d.example.test", i), "ipv4Address": "192.0.2.1", "ttlSeconds": 0})
		}
	}
	cases := map[string]struct {
		mod  func(*backend)
		want string
	}{
		"empty object":     {func(b *backend) { b.listRaw = `{}` }, "no data"},
		"no data key":      {func(b *backend) { b.listRaw = `{"offset":0,"limit":5,"count":0,"totalCount":0}` }, "no data"},
		"no totalCount":    {func(b *backend) { b.listRaw = `{"data":[]}` }, "no totalCount"},
		"count lies":       {func(b *backend) { b.listRaw = `{"count":0,"totalCount":3,"data":[]}` }, "empty page"},
		"ignores offset":   {func(b *backend) { many(b); b.ignoreOffset = true }, "repeated"},
		"mid-page failure": {func(b *backend) { many(b); b.failOffset = 3 }, "status 500"},
		"fewer than total": {func(b *backend) {
			b.listRaw = `{"count":1,"totalCount":2,"data":[{"id":"a","type":"A_RECORD","domain":"a.example.test","ipv4Address":"192.0.2.1"}]}`
		}, "repeated"},
		"more than total": {func(b *backend) {
			b.listRaw = `{"count":1,"totalCount":0,"data":[{"id":"a","type":"A_RECORD","domain":"a.example.test","ipv4Address":"192.0.2.1"}]}`
		}, "totalCount"},
	}
	for name, tc := range cases {
		b := newBackend(t)
		tc.mod(b)
		p := newProvider(t, b, func(c *unifi.Config) { c.SiteID = siteID })
		recs, err := p.ListRecords(ctx, "example.test")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: recs=%v err=%v", name, recs, err)
		}
	}
	// the sites list is hardened too
	b := newBackend(t)
	b.listRaw = `{}`
	if err := newProvider(t, b, nil).Test(ctx); err == nil || !strings.Contains(err.Error(), "no data") {
		t.Errorf("sites: err = %v", err)
	}
}

func TestCreateWithoutEchoFindsIDOrFails(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	b.postEmpty = true
	p := newProvider(t, b, nil)
	got, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "new.example.test", Type: "A", Value: "192.0.2.44", TTL: 60})
	if err != nil || got.ID == "" || got.Value != "192.0.2.44" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	// if the policy can't be found afterwards the create must error, not return an empty ID
	b2 := newBackend(t)
	b2.postEmpty = true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(201) // accepted but never stored
			return
		}
		b2.ServeHTTP(w, r)
	}))
	defer srv.Close()
	p2, _ := unifi.New(unifi.Config{URL: srv.URL, APIKey: fakeKey})
	if got, err := p2.CreateRecord(ctx, "example.test", dns.Record{Name: "lost.example.test", Type: "A", Value: "192.0.2.45"}); !errors.Is(err, dns.ErrUnconfirmed) || got.Name != "lost.example.test" || got.Value != "192.0.2.45" || got.ID != "" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestDisabledPolicyAndMultiMatch(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	b.pols = append(b.pols,
		map[string]any{"type": "A_RECORD", "id": "d1", "enabled": false, "domain": "off.example.test", "ipv4Address": "192.0.2.8", "ttlSeconds": 0},
		map[string]any{"type": "A_RECORD", "id": "m1", "enabled": true, "domain": "m.example.test", "ipv4Address": "192.0.2.1", "ttlSeconds": 0},
		map[string]any{"type": "A_RECORD", "id": "m2", "enabled": true, "domain": "m.example.test", "ipv4Address": "192.0.2.2", "ttlSeconds": 0})
	p := newProvider(t, b, nil)
	// same value but disabled: not a silent success
	_, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "off.example.test", Type: "A", Value: "192.0.2.8"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("err = %v", err)
	}
	_, err = p.UpdateRecord(ctx, "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.99"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "2 DNS policies") {
		t.Fatalf("err = %v", err)
	}
}

func TestCNAMEAndForwardPoliciesBlockA(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	p := newProvider(t, b, nil)
	before := len(b.pols)
	for _, name := range []string{"alias.example.test", "corp.example.test"} { // fixture CNAME_RECORD / FORWARD_DOMAIN
		_, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: name, Type: "A", Value: "192.0.2.50"})
		if !errors.Is(err, dns.ErrRecordExists) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if len(b.pols) != before {
		t.Fatal("conflicting policy was created")
	}
}

func TestTotalCountDriftRetriedOnceThenError(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	for i := 0; i < 7; i++ {
		b.pols = append(b.pols, map[string]any{"type": "A_RECORD", "id": fmt.Sprint("p", i), "enabled": true, "domain": fmt.Sprintf("h%d.example.test", i), "ipv4Address": "192.0.2.1", "ttlSeconds": 0})
	}
	b.driftOnce = true
	p := newProvider(t, b, func(c *unifi.Config) { c.SiteID = siteID })
	if recs, err := p.ListRecords(ctx, "example.test"); err != nil || len(recs) != 10 {
		t.Fatalf("single drift must be retried: recs=%d err=%v", len(recs), err)
	}
	b.driftAlways = true
	if _, err := p.ListRecords(ctx, "example.test"); err == nil || !strings.Contains(err.Error(), "totalCount changed") {
		t.Fatalf("err = %v", err)
	}
}

func TestDeleteByIDRefusesNameMismatch(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	p := newProvider(t, b, nil)
	id := "aaaaaaaa-0000-4000-8000-000000000001" // app.example.test A
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{ID: id, Name: "other.example.test", Type: "A"}); err == nil {
		t.Fatal("deleted a policy under the wrong name")
	}
	if len(b.pols) != 3 {
		t.Fatal("policy removed")
	}
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{ID: id}); err != nil || len(b.pols) != 2 {
		t.Fatalf("plain delete by ID: err=%v pols=%d", err, len(b.pols))
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
	b := newBackend(t)
	srv := httptest.NewServer(applyThenDrop(b, func(r *http.Request) bool { return r.Method != "GET" }))
	defer srv.Close()
	p, _ := unifi.New(unifi.Config{URL: srv.URL, APIKey: fakeKey})
	got, err := p.CreateRecord(ctx, "example.test", rec)
	if !errors.Is(err, dns.ErrUnconfirmed) || got.Name != rec.Name || got.Value != rec.Value || got.ID != "" {
		t.Fatalf("create: got %+v err %v", got, err)
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
			b := newBackend(t)
			return newProvider(t, b, nil), newProvider(t, wrap(b), nil)
		},
		IsWrite:     func(r *http.Request) bool { return r.Method != "GET" },
		Create:      dns.Record{Name: "new.example.test", Type: "A", Value: "192.0.2.10"},
		Existing:    dns.Record{Name: "old.example.test", Type: "A", Value: "192.0.2.11"},
		UpdateValue: "192.0.2.12",
	})
}
