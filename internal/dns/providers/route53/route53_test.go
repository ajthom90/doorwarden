package route53_test

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/dnstest"
	"github.com/ajthom90/doorwarden/internal/dns/providers/route53"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const (
	fakeKeyID  = "AKIATESTKEYID00000"
	fakeSecret = "r53-SECRET-do-not-leak-xyz"
	ns         = `xmlns="https://route53.amazonaws.com/doc/2013-04-01/"`
)

type zone struct {
	pending  map[string]*set // changes not yet visible to reads
	id, name string
	private  bool
	sets     map[string]*set // key name|type
}

type set struct {
	name, typ string
	ttl       int
	vals      []string
	alias     bool
}

type backend struct {
	rejectChange, dropAfterApply, stallChange bool          // change-call failure modes
	afterChange                               func(z *zone) // runs after a change was applied (simulates another writer)
	lag, lagLeft                              int           // reads that still show the old state after a change
	mu                                        sync.Mutex
	zones                                     []*zone
	failCode                                  string // when set, every call fails with this error code
	slow                                      time.Duration
	listed                                    []string // hosted zone ids whose rrsets were listed
	zonePages, setPages                       int
	badAll, badSets, badPost                  string // serve a malformed HTTP 200 body for all / rrset / change requests
	dropChange                                bool   // acknowledge changes without applying them
	brokenTrunc                               bool   // truncated pages without a continuation marker
	posts                                     int    // change requests received
	changeStatus                              int    // answer change requests with this HTTP status (not applied)
	changeBody                                string // body for changeStatus ("" = an XML ServiceUnavailable error)
	applyThenReject                           bool   // apply the change, then answer InvalidChangeBatch (a lost first attempt)
}

// mkzone builds a hosted zone with the apex SOA and NS sets every real zone has.
func mkzone(id, name string, private bool) *zone {
	z := &zone{id: id, name: name, private: private, sets: map[string]*set{}}
	z.sets[name+"|SOA"] = &set{name: name, typ: "SOA", ttl: 900, vals: []string{"ns-1.example.net. hostmaster.example.net. 1 7200 900 1209600 86400"}}
	z.sets[name+"|NS"] = &set{name: name, typ: "NS", ttl: 172800, vals: []string{"ns-1.example.net."}}
	return z
}

func newBackend() *backend {
	return &backend{zones: []*zone{
		mkzone("ZTEST", "test.", false),
		mkzone("ZEXAMPLE", "example.test.", false),
		mkzone("ZPRIV", "example.test.", true),
		mkzone("ZOTHER", "other.test.", false),
	}}
}

func (b *backend) zone(id string) *zone {
	for _, z := range b.zones {
		if z.id == id {
			return z
		}
	}
	return nil
}

// norm mirrors Route 53 name handling: case-insensitive, always stored with a
// trailing dot.
func norm(n string) string { return strings.TrimSuffix(strings.ToLower(n), ".") + "." }

func (b *backend) writeBad(w http.ResponseWriter, mode string) {
	switch mode {
	case "empty":
	case "json":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	case "emptyxml":
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<ListResourceRecordSetsResponse/>`))
	case "html":
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Please log in to the network</body></html>`))
	case "trunc":
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>a.exa`))
	}
}

func xmlErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<ErrorResponse %s><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error><RequestId>req-1</RequestId></ErrorResponse>`, ns, code, msg)
}

type changeBatch struct {
	Changes []struct {
		Action string `xml:"Action"`
		Set    struct {
			Name    string `xml:"Name"`
			Type    string `xml:"Type"`
			TTL     int    `xml:"TTL"`
			Records []struct {
				Value string `xml:"Value"`
			} `xml:"ResourceRecords>ResourceRecord"`
		} `xml:"ResourceRecordSet"`
	} `xml:"ChangeBatch>Changes>Change"`
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.slow > 0 {
		time.Sleep(b.slow)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failCode != "" {
		code := 400
		if b.failCode == "InvalidClientTokenId" {
			code = 403
		}
		xmlErr(w, code, b.failCode, "failed; credential "+fakeSecret)
		return
	}
	if b.badAll != "" || (b.badSets != "" && strings.Contains(r.URL.Path, "/rrset") && r.Method == "GET") {
		mode := b.badAll
		if mode == "" {
			mode = b.badSets
		}
		b.writeBad(w, mode)
		return
	}
	if !strings.Contains(r.Header.Get("Authorization"), "Credential="+fakeKeyID+"/") {
		xmlErr(w, 403, "InvalidClientTokenId", "The security token included in the request is invalid.")
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	path := strings.TrimPrefix(r.URL.Path, "/2013-04-01")
	switch {
	case path == "/hostedzone" && r.Method == "GET":
		start := 0
		if m := r.URL.Query().Get("marker"); m != "" {
			for i, z := range b.zones {
				if z.id == m {
					start = i
				}
			}
		}
		per := 1 // truncate after every zone
		if m := r.URL.Query().Get("maxitems"); m == "1" {
			per = 1
		}
		end := start + per
		if end > len(b.zones) {
			end = len(b.zones)
		}
		b.zonePages++
		fmt.Fprintf(w, `<ListHostedZonesResponse %s><HostedZones>`, ns)
		for _, z := range b.zones[start:end] {
			fmt.Fprintf(w, `<HostedZone><Id>/hostedzone/%s</Id><Name>%s</Name><CallerReference>c</CallerReference><Config><PrivateZone>%v</PrivateZone></Config><ResourceRecordSetCount>0</ResourceRecordSetCount></HostedZone>`, z.id, z.name, z.private)
		}
		fmt.Fprintf(w, `</HostedZones>`)
		if end < len(b.zones) {
			fmt.Fprintf(w, `<IsTruncated>true</IsTruncated><NextMarker>%s</NextMarker>`, b.zones[end].id)
		} else {
			fmt.Fprint(w, `<IsTruncated>false</IsTruncated>`)
		}
		fmt.Fprintf(w, `<MaxItems>%d</MaxItems></ListHostedZonesResponse>`, per)
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/hostedzone/"), "/")
	z := b.zone(parts[0])
	if z == nil {
		xmlErr(w, 404, "NoSuchHostedZone", "No hosted zone found with ID: "+parts[0])
		return
	}
	switch {
	case len(parts) == 1 && r.Method == "GET":
		fmt.Fprintf(w, `<GetHostedZoneResponse %s><HostedZone><Id>/hostedzone/%s</Id><Name>%s</Name><CallerReference>c</CallerReference></HostedZone></GetHostedZoneResponse>`, ns, z.id, z.name)
	case len(parts) == 2 && parts[1] == "rrset" && r.Method == "GET":
		if z.pending != nil {
			if b.lagLeft > 0 {
				b.lagLeft--
			} else {
				z.sets, z.pending = z.pending, nil
			}
		}
		b.listed = append(b.listed, z.id)
		q := r.URL.Query()
		var all []*set
		for _, s := range z.sets {
			all = append(all, s)
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].name != all[j].name {
				return all[i].name < all[j].name
			}
			return all[i].typ < all[j].typ
		})
		sn, st := norm(q.Get("name")), q.Get("type")
		if q.Get("name") == "" {
			sn = ""
		}
		start := 0
		for start < len(all) && (all[start].name < sn || (all[start].name == sn && all[start].typ < st)) {
			start++
		}
		per := 2 // force pagination
		b.setPages++
		if m := q.Get("maxitems"); m == "1" {
			per = 1
		}
		end := start + per
		if end > len(all) {
			end = len(all)
		}
		fmt.Fprintf(w, `<ListResourceRecordSetsResponse %s><ResourceRecordSets>`, ns)
		for _, s := range all[start:end] {
			if s.alias {
				fmt.Fprintf(w, `<ResourceRecordSet><Name>%s</Name><Type>%s</Type><AliasTarget><HostedZoneId>Z9</HostedZoneId><DNSName>lb.example.test.</DNSName><EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget></ResourceRecordSet>`, s.name, s.typ)
				continue
			}
			fmt.Fprintf(w, `<ResourceRecordSet><Name>%s</Name><Type>%s</Type><TTL>%d</TTL><ResourceRecords>`, s.name, s.typ, s.ttl)
			for _, v := range s.vals {
				fmt.Fprintf(w, `<ResourceRecord><Value>%s</Value></ResourceRecord>`, v)
			}
			fmt.Fprint(w, `</ResourceRecords></ResourceRecordSet>`)
		}
		fmt.Fprint(w, `</ResourceRecordSets>`)
		if end < len(all) && b.brokenTrunc {
			fmt.Fprint(w, `<IsTruncated>true</IsTruncated>`)
		} else if end < len(all) {
			fmt.Fprintf(w, `<IsTruncated>true</IsTruncated><NextRecordName>%s</NextRecordName><NextRecordType>%s</NextRecordType>`, all[end].name, all[end].typ)
		} else {
			fmt.Fprint(w, `<IsTruncated>false</IsTruncated>`)
		}
		fmt.Fprintf(w, `<MaxItems>%d</MaxItems></ListResourceRecordSetsResponse>`, per)
	case len(parts) == 2 && parts[1] == "rrset" && r.Method == "POST":
		b.posts++
		body, _ := io.ReadAll(r.Body)
		var cb changeBatch
		if err := xml.Unmarshal(body, &cb); err != nil {
			xmlErr(w, 400, "MalformedXML", err.Error())
			return
		}
		if b.badPost != "" {
			b.writeBad(w, b.badPost)
			return
		}
		if b.rejectChange {
			xmlErr(w, 400, "InvalidChangeBatch", "refused")
			return
		}
		if b.changeStatus != 0 {
			if b.changeBody != "" {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(b.changeStatus)
				_, _ = w.Write([]byte(b.changeBody))
				return
			}
			code := "ServiceUnavailable"
			switch {
			case b.changeStatus == 500:
				code = "InternalFailure"
			case b.changeStatus < 500:
				code = "Throttling"
			}
			xmlErr(w, b.changeStatus, code, "change failed")
			return
		}
		if b.stallChange { // times out on the client before anything is applied
			b.mu.Unlock()
			time.Sleep(700 * time.Millisecond)
			b.mu.Lock()
			return
		}
		next := map[string]*set{}
		for k, v := range z.sets {
			next[k] = v
		}
		for _, c := range cb.Changes {
			c.Set.Name = norm(c.Set.Name)
			key := c.Set.Name + "|" + c.Set.Type
			var vals []string
			for _, rr := range c.Set.Records {
				vals = append(vals, rr.Value)
			}
			switch c.Action {
			case "CREATE":
				if _, ok := next[key]; ok {
					xmlErr(w, 400, "InvalidChangeBatch", "Tried to create resource record set but it already exists")
					return
				}
				next[key] = &set{name: c.Set.Name, typ: c.Set.Type, ttl: c.Set.TTL, vals: vals}
			case "UPSERT":
				next[key] = &set{name: c.Set.Name, typ: c.Set.Type, ttl: c.Set.TTL, vals: vals}
			case "DELETE":
				cur, ok := next[key]
				// like the real service, DELETE must match the stored set exactly
				if !ok || cur.ttl != c.Set.TTL || strings.Join(cur.vals, ",") != strings.Join(vals, ",") {
					xmlErr(w, 400, "InvalidChangeBatch", "Tried to delete resource record set but it was not found or its values do not match")
					return
				}
				delete(next, key)
			}
		}
		if b.afterChange != nil && !b.dropChange {
			z.sets = next
			b.afterChange(z)
			next = z.sets
		}
		if b.applyThenReject { // an earlier attempt applied it: this one is refused
			z.sets = next
			xmlErr(w, 400, "InvalidChangeBatch", "[Tried to create resource record set [name='x', type='A'] but it already exists, Tried to delete resource record set [name='x', type='A'] but the values provided do not match the current values]")
			return
		}
		if b.dropAfterApply { // apply, then cut the connection before answering
			z.sets = next
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		if !b.dropChange && b.lag > 0 {
			z.pending, b.lagLeft = next, b.lag
		} else if !b.dropChange {
			z.sets = next // the batch is atomic
		}
		fmt.Fprintf(w, `<ChangeResourceRecordSetsResponse %s><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status><SubmittedAt>2024-01-01T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>`, ns)
	default:
		xmlErr(w, 404, "NoSuchHostedZone", "bad route")
	}
}

func (b *backend) seed(zid, name string, values ...string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := norm(name) // the real service stores names with a trailing dot
	b.zone(zid).sets[n+"|A"] = &set{name: n, typ: "A", ttl: 300, vals: values}
}

// fakeClock is the injected time source: Sleep advances it instantly, so the
// verification polling never waits in real time.
type fakeClock struct {
	mu      sync.Mutex
	t       time.Time
	slept   time.Duration
	onSleep func() // runs on every sleep (tests use it to cancel a context)
}

func newClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if c.onSleep != nil {
		c.onSleep()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.t, c.slept = c.t.Add(d), c.slept+d
	c.mu.Unlock()
	return nil
}

func newProvider(t *testing.T, b *backend, mod func(*route53.Config)) *route53.Provider {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	clk := newClock()
	cfg := route53.Config{AccessKeyID: fakeKeyID, SecretAccessKey: fakeSecret, Endpoint: srv.URL,
		VerifyTimeout: 10 * time.Second, VerifyInterval: time.Second, Now: clk.now, Sleep: clk.sleep}
	if mod != nil {
		mod(&cfg)
	}
	p, err := route53.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformance(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, nil)
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test",
		SeedMultiValue: func(_ context.Context, _, name string, values ...string) error {
			b.seed("ZEXAMPLE", name, values...)
			return nil
		},
		Unconfirmed: func(t *testing.T) dns.Provider {
			lagging := &lagHandler{inner: b}
			srv := httptest.NewServer(lagging)
			t.Cleanup(srv.Close)
			clk := newClock()
			p, err := route53.New(context.Background(), route53.Config{AccessKeyID: fakeKeyID, SecretAccessKey: fakeSecret, Endpoint: srv.URL,
				VerifyTimeout: 3 * time.Second, VerifyInterval: time.Second, Now: clk.now, Sleep: clk.sleep})
			if err != nil {
				t.Fatal(err)
			}
			return p
		}})
	// all rrset activity for example.test went to the public longest-suffix zone
	for _, id := range b.listed {
		if id == "ZTEST" || id == "ZPRIV" {
			t.Fatalf("listed wrong zone %s", id)
		}
	}
}

func TestZoneAutoDiscoveryLongestSuffix(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	p := newProvider(t, b, nil)
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if len(b.zone("ZEXAMPLE").sets) != 3 || len(b.zone("ZTEST").sets) != 2 || len(b.zone("ZPRIV").sets) != 2 {
		t.Fatalf("record landed in wrong zone: example=%d test=%d priv=%d", len(b.zone("ZEXAMPLE").sets), len(b.zone("ZTEST").sets), len(b.zone("ZPRIV").sets))
	}
	// a sub-zone with no own hosted zone falls back to the parent
	if _, err := p.CreateRecord(ctx, "lab.example.test", dns.Record{Name: "x.lab.example.test", Type: "A", Value: "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	if len(b.zone("ZEXAMPLE").sets) != 4 {
		t.Fatal("sub-zone record not in parent zone")
	}
	// a zone with no matching hosted zone
	if _, err := p.ListRecords(ctx, "nomatch.invalid"); err == nil || !strings.Contains(err.Error(), "no hosted zone") {
		t.Fatalf("err = %v", err)
	}
}

func TestPrivateZoneOnlyWithHostedZoneID(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.zones = []*zone{mkzone("ZPRIV", "internal.test.", true)}
	p := newProvider(t, b, nil)
	if _, err := p.ListRecords(ctx, "internal.test"); err == nil || !strings.Contains(err.Error(), "hosted_zone_id") {
		t.Fatalf("private zone chosen implicitly: %v", err)
	}
	pinned := newProvider(t, b, func(c *route53.Config) { c.HostedZoneID = "/hostedzone/ZPRIV" })
	if _, err := pinned.CreateRecord(ctx, "internal.test", dns.Record{Name: "a.internal.test", Type: "A", Value: "192.0.2.5"}); err != nil {
		t.Fatal(err)
	}
	if len(b.zone("ZPRIV").sets) != 3 {
		t.Fatal("pinned private zone not used")
	}
	if pinned.Capabilities().MultiZone {
		t.Fatal("pinned provider must not claim MultiZone")
	}
	if err := pinned.Test(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestErrorMappingNoSecretLeak(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	for code, want := range map[string]string{"InvalidClientTokenId": "authentication", "Throttling": "rate limited", "SomethingElse": "SomethingElse"} {
		b.failCode = code
		p := newProvider(t, b, nil)
		err := p.Test(ctx)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v", code, err)
		}
		if strings.Contains(err.Error(), fakeSecret) {
			t.Fatalf("%s: secret leaked: %v", code, err)
		}
	}
	// bad credentials against the real signature check path
	b.failCode = ""
	srv := httptest.NewServer(b)
	defer srv.Close()
	p, _ := route53.New(ctx, route53.Config{AccessKeyID: "AKIAWRONG", SecretAccessKey: fakeSecret, Endpoint: srv.URL})
	if err := p.Test(ctx); err == nil || !strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), fakeSecret) {
		t.Fatalf("err = %v", err)
	}
	// missing pinned zone
	nf := newProvider(t, b, func(c *route53.Config) { c.HostedZoneID = "ZNOPE" })
	if err := nf.Test(ctx); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestContextTimeout(t *testing.T) {
	b := newBackend()
	b.slow = 500 * time.Millisecond
	p := newProvider(t, b, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Test(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestMultiValueSetAndWildcardEscaping(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.zone("ZEXAMPLE").sets[`foreign.example.test.|A`] = &set{name: `foreign.example.test.`, typ: "A", ttl: 60, vals: []string{"192.0.2.7", "192.0.2.8"}}
	p := newProvider(t, b, nil)
	recs, _ := p.ListRecords(ctx, "example.test")
	if len(recs) != 3 { // two A values + the apex NS
		t.Fatalf("recs = %+v", recs)
	}
	// deleting one value of a multi-value set keeps the other
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: "foreign.example.test", Type: "A", Value: "192.0.2.7"}); err != nil {
		t.Fatal(err)
	}
	recs, _ = p.ListRecords(ctx, "example.test")
	if len(recs) != 2 || recs[1].Value != "192.0.2.8" {
		t.Fatalf("recs = %+v", recs)
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "*.example.test", Type: "A", Value: "192.0.2.9"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.zone("ZEXAMPLE").sets[`\052.example.test.|A`]; !ok {
		var keys []string
		for k := range b.zone("ZEXAMPLE").sets {
			keys = append(keys, k)
		}
		t.Fatalf("wildcard not sent escaped: %v", keys)
	}
}

func TestRegistryCredentialValidation(t *testing.T) {
	if _, err := dns.New("route53", map[string]any{"access_key_id": "AKIAX"}, nil); err == nil {
		t.Fatal("half-configured credentials accepted")
	}
	p, err := dns.New("route53", map[string]any{}, nil) // default chain
	if err != nil || p.Type() != "route53" {
		t.Fatal(err)
	}
	if _, ok := dns.CapsFor("route53"); !ok {
		t.Fatal("not registered")
	}
	_ = secrets.Secret("")
}

func TestNoEndpointOverrideInSchema(t *testing.T) {
	sch, _ := dns.SchemaFor("route53")
	for _, f := range sch.Fields {
		if f.Name == "endpoint" || f.Name == "api_url" {
			t.Fatalf("user-configurable endpoint %q in schema", f.Name)
		}
	}
}

func TestPaginationCoversAllPages(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	for i := 0; i < 8; i++ {
		b.seed("ZEXAMPLE", fmt.Sprintf("h%d.example.test", i), "192.0.2.1")
	}
	p := newProvider(t, b, nil)
	recs, err := p.ListRecords(ctx, "example.test")
	if err != nil || len(recs) != 9 {
		t.Fatalf("recs=%d err=%v", len(recs), err)
	}
	if b.zonePages < 3 || b.setPages < 3 {
		t.Fatalf("pagination not exercised: zone pages %d, set pages %d", b.zonePages, b.setPages)
	}
}

func TestUpdateRefusesMultiValueAndAlias(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.seed("ZEXAMPLE", "m.example.test.", "192.0.2.1", "192.0.2.2")
	p := newProvider(t, b, nil)
	_, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.99"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "2 values") {
		t.Fatalf("err = %v", err)
	}
	if got := b.zone("ZEXAMPLE").sets["m.example.test.|A"].vals; len(got) != 2 {
		t.Fatalf("set changed: %v", got)
	}
	// deleting one value keeps the other (trailing-dot seed vs. undotted request)
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if got := b.zone("ZEXAMPLE").sets["m.example.test.|A"].vals; len(got) != 1 || got[0] != "192.0.2.2" {
		t.Fatalf("vals = %v", got)
	}
	// single value: update allowed
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.50"}); err != nil {
		t.Fatal(err)
	}
	// alias set refused
	b.zone("ZEXAMPLE").sets["al.example.test.|A"] = &set{name: "al.example.test.", typ: "A", alias: true}
	_, err = p.UpdateRecord(ctx, "example.test", dns.Record{Name: "al.example.test", Type: "A", Value: "192.0.2.3"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("err = %v", err)
	}
}

func TestTXTNotSupportedAndBrokenPagination(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	p := newProvider(t, b, nil)
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "t.example.test", Type: "TXT", Value: "v"}); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err = %v", err)
	}
	for i := 0; i < 5; i++ {
		b.seed("ZEXAMPLE", fmt.Sprintf("x%d.example.test", i), "192.0.2.1")
	}
	b.brokenTrunc = true
	if _, err := p.ListRecords(ctx, "example.test"); err == nil || !strings.Contains(err.Error(), "next") {
		t.Fatalf("truncated page without marker accepted: %v", err)
	}
}

func TestMalformedResponsesFailClosed(t *testing.T) {
	ctx := context.Background()
	rec := dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}
	ops := map[string]func(p *route53.Provider) error{
		"list":   func(p *route53.Provider) error { _, err := p.ListRecords(ctx, "example.test"); return err },
		"test":   func(p *route53.Provider) error { return p.Test(ctx) },
		"create": func(p *route53.Provider) error { _, err := p.CreateRecord(ctx, "example.test", rec); return err },
		"update": func(p *route53.Provider) error { _, err := p.UpdateRecord(ctx, "example.test", rec); return err },
		"delete": func(p *route53.Provider) error { return p.DeleteRecord(ctx, "example.test", rec) },
	}
	for _, mode := range []string{"empty", "json", "emptyxml", "html", "trunc"} {
		// every request is malformed (hosted zones included)
		for name, op := range ops {
			b := newBackend()
			b.badAll = mode
			if err := op(newProvider(t, b, nil)); err == nil {
				t.Errorf("badAll=%s %s: malformed 200 accepted", mode, name)
			}
		}
		// zones are fine, record-set reads are malformed
		for name, op := range ops {
			if name == "test" {
				continue
			}
			b := newBackend()
			b.seed("ZEXAMPLE", "a.example.test", "192.0.2.1")
			b.badSets = mode
			if err := op(newProvider(t, b, nil)); err == nil {
				t.Errorf("badSets=%s %s: malformed 200 accepted", mode, name)
			}
		}
		// a malformed answer to the change itself
		for _, name := range []string{"create", "update", "delete"} {
			b := newBackend()
			b.seed("ZEXAMPLE", "a.example.test", "192.0.2.9")
			if name == "create" {
				delete(b.zone("ZEXAMPLE").sets, "a.example.test.|A")
			}
			b.badPost = mode
			if err := ops[name](newProvider(t, b, nil)); err == nil && name != "delete" {
				t.Errorf("badPost=%s %s: accepted", mode, name)
			}
		}
	}
}

func TestDeleteWithMalformedChangeStillDetected(t *testing.T) {
	// delete of the exact value with a malformed change answer must error
	b := newBackend()
	b.seed("ZEXAMPLE", "a.example.test", "192.0.2.1")
	b.badPost = "json"
	err := newProvider(t, b, nil).DeleteRecord(context.Background(), "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"})
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("err = %v", err)
	}
}

func TestAcceptedButInvisibleChangesAreUnconfirmedNotSuccess(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.dropChange = true
	p := newProvider(t, b, nil)
	rec := dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}
	got, err := p.CreateRecord(ctx, "example.test", rec)
	if !errors.Is(err, dns.ErrUnconfirmed) || got.Name != rec.Name || got.Value != rec.Value || got.Type != "A" {
		t.Fatalf("create: want the written record with ErrUnconfirmed, got %+v / %v", got, err)
	}
	b.dropChange = false
	b.seed("ZEXAMPLE", "d.example.test", "192.0.2.5")
	b.dropChange = true
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: "d.example.test", Type: "A", Value: "192.0.2.5"}); !errors.Is(err, dns.ErrUnconfirmed) {
		t.Fatalf("delete: err = %v", err)
	}
	got, err = p.UpdateRecord(ctx, "example.test", dns.Record{Name: "d.example.test", Type: "A", Value: "192.0.2.6"})
	if !errors.Is(err, dns.ErrUnconfirmed) || got.Value != "192.0.2.6" {
		t.Fatalf("update: got %+v err %v", got, err)
	}
}

func TestListingWithoutApexSOAandNSIsIncomplete(t *testing.T) {
	b := newBackend()
	delete(b.zone("ZEXAMPLE").sets, "example.test.|SOA")
	if _, err := newProvider(t, b, nil).ListRecords(context.Background(), "example.test"); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err = %v", err)
	}
	b = newBackend()
	delete(b.zone("ZEXAMPLE").sets, "example.test.|NS")
	if _, err := newProvider(t, b, nil).ListRecords(context.Background(), "example.test"); err == nil {
		t.Fatal("missing NS accepted")
	}
}

func TestUpdateIsCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.seed("ZEXAMPLE", "c.example.test", "192.0.2.1")
	p := newProvider(t, b, nil)
	// a competing writer changes the set between our read and our batch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			b.mu.Lock()
			b.zone("ZEXAMPLE").sets["c.example.test.|A"].vals = []string{"192.0.2.77"}
			b.mu.Unlock()
		}
		b.ServeHTTP(w, r)
	}))
	defer srv.Close()
	cas, err := route53.New(ctx, route53.Config{AccessKeyID: fakeKeyID, SecretAccessKey: fakeSecret, Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_ = p
	if _, err := cas.UpdateRecord(ctx, "example.test", dns.Record{Name: "c.example.test", Type: "A", Value: "192.0.2.2"}); err == nil {
		t.Fatal("update overwrote a concurrent change")
	}
	if got := b.zone("ZEXAMPLE").sets["c.example.test.|A"].vals; len(got) != 1 || got[0] != "192.0.2.77" {
		t.Fatalf("concurrent change lost: %v", got)
	}
}

func TestTestResolvesAZone(t *testing.T) {
	b := newBackend()
	if err := newProvider(t, b, nil).Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.badAll = "json"
	if err := newProvider(t, b, nil).Test(context.Background()); err == nil {
		t.Fatal("malformed Test accepted")
	}
}

func TestCNAMEBlocksARecord(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.zone("ZEXAMPLE").sets["c.example.test.|CNAME"] = &set{name: "c.example.test.", typ: "CNAME", ttl: 60, vals: []string{"t.example.test."}}
	b.seed("ZEXAMPLE", "a.example.test", "192.0.2.1")
	p := newProvider(t, b, nil)
	n := len(b.zone("ZEXAMPLE").sets)
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "c.example.test", Type: "A", Value: "192.0.2.2"}); !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "CNAME") {
		t.Fatalf("err = %v", err)
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "CNAME", Value: "x.example.test"}); !errors.Is(err, dns.ErrRecordExists) {
		t.Fatalf("err = %v", err)
	}
	if len(b.zone("ZEXAMPLE").sets) != n {
		t.Fatal("conflicting set created")
	}
}

func TestPinnedProviderRefusesOtherZones(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	p := newProvider(t, b, func(c *route53.Config) { c.HostedZoneID = "ZEXAMPLE" })
	before := len(b.zone("ZEXAMPLE").sets)
	rec := dns.Record{Name: "y.other.test", Type: "A", Value: "192.0.2.1"}
	checks := map[string]error{}
	_, checks["list"] = p.ListRecords(ctx, "other.test")
	_, checks["create"] = p.CreateRecord(ctx, "other.test", rec)
	_, checks["update"] = p.UpdateRecord(ctx, "other.test", rec)
	checks["delete"] = p.DeleteRecord(ctx, "other.test", rec)
	for op, err := range checks {
		if err == nil || !strings.Contains(err.Error(), "not served by the pinned hosted zone") {
			t.Errorf("%s with a foreign zone: err = %v", op, err)
		}
	}
	if len(b.zone("ZEXAMPLE").sets) != before {
		t.Fatal("a record for another zone was written into the pinned zone")
	}
	// the pinned zone itself and its sub-domains still work
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ListRecords(ctx, "lab.example.test"); err != nil {
		t.Fatalf("sub-zone of the pinned zone: %v", err)
	}
	if err := p.Test(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEventualConsistencyIsPolledAndUnconfirmedNamesRecord(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.lag = 3 // the first reads after a change still show the old state
	p := newProvider(t, b, nil)
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "lag.example.test", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatalf("lagging reads must be polled: %v", err)
	}
	b.lag = 1000
	got, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "never.example.test", Type: "A", Value: "192.0.2.2"})
	if !errors.Is(err, dns.ErrUnconfirmed) || got.Name != "never.example.test" || !strings.Contains(err.Error(), "never.example.test") {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestConflictingValueIsAnOrdinaryError(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	// another writer replaces the set right after our change was applied
	b.afterChange = func(z *zone) {
		z.sets["w.example.test.|A"] = &set{name: "w.example.test.", typ: "A", ttl: 60, vals: []string{"192.0.2.99"}}
	}
	p := newProvider(t, b, nil)
	got, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "w.example.test", Type: "A", Value: "192.0.2.1"})
	if err == nil || errors.Is(err, dns.ErrUnconfirmed) || got.Name != "" {
		t.Fatalf("a conflicting value must be a normal error: got %+v err %v", got, err)
	}
}

func TestContextExpiryAfterAcceptedChangeIsUnconfirmed(t *testing.T) {
	b := newBackend()
	b.lag = 1000
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(b)
	defer srv.Close()
	clk := newClock()
	clk.onSleep = cancel // the caller's deadline hits while we poll
	p, err := route53.New(context.Background(), route53.Config{AccessKeyID: fakeKeyID, SecretAccessKey: fakeSecret, Endpoint: srv.URL,
		VerifyTimeout: 20 * time.Second, VerifyInterval: time.Second, Now: clk.now, Sleep: clk.sleep})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "c.example.test", Type: "A", Value: "192.0.2.1"})
	if !errors.Is(err, dns.ErrUnconfirmed) || got.Name != "c.example.test" {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestVerifyWindowEndsBeforeTheCallersDeadline(t *testing.T) {
	b := newBackend()
	b.lag = 1000
	srv := httptest.NewServer(b)
	defer srv.Close()
	clk := newClock()
	p, err := route53.New(context.Background(), route53.Config{AccessKeyID: fakeKeyID, SecretAccessKey: fakeSecret, Endpoint: srv.URL,
		VerifyTimeout: 20 * time.Second, VerifyInterval: time.Second, Now: clk.now, Sleep: clk.sleep})
	if err != nil {
		t.Fatal(err)
	}
	// a 30s per-call deadline (the executor's), nearly all of it still ahead
	ctx, cancel := context.WithDeadline(context.Background(), clk.now().Add(30*time.Second))
	defer cancel()
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "d.example.test", Type: "A", Value: "192.0.2.1"}); !errors.Is(err, dns.ErrUnconfirmed) {
		t.Fatalf("err = %v", err)
	}
	if clk.slept > 20*time.Second || clk.slept < 15*time.Second {
		t.Fatalf("polled for %s, want about the 20s verify timeout", clk.slept)
	}
	// with only 5s left the window shrinks to ~3s, leaving 2s for the caller
	clk2 := newClock()
	p2, _ := route53.New(context.Background(), route53.Config{AccessKeyID: fakeKeyID, SecretAccessKey: fakeSecret, Endpoint: srv.URL,
		VerifyTimeout: 20 * time.Second, VerifyInterval: time.Second, Now: clk2.now, Sleep: clk2.sleep})
	ctx2, cancel2 := context.WithDeadline(context.Background(), clk2.now().Add(5*time.Second))
	defer cancel2()
	if _, err := p2.CreateRecord(ctx2, "example.test", dns.Record{Name: "e.example.test", Type: "A", Value: "192.0.2.1"}); !errors.Is(err, dns.ErrUnconfirmed) {
		t.Fatalf("err = %v", err)
	}
	if clk2.slept > 3*time.Second {
		t.Fatalf("polled %s past the deadline-minus-2s cap", clk2.slept)
	}
}

func TestZoneNameIsNormalised(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, func(c *route53.Config) { c.HostedZoneID = "ZEXAMPLE" })
	for _, z := range []string{"Example.Test.", "EXAMPLE.test", "Lab.Example.Test."} {
		if _, err := p.ListRecords(context.Background(), z); err != nil {
			t.Errorf("%q: %v", z, err)
		}
	}
	if _, err := p.CreateRecord(context.Background(), "Example.Test.", dns.Record{Name: "n.example.test", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
}

func TestCNAMEConflictCoversEveryType(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.zone("ZEXAMPLE").sets["t.example.test.|TXT"] = &set{name: "t.example.test.", typ: "TXT", ttl: 60, vals: []string{`"hello"`}}
	b.zone("ZEXAMPLE").sets["m.example.test.|MX"] = &set{name: "m.example.test.", typ: "MX", ttl: 60, vals: []string{"10 mail.example.test."}}
	p := newProvider(t, b, nil)
	for _, n := range []string{"t.example.test", "m.example.test"} {
		if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: n, Type: "CNAME", Value: "x.example.test"}); !errors.Is(err, dns.ErrRecordExists) {
			t.Errorf("%s: CNAME over a non-address set: %v", n, err)
		}
	}
}

// lagHandler serves the same backend but hides every change from rrset reads
// of the single-set kind (MaxItems=1) the verification uses, which is what a
// lagging read looks like. Changes are applied to the backend.
type lagHandler struct{ inner *backend }

func (h *lagHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrset") && r.URL.Query().Get("maxitems") == "1" {
		h.inner.mu.Lock()
		name := strings.ToLower(r.URL.Query().Get("name"))
		h.inner.mu.Unlock()
		if strings.Contains(name, "unconf") { // changes to this name are never visible
			fmt.Fprintf(w, `<ListResourceRecordSetsResponse %s><ResourceRecordSets></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>`, ns)
			return
		}
	}
	h.inner.ServeHTTP(w, r)
}

func TestAmbiguousChangeCallIsUnconfirmedDefinitiveIsPlain(t *testing.T) {
	rec := dns.Record{Name: "amb.example.test", Type: "A", Value: "192.0.2.1"}
	cases := map[string]struct {
		mod         func(*backend)
		unconfirmed bool
		applied     bool
	}{
		"response dropped after the change was applied": {func(b *backend) { b.dropAfterApply = true }, true, true},
		"client times out before the change is applied": {func(b *backend) { b.stallChange = true }, true, false},
		"unparseable answer to the change":              {func(b *backend) { b.badPost = "html" }, true, false},
		"definitive InvalidChangeBatch rejection":       {func(b *backend) { b.rejectChange = true }, false, false},
	}
	for name, tc := range cases {
		// create
		b := newBackend()
		tc.mod(b)
		p := newProvider(t, b, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		got, err := p.CreateRecord(ctx, "example.test", rec)
		cancel()
		if tc.unconfirmed {
			if !errors.Is(err, dns.ErrUnconfirmed) || got.Name != rec.Name || got.Value != rec.Value {
				t.Errorf("%s: create got %+v err %v", name, got, err)
			}
		} else if err == nil || errors.Is(err, dns.ErrUnconfirmed) || got.Name != "" {
			t.Errorf("%s: create must be a plain error with no record, got %+v err %v", name, got, err)
		}
		b.mu.Lock()
		_, ok := b.zone("ZEXAMPLE").sets["amb.example.test.|A"]
		b.mu.Unlock()
		if ok != tc.applied && name != "unparseable answer to the change" {
			t.Errorf("%s: applied = %v, want %v", name, ok, tc.applied)
		}
		// update
		b = newBackend()
		b.seed("ZEXAMPLE", "amb.example.test", "192.0.2.9")
		tc.mod(b)
		p = newProvider(t, b, nil)
		ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
		got, err = p.UpdateRecord(ctx, "example.test", rec)
		cancel()
		if tc.unconfirmed != errors.Is(err, dns.ErrUnconfirmed) || (tc.unconfirmed && got.Value != rec.Value) || (!tc.unconfirmed && got.Name != "") {
			t.Errorf("%s: update got %+v err %v", name, got, err)
		}
		// delete
		b = newBackend()
		b.seed("ZEXAMPLE", "amb.example.test", "192.0.2.1")
		tc.mod(b)
		p = newProvider(t, b, nil)
		ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
		err = p.DeleteRecord(ctx, "example.test", rec)
		cancel()
		if err == nil || tc.unconfirmed != errors.Is(err, dns.ErrUnconfirmed) {
			t.Errorf("%s: delete err %v", name, err)
		}
	}
}

func TestErrorsBeforeTheRequestIsSentArePlain(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, func(c *route53.Config) { c.HostedZoneID = "ZEXAMPLE" })
	got, err := p.CreateRecord(context.Background(), "other.test", dns.Record{Name: "x.other.test", Type: "A", Value: "192.0.2.1"})
	if err == nil || errors.Is(err, dns.ErrUnconfirmed) || got.Name != "" {
		t.Fatalf("zone mismatch: got %+v err %v", got, err)
	}
	if _, err := p.CreateRecord(context.Background(), "example.test", dns.Record{Name: "x.example.test", Type: "MX", Value: "v"}); err == nil || errors.Is(err, dns.ErrUnconfirmed) {
		t.Fatalf("validation: %v", err)
	}
}

// newProductionProvider uses the SDK's PRODUCTION retry configuration (the
// standard retryer: 3 attempts, retrying resets, EOF, timeouts and 5xx); only
// the endpoint points at the fake.
func newProductionProvider(t *testing.T, b http.Handler) *route53.Provider {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	clk := newClock()
	p, err := route53.New(context.Background(), route53.Config{AccessKeyID: fakeKeyID, SecretAccessKey: fakeSecret, Endpoint: srv.URL,
		VerifyTimeout: 10 * time.Second, VerifyInterval: time.Second, Now: clk.now, Sleep: clk.sleep})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestChangeIsNeverRetriedUnderProductionRetries: with the SDK's standard
// retryer, a change that was applied but whose response was lost would be sent
// again and refused (InvalidChangeBatch "already exists" / "values do not
// match"), turning an applied write into a plain error and an unowned record.
// The change call must be sent exactly once and end ambiguous.
func TestChangeIsNeverRetriedUnderProductionRetries(t *testing.T) {
	rec := dns.Record{Name: "prod.example.test", Type: "A", Value: "192.0.2.1"}
	ctx := context.Background()
	check := func(op string, b *backend, got dns.Record, err error, wantRec bool) {
		t.Helper()
		b.mu.Lock()
		posts := b.posts
		b.mu.Unlock()
		if posts != 1 {
			t.Errorf("%s: %d change requests, want exactly 1", op, posts)
		}
		if !errors.Is(err, dns.ErrUnconfirmed) || (wantRec && (got.Name != rec.Name || got.Value != rec.Value)) {
			t.Errorf("%s: want ErrUnconfirmed with the record, got %+v err %v", op, got, err)
		}
	}
	b := newBackend()
	b.dropAfterApply = true
	got, err := newProductionProvider(t, b).CreateRecord(ctx, "example.test", rec)
	check("create", b, got, err, true)

	b = newBackend()
	b.seed("ZEXAMPLE", rec.Name, "192.0.2.9")
	b.dropAfterApply = true
	got, err = newProductionProvider(t, b).UpdateRecord(ctx, "example.test", rec)
	check("update", b, got, err, true)

	b = newBackend()
	b.seed("ZEXAMPLE", rec.Name, rec.Value)
	b.dropAfterApply = true
	err = newProductionProvider(t, b).DeleteRecord(ctx, "example.test", rec)
	check("delete", b, dns.Record{}, err, false)
}

// TestChangeStatusClassification: an AWS 5xx answer (InternalFailure,
// ServiceUnavailable, an HTML gateway page) to the change leaves the outcome
// unknown; a 4xx API error (Throttling, InvalidChangeBatch) is a refusal.
func TestChangeStatusClassification(t *testing.T) {
	rec := dns.Record{Name: "st.example.test", Type: "A", Value: "192.0.2.1"}
	ctx := context.Background()
	for _, tc := range []struct {
		status    int
		body      string
		ambiguous bool
	}{
		{400, "", false},
		{500, "", true},
		{502, "<html><body><h1>502 Bad Gateway</h1></body></html>", true},
		{503, "", true},
		{504, "<html><body><h1>504 Gateway Time-out</h1></body></html>", true},
	} {
		for _, op := range []string{"create", "update", "delete"} {
			b := newBackend()
			if op != "create" {
				b.seed("ZEXAMPLE", rec.Name, "192.0.2.9")
			}
			b.changeStatus, b.changeBody = tc.status, tc.body
			p := newProductionProvider(t, b)
			var got dns.Record
			var err error
			want := rec
			switch op {
			case "create":
				got, err = p.CreateRecord(ctx, "example.test", rec)
			case "update":
				got, err = p.UpdateRecord(ctx, "example.test", rec)
			case "delete":
				want.Value = "192.0.2.9"
				err = p.DeleteRecord(ctx, "example.test", want)
			}
			b.mu.Lock()
			posts := b.posts
			b.mu.Unlock()
			if posts != 1 {
				t.Errorf("status %d %s: %d change requests, want 1", tc.status, op, posts)
			}
			if err == nil || errors.Is(err, dns.ErrUnconfirmed) != tc.ambiguous {
				t.Errorf("status %d %s: ambiguous=%v, got err %v", tc.status, op, tc.ambiguous, err)
			}
			if op != "delete" && tc.ambiguous && (got.Name != rec.Name || got.Value != rec.Value) {
				t.Errorf("status %d %s: ErrUnconfirmed must come with the record, got %+v", tc.status, op, got)
			}
			if op != "delete" && !tc.ambiguous && got != (dns.Record{}) {
				t.Errorf("status %d %s: a refusal must return an empty Record, got %+v", tc.status, op, got)
			}
		}
	}
}

// TestRefusedChangeWhoseResultIsAlreadyInPlaceIsUnconfirmed: InvalidChangeBatch
// ("already exists" / "values do not match") while the set already holds the
// requested state means someone (an earlier attempt of ours, or another
// writer) made it; we cannot prove who, so the conservative answer is the
// record with ErrUnconfirmed rather than a plain error that could leave our own
// write unowned. A refusal with the set in any other state stays plain.
func TestRefusedChangeWhoseResultIsAlreadyInPlaceIsUnconfirmed(t *testing.T) {
	rec := dns.Record{Name: "rej.example.test", Type: "A", Value: "192.0.2.1"}
	ctx := context.Background()
	b := newBackend()
	b.applyThenReject = true
	got, err := newProvider(t, b, nil).CreateRecord(ctx, "example.test", rec)
	if !errors.Is(err, dns.ErrUnconfirmed) || got.Name != rec.Name || got.Value != rec.Value {
		t.Errorf("create: got %+v err %v", got, err)
	}
	b = newBackend()
	b.seed("ZEXAMPLE", rec.Name, "192.0.2.9")
	b.applyThenReject = true
	got, err = newProvider(t, b, nil).UpdateRecord(ctx, "example.test", rec)
	if !errors.Is(err, dns.ErrUnconfirmed) || got.Value != rec.Value {
		t.Errorf("update: got %+v err %v", got, err)
	}
	b = newBackend()
	b.seed("ZEXAMPLE", rec.Name, rec.Value)
	b.applyThenReject = true
	if err := newProvider(t, b, nil).DeleteRecord(ctx, "example.test", rec); !errors.Is(err, dns.ErrUnconfirmed) {
		t.Errorf("delete: %v", err)
	}
	// refused and the set is NOT in the requested state: plain
	b = newBackend()
	b.rejectChange = true
	got, err = newProvider(t, b, nil).CreateRecord(ctx, "example.test", rec)
	if err == nil || errors.Is(err, dns.ErrUnconfirmed) || got.Name != "" {
		t.Errorf("plain refusal: got %+v err %v", got, err)
	}
	// refused while ANOTHER value is in place: plain (another writer)
	b = newBackend()
	b.afterChange = func(z *zone) { z.sets["rej.example.test.|A"].vals = []string{"192.0.2.77"} }
	b.applyThenReject = true
	got, err = newProvider(t, b, nil).CreateRecord(ctx, "example.test", rec)
	if err == nil || errors.Is(err, dns.ErrUnconfirmed) || got.Name != "" {
		t.Errorf("refused with another value in place: got %+v err %v", got, err)
	}
}

// TestAmbiguousChangeErrorCarriesOnlyScrubbedText: the unconfirmed error keeps
// the SDK error only as scrubbed text, never as a wrapped value a caller could
// unwrap and print unscrubbed.
func TestAmbiguousChangeErrorCarriesOnlyScrubbedText(t *testing.T) {
	b := newBackend()
	b.changeStatus, b.changeBody = 502, "<html>bad gateway "+fakeSecret+"</html>"
	_, err := newProductionProvider(t, b).CreateRecord(context.Background(), "example.test", dns.Record{Name: "s.example.test", Type: "A", Value: "192.0.2.1"})
	if !errors.Is(err, dns.ErrUnconfirmed) || strings.Contains(err.Error(), fakeSecret) {
		t.Fatalf("err = %v", err)
	}
	var oe *smithy.OperationError
	if errors.As(err, &oe) {
		t.Fatalf("the raw SDK error is reachable: %v", oe)
	}
}
