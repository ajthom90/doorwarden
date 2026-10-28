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
	mu                       sync.Mutex
	zones                    []*zone
	failCode                 string // when set, every call fails with this error code
	slow                     time.Duration
	listed                   []string // hosted zone ids whose rrsets were listed
	zonePages, setPages      int
	badAll, badSets, badPost string // serve a malformed HTTP 200 body for all / rrset / change requests
	dropChange               bool   // acknowledge changes without applying them
	brokenTrunc              bool   // truncated pages without a continuation marker
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
		if !b.dropChange {
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

func newProvider(t *testing.T, b *backend, mod func(*route53.Config)) *route53.Provider {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	cfg := route53.Config{AccessKeyID: fakeKeyID, SecretAccessKey: fakeSecret, Endpoint: srv.URL}
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

func TestSilentlyDroppedChangesDetected(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.dropChange = true
	p := newProvider(t, b, nil)
	_, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"})
	if err == nil || !strings.Contains(err.Error(), "refusing to report success") {
		t.Fatalf("create: err = %v", err)
	}
	b.dropChange = false
	b.seed("ZEXAMPLE", "d.example.test", "192.0.2.5")
	b.dropChange = true
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: "d.example.test", Type: "A", Value: "192.0.2.5"}); err == nil {
		t.Fatal("dropped delete reported success")
	}
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "d.example.test", Type: "A", Value: "192.0.2.6"}); err == nil {
		t.Fatal("dropped update reported success")
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
