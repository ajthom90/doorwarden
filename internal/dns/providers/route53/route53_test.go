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
}

type backend struct {
	mu       sync.Mutex
	zones    []*zone
	failCode string // when set, every call fails with this error code
	slow     time.Duration
	listed   []string // hosted zone ids whose rrsets were listed
}

func newBackend() *backend {
	return &backend{zones: []*zone{
		{id: "ZTEST", name: "test.", sets: map[string]*set{}},
		{id: "ZEXAMPLE", name: "example.test.", sets: map[string]*set{}},
		{id: "ZPRIV", name: "example.test.", private: true, sets: map[string]*set{}},
		{id: "ZOTHER", name: "other.test.", sets: map[string]*set{}},
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
	if !strings.Contains(r.Header.Get("Authorization"), "Credential="+fakeKeyID+"/") {
		xmlErr(w, 403, "InvalidClientTokenId", "The security token included in the request is invalid.")
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	path := strings.TrimPrefix(r.URL.Path, "/2013-04-01")
	switch {
	case path == "/hostedzone" && r.Method == "GET":
		fmt.Fprintf(w, `<ListHostedZonesResponse %s><HostedZones>`, ns)
		for _, z := range b.zones {
			fmt.Fprintf(w, `<HostedZone><Id>/hostedzone/%s</Id><Name>%s</Name><CallerReference>c</CallerReference><Config><PrivateZone>%v</PrivateZone></Config><ResourceRecordSetCount>0</ResourceRecordSetCount></HostedZone>`, z.id, z.name, z.private)
		}
		fmt.Fprintf(w, `</HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListHostedZonesResponse>`)
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
		sn, st := q.Get("name"), q.Get("type")
		start := 0
		for start < len(all) && (all[start].name < sn || (all[start].name == sn && all[start].typ < st)) {
			start++
		}
		per := 3 // force pagination
		if m := q.Get("maxitems"); m == "1" {
			per = 1
		}
		end := start + per
		if end > len(all) {
			end = len(all)
		}
		fmt.Fprintf(w, `<ListResourceRecordSetsResponse %s><ResourceRecordSets>`, ns)
		for _, s := range all[start:end] {
			fmt.Fprintf(w, `<ResourceRecordSet><Name>%s</Name><Type>%s</Type><TTL>%d</TTL><ResourceRecords>`, s.name, s.typ, s.ttl)
			for _, v := range s.vals {
				fmt.Fprintf(w, `<ResourceRecord><Value>%s</Value></ResourceRecord>`, v)
			}
			fmt.Fprint(w, `</ResourceRecords></ResourceRecordSet>`)
		}
		fmt.Fprint(w, `</ResourceRecordSets>`)
		if end < len(all) {
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
		for _, c := range cb.Changes {
			key := c.Set.Name + "|" + c.Set.Type
			var vals []string
			for _, rr := range c.Set.Records {
				vals = append(vals, rr.Value)
			}
			switch c.Action {
			case "CREATE":
				if _, ok := z.sets[key]; ok {
					xmlErr(w, 400, "InvalidChangeBatch", "Tried to create resource record set but it already exists")
					return
				}
				z.sets[key] = &set{c.Set.Name, c.Set.Type, c.Set.TTL, vals}
			case "UPSERT":
				z.sets[key] = &set{c.Set.Name, c.Set.Type, c.Set.TTL, vals}
			case "DELETE":
				if _, ok := z.sets[key]; !ok {
					xmlErr(w, 400, "InvalidChangeBatch", "not found")
					return
				}
				delete(z.sets, key)
			}
		}
		fmt.Fprintf(w, `<ChangeResourceRecordSetsResponse %s><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status><SubmittedAt>2024-01-01T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>`, ns)
	default:
		xmlErr(w, 404, "NoSuchHostedZone", "bad route")
	}
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
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test"})
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
	if len(b.zone("ZEXAMPLE").sets) != 1 || len(b.zone("ZTEST").sets) != 0 || len(b.zone("ZPRIV").sets) != 0 {
		t.Fatalf("record landed in wrong zone: example=%d test=%d priv=%d", len(b.zone("ZEXAMPLE").sets), len(b.zone("ZTEST").sets), len(b.zone("ZPRIV").sets))
	}
	// a sub-zone with no own hosted zone falls back to the parent
	if _, err := p.CreateRecord(ctx, "lab.example.test", dns.Record{Name: "x.lab.example.test", Type: "A", Value: "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	if len(b.zone("ZEXAMPLE").sets) != 2 {
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
	b.zones = []*zone{{id: "ZPRIV", name: "internal.test.", private: true, sets: map[string]*set{}}}
	p := newProvider(t, b, nil)
	if _, err := p.ListRecords(ctx, "internal.test"); err == nil || !strings.Contains(err.Error(), "hosted_zone_id") {
		t.Fatalf("private zone chosen implicitly: %v", err)
	}
	pinned := newProvider(t, b, func(c *route53.Config) { c.HostedZoneID = "/hostedzone/ZPRIV" })
	if _, err := pinned.CreateRecord(ctx, "internal.test", dns.Record{Name: "a.internal.test", Type: "A", Value: "192.0.2.5"}); err != nil {
		t.Fatal(err)
	}
	if len(b.zone("ZPRIV").sets) != 1 {
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
	b.zone("ZEXAMPLE").sets[`foreign.example.test.|A`] = &set{`foreign.example.test.`, "A", 60, []string{"192.0.2.7", "192.0.2.8"}}
	p := newProvider(t, b, nil)
	recs, _ := p.ListRecords(ctx, "example.test")
	if len(recs) != 2 {
		t.Fatalf("recs = %+v", recs)
	}
	// deleting one value of a multi-value set keeps the other
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: "foreign.example.test", Type: "A", Value: "192.0.2.7"}); err != nil {
		t.Fatal(err)
	}
	recs, _ = p.ListRecords(ctx, "example.test")
	if len(recs) != 1 || recs[0].Value != "192.0.2.8" {
		t.Fatalf("recs = %+v", recs)
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "*.example.test", Type: "A", Value: "192.0.2.9"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.zone("ZEXAMPLE").sets[`\052.example.test|A`]; !ok {
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
