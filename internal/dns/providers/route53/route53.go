// Package route53 is the AWS Route 53 DNS provider.
//
// It uses aws-sdk-go-v2 directly rather than libdns/route53 because the
// dns.Provider contract needs hosted-zone auto-discovery (longest matching
// suffix, public over private), per-value Create/Update/Delete semantics and
// an endpoint override for tests, none of which libdns exposes.
//
// Route 53 has no record IDs, so Record.ID is always empty: Update/Delete
// address records by (name, type[, value]). A non-empty ID on Update returns
// dns.ErrNotFound and on Delete is a no-op, since this provider never issues
// IDs. A record set holding several values is listed as one Record per value.
//
// Every response is validated: the SDK happily decodes an empty body, "{}" or
// an HTML page (a proxy or captive portal) into zero-valued output, so list
// calls require MaxItems, changes require ChangeInfo, a full zone listing must
// contain the apex SOA and NS sets, and every write is followed by a read of
// the single (name, type) set to confirm the post-state.
package route53

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	r53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Type is the registry name.
const Type = "route53"

// maxPages bounds list pagination so a misbehaving server cannot loop forever.
const maxPages = 1000

var staticCaps = dns.Capabilities{WildcardA: true, MultiZone: true, Update: true, TTL: true}

func init() {
	dns.Register(Type, func(cfg map[string]any, sr dns.SecretResolver) (dns.Provider, error) {
		c := Config{}
		_, hasKey := cfg["access_key_id"]
		_, hasSecret := cfg["secret_access_key"]
		empty := func(k string) bool { v, _ := cfg[k].(string); return v == "" }
		hasKey, hasSecret = hasKey && !empty("access_key_id"), hasSecret && !empty("secret_access_key")
		if hasKey != hasSecret {
			return nil, errors.New("route53: access_key_id and secret_access_key must both be set, or both empty to use the default AWS credential chain")
		}
		if hasKey {
			id, err := dns.ResolveField(cfg, sr, "access_key_id")
			if err != nil {
				return nil, fmt.Errorf("route53: %w", err)
			}
			sec, err := dns.ResolveField(cfg, sr, "secret_access_key")
			if err != nil {
				return nil, fmt.Errorf("route53: %w", err)
			}
			c.AccessKeyID, c.SecretAccessKey = id, sec
		}
		c.Region, _ = cfg["region"].(string)
		c.HostedZoneID, _ = cfg["hosted_zone_id"].(string)
		return New(context.Background(), c)
	}, dns.ConfigSchema{Fields: []dns.Field{
		{Name: "access_key_id", Secret: true, Help: "AWS access key ID; leave both key fields empty to use the default credential chain (env, shared config, IAM role)"},
		{Name: "secret_access_key", Secret: true, Help: "AWS secret access key"},
		{Name: "region", Help: "AWS region for signing (default us-east-1; Route 53 is global)"},
		{Name: "hosted_zone_id", Help: "pin a hosted zone ID (required to use a private zone; disables auto-discovery)"},
	}}, staticCaps)
}

// Config configures a Provider.
type Config struct {
	AccessKeyID     secrets.Secret
	SecretAccessKey secrets.Secret
	Region          string
	HostedZoneID    string // when set, used for every zone and may be private
	Endpoint        string // Go-level test seam; not reachable from user config (SSRF/credential exfiltration)

	// VerifyTimeout bounds how long a write waits for its change to become
	// visible to reads (default 20s, and never beyond the caller's context
	// deadline minus 2s); VerifyInterval is the poll step (default 1s). Route 53
	// does not promise that a read right after a change shows it.
	VerifyTimeout  time.Duration
	VerifyInterval time.Duration
	// Now and Sleep replace time.Now and a context-aware sleep (tests only).
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// Provider implements dns.Provider. It holds no secret-bearing value: the AWS
// client (which embeds the credentials provider) and the scrub list are only
// reachable through closures.
type Provider struct {
	client  func() *r53.Client
	scrubFn func(string) string
	pinned  string

	verifyTimeout, verifyEvery time.Duration
	now                        func() time.Time
	sleep                      func(ctx context.Context, d time.Duration) error

	mu    *sync.Mutex
	cache map[string]zoneRef // zone -> hosted zone
}

type zoneRef struct{ id, name string }

// New builds a provider. With empty static credentials the default AWS
// credential chain is used (resolved lazily by the SDK).
func New(ctx context.Context, c Config) (*Provider, error) {
	region := c.Region
	if region == "" {
		region = "us-east-1"
	}
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	var sec []secrets.Secret
	if c.AccessKeyID != "" || c.SecretAccessKey != "" {
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return nil, errors.New("route53: access key ID and secret access key must be set together")
		}
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKeyID.Reveal(), c.SecretAccessKey.Reveal(), "")))
		sec = []secrets.Secret{c.AccessKeyID, c.SecretAccessKey}
	}
	if c.Endpoint != "" {
		opts = append(opts, awsconfig.WithRetryMaxAttempts(1))
	}
	awscfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("route53: load AWS config: %w", err)
	}
	cl := r53.NewFromConfig(awscfg, func(o *r53.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
	})
	_, scrub := dns.Scrubber(sec...)
	vt, vi := c.VerifyTimeout, c.VerifyInterval
	if vt <= 0 {
		vt = 20 * time.Second
	}
	if vi <= 0 {
		vi = time.Second
	}
	now, sleep := c.Now, c.Sleep
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		}
	}
	return &Provider{client: func() *r53.Client { return cl }, scrubFn: scrub,
		pinned: strings.TrimPrefix(c.HostedZoneID, "/hostedzone/"), verifyTimeout: vt, verifyEvery: vi, now: now, sleep: sleep,
		mu: &sync.Mutex{}, cache: map[string]zoneRef{}}, nil
}

func (p *Provider) Type() string { return Type }

func (p *Provider) Capabilities() dns.Capabilities {
	c := staticCaps
	c.MultiZone = p.pinned == ""
	return c
}

func (p *Provider) scrub(s string) string { return p.scrubFn(s) }

// mapErr converts SDK errors into clear, secret-free errors.
func (p *Provider) mapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException", "ExpiredToken", "ExpiredTokenException", "InvalidSignatureException":
			return fmt.Errorf("route53: %s: authentication/authorization failed (%s); check the AWS credentials and IAM permissions (route53:ListHostedZones, ListResourceRecordSets, ChangeResourceRecordSets)", op, ae.ErrorCode())
		case "Throttling", "ThrottlingException", "PriorHybridRequestException", "RequestLimitExceeded", "PriorRequestNotComplete":
			return fmt.Errorf("route53: %s: rate limited by AWS (%s); retry later", op, ae.ErrorCode())
		case "NoSuchHostedZone":
			return fmt.Errorf("route53: %s: hosted zone not found", op)
		}
		return fmt.Errorf("route53: %s: %s: %s", op, ae.ErrorCode(), p.scrub(ae.ErrorMessage()))
	}
	return fmt.Errorf("route53: %s: %s", op, p.scrub(err.Error()))
}

func malformed(op, what string) error {
	return fmt.Errorf("route53: %s: malformed response (%s); a proxy or captive portal may be answering instead of AWS", op, what)
}

func (p *Provider) wrapCtx(ctx context.Context, op string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("route53: %s: %w", op, ctx.Err())
	}
	return p.mapErr(op, err)
}

type hostedZone struct {
	id      string
	name    string // lowercase, no trailing dot
	private bool
}

func normZoneName(n string) string { return strings.ToLower(strings.TrimSuffix(n, ".")) }

func (p *Provider) listZones(ctx context.Context) ([]hostedZone, error) {
	var out []hostedZone
	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("route53: list hosted zones: more than %d pages; refusing to continue", maxPages)
		}
		resp, err := p.client().ListHostedZones(ctx, &r53.ListHostedZonesInput{Marker: marker})
		if err != nil {
			return nil, p.wrapCtx(ctx, "list hosted zones", err)
		}
		if resp.MaxItems == nil {
			return nil, malformed("list hosted zones", "no MaxItems")
		}
		for _, z := range resp.HostedZones {
			priv := z.Config != nil && z.Config.PrivateZone
			out = append(out, hostedZone{
				id:      strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/"),
				name:    normZoneName(aws.ToString(z.Name)),
				private: priv,
			})
		}
		if !resp.IsTruncated {
			return out, nil
		}
		if resp.NextMarker == nil || (marker != nil && *marker == *resp.NextMarker) {
			return nil, errors.New("route53: list hosted zones: truncated response without a usable next marker")
		}
		marker = resp.NextMarker
	}
}

// pick chooses the hosted zone for zone: the longest hosted-zone name that
// equals zone or is a parent domain of it; a private zone is never chosen
// implicitly (set hosted_zone_id).
func pick(zone string, zones []hostedZone) (hostedZone, error) {
	var cands []hostedZone
	for _, z := range zones {
		if z.private {
			continue
		}
		if zone == z.name || strings.HasSuffix(zone, "."+z.name) {
			cands = append(cands, z)
		}
	}
	if len(cands) == 0 {
		for _, z := range zones {
			if z.private && (zone == z.name || strings.HasSuffix(zone, "."+z.name)) {
				return hostedZone{}, fmt.Errorf("route53: only a private hosted zone matches %q; set hosted_zone_id to use it", zone)
			}
		}
		return hostedZone{}, fmt.Errorf("route53: no hosted zone found for %q (check the credentials can list hosted zones)", zone)
	}
	sort.SliceStable(cands, func(i, j int) bool { return len(cands[i].name) > len(cands[j].name) })
	if len(cands) > 1 && len(cands[0].name) == len(cands[1].name) {
		return hostedZone{}, fmt.Errorf("route53: several public hosted zones named %q; set hosted_zone_id", cands[0].name)
	}
	return cands[0], nil
}

// getZone fetches a hosted zone by ID and validates the answer.
func (p *Provider) getZone(ctx context.Context, op, id string) (zoneRef, error) {
	resp, err := p.client().GetHostedZone(ctx, &r53.GetHostedZoneInput{Id: aws.String(id)})
	if err != nil {
		return zoneRef{}, p.wrapCtx(ctx, op, err)
	}
	if resp.HostedZone == nil || aws.ToString(resp.HostedZone.Id) == "" || aws.ToString(resp.HostedZone.Name) == "" {
		return zoneRef{}, malformed(op, "no hosted zone")
	}
	got := strings.TrimPrefix(aws.ToString(resp.HostedZone.Id), "/hostedzone/")
	if got != strings.TrimPrefix(id, "/hostedzone/") {
		return zoneRef{}, malformed(op, "hosted zone id mismatch")
	}
	return zoneRef{id: got, name: normZoneName(aws.ToString(resp.HostedZone.Name))}, nil
}

func (p *Provider) zoneFor(ctx context.Context, zone string) (zoneRef, error) {
	zone = normZoneName(zone)
	p.mu.Lock()
	ref, ok := p.cache[zone]
	p.mu.Unlock()
	if ok {
		return ref, nil
	}
	var err error
	if p.pinned != "" {
		ref, err = p.getZone(ctx, "look up hosted zone", p.pinned)
		if err == nil && !inZone(zone, ref.name) {
			// a pinned provider serves exactly one hosted zone; answering for any
			// other zone would list nothing, write into the wrong zone, or report
			// deletes that never happened
			return zoneRef{}, fmt.Errorf("route53: zone %q is not served by the pinned hosted zone %s (%s); hosted_zone_id binds this provider to that one zone", zone, ref.id, ref.name)
		}
	} else {
		var zs []hostedZone
		if zs, err = p.listZones(ctx); err == nil {
			var z hostedZone
			if z, err = pick(zone, zs); err == nil {
				ref = zoneRef{id: z.id, name: z.name}
			}
		}
	}
	if err != nil {
		return zoneRef{}, err
	}
	p.mu.Lock()
	p.cache[zone] = ref
	p.mu.Unlock()
	return ref, nil
}

// Test verifies the credentials and that a hosted zone really resolves: the
// pinned zone, or else the first listed zone, is fetched and validated.
func (p *Provider) Test(ctx context.Context) error {
	if p.pinned != "" {
		_, err := p.getZone(ctx, "verify credentials", p.pinned)
		return err
	}
	resp, err := p.client().ListHostedZones(ctx, &r53.ListHostedZonesInput{MaxItems: aws.Int32(1)})
	if err != nil {
		return p.wrapCtx(ctx, "verify credentials", err)
	}
	if resp.MaxItems == nil {
		return malformed("verify credentials", "no MaxItems")
	}
	if len(resp.HostedZones) > 0 {
		id := strings.TrimPrefix(aws.ToString(resp.HostedZones[0].Id), "/hostedzone/")
		if id == "" {
			return malformed("verify credentials", "hosted zone without id")
		}
		if _, err := p.getZone(ctx, "verify credentials", id); err != nil {
			return err
		}
	}
	return nil
}

func escName(n string) string { return strings.ReplaceAll(strings.ToLower(n), "*", `\052`) }

func unescName(n string) string {
	n = strings.ReplaceAll(n, `\052`, "*")
	return strings.ToLower(strings.TrimSuffix(n, "."))
}

func (p *Provider) allSets(ctx context.Context, zid string) ([]types.ResourceRecordSet, error) {
	var out []types.ResourceRecordSet
	in := &r53.ListResourceRecordSetsInput{HostedZoneId: aws.String(zid)}
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("route53: list records: more than %d pages; refusing to continue", maxPages)
		}
		resp, err := p.client().ListResourceRecordSets(ctx, in)
		if err != nil {
			return nil, p.wrapCtx(ctx, "list records", err)
		}
		if resp.MaxItems == nil {
			return nil, malformed("list records", "no MaxItems")
		}
		out = append(out, resp.ResourceRecordSets...)
		if !resp.IsTruncated {
			return out, nil
		}
		if resp.NextRecordName == nil || resp.NextRecordType == "" {
			return nil, errors.New("route53: list records: truncated response without a next record marker")
		}
		in.StartRecordName, in.StartRecordType, in.StartRecordIdentifier = resp.NextRecordName, resp.NextRecordType, resp.NextRecordIdentifier
	}
}

func inZone(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }

func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	zone = normZoneName(zone)
	ref, err := p.zoneFor(ctx, zone)
	if err != nil {
		return nil, err
	}
	sets, err := p.allSets(ctx, ref.id)
	if err != nil {
		return nil, err
	}
	// a real hosted zone always has apex SOA and NS sets; their absence means
	// the listing is not the zone's
	var soa, ns bool
	for _, s := range sets {
		if unescName(aws.ToString(s.Name)) == ref.name {
			soa = soa || s.Type == types.RRTypeSoa
			ns = ns || s.Type == types.RRTypeNs
		}
	}
	if !soa || !ns {
		return nil, fmt.Errorf("route53: list records: listing incomplete (apex SOA/NS sets of %q missing)", ref.name)
	}
	var out []dns.Record
	for _, s := range sets {
		name := unescName(aws.ToString(s.Name))
		if !inZone(name, zone) || s.AliasTarget != nil || s.Type == types.RRTypeSoa {
			continue
		}
		for _, rr := range s.ResourceRecords {
			out = append(out, dns.Record{Name: name, Type: string(s.Type), Value: aws.ToString(rr.Value), TTL: int(aws.ToInt64(s.TTL))})
		}
	}
	return out, nil
}

// getSet fetches the plain (non-routing-policy) record set for (name, type).
func (p *Provider) getSet(ctx context.Context, zid, name, typ string) (*types.ResourceRecordSet, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	resp, err := p.client().ListResourceRecordSets(ctx, &r53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zid), StartRecordName: aws.String(escName(name)),
		StartRecordType: types.RRType(typ), MaxItems: aws.Int32(1),
	})
	if err != nil {
		return nil, p.wrapCtx(ctx, "get record", err)
	}
	if resp.MaxItems == nil {
		return nil, malformed("get record", "no MaxItems")
	}
	for i := range resp.ResourceRecordSets {
		s := resp.ResourceRecordSets[i]
		if unescName(aws.ToString(s.Name)) == name && string(s.Type) == typ && s.SetIdentifier == nil {
			return &s, nil
		}
	}
	return nil, nil
}

// change submits one atomic change batch.
func (p *Provider) change(ctx context.Context, zid, op string, changes ...types.Change) error {
	resp, err := p.client().ChangeResourceRecordSets(ctx, &r53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zid),
		ChangeBatch:  &types.ChangeBatch{Changes: changes},
	})
	if err != nil {
		var ae smithy.APIError
		if ctx.Err() == nil && errors.As(err, &ae) {
			return p.mapErr(op, err) // the service answered with an API error: definitively refused
		}
		// cancellation, deadline, transport failure, unparseable answer: the
		// service may have applied the change
		cause := err
		if ctx.Err() != nil {
			cause = ctx.Err()
		}
		return fmt.Errorf("route53: %s: the request may have been applied but the outcome is unknown (%s): %w: %w", op, p.scrub(cause.Error()), dns.ErrUnconfirmed, cause)
	}
	if resp.ChangeInfo == nil || aws.ToString(resp.ChangeInfo.Id) == "" {
		return fmt.Errorf("%w: %w", malformed(op, "no ChangeInfo"), dns.ErrUnconfirmed)
	}
	return nil
}

func valuesOf(s *types.ResourceRecordSet) []string {
	if s == nil {
		return nil
	}
	var v []string
	for _, rr := range s.ResourceRecords {
		v = append(v, aws.ToString(rr.Value))
	}
	sort.Strings(v)
	return v
}

func sameValues(s *types.ResourceRecordSet, want ...string) bool {
	sort.Strings(want)
	got := valuesOf(s)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// verify re-reads the single (name, type) set until it shows the requested
// state want. pre is the state before the change. Route 53 does not promise that
// a read issued right after a change already reflects it, so the read is polled
// every verifyEvery for at most the verification window: verifyTimeout, capped
// at the caller's context deadline minus 2s so this provider answers before the
// caller's own timeout cancels it. (We deliberately do not wait for GetChange
// to reach INSYNC, which can take minutes and is not what the next read
// depends on.)
//
// Outcomes: nil (confirmed); an ordinary error when a read shows values that
// are neither pre nor want (another writer changed the set); otherwise an error
// wrapping dns.ErrUnconfirmed: the change was accepted, so the caller must
// treat it as made.
func (p *Provider) verify(ctx context.Context, zid, op, name, typ string, pre, want []string) error {
	start := p.now()
	limit := p.verifyTimeout
	if dl, ok := ctx.Deadline(); ok {
		if room := dl.Sub(start) - 2*time.Second; room < limit {
			limit = room
		}
	}
	deadline := start.Add(limit) // limit <= 0 still allows the first read
	window := limit
	if window < 0 {
		window = 0
	}
	unconfirmed := func(cause error) error {
		return fmt.Errorf("route53: %s: change for %s %s was accepted but could not be confirmed within %s (%s): %w",
			op, name, typ, window.Round(time.Millisecond), p.scrub(cause.Error()), dns.ErrUnconfirmed)
	}
	for {
		got, err := p.getSet(ctx, zid, name, typ)
		if err != nil {
			return unconfirmed(err)
		}
		if sameValues(got, append([]string(nil), want...)...) {
			return nil
		}
		if !sameValues(got, append([]string(nil), pre...)...) {
			return fmt.Errorf("route53: %s: %s %s now holds %v, neither the previous nor the requested values (changed by another writer?)", op, name, typ, valuesOf(got))
		}
		if !p.now().Add(p.verifyEvery).Before(deadline) {
			return unconfirmed(errors.New("the record set still shows the previous values"))
		}
		if err := p.sleep(ctx, p.verifyEvery); err != nil {
			return unconfirmed(err)
		}
	}
}

func newSet(r dns.Record, ttl int64) types.ResourceRecordSet {
	return types.ResourceRecordSet{
		Name: aws.String(escName(r.Name)), Type: types.RRType(r.Type), TTL: aws.Int64(ttl),
		ResourceRecords: []types.ResourceRecord{{Value: aws.String(r.Value)}},
	}
}

func ttlOf(r dns.Record) int64 {
	if r.TTL <= 0 {
		return 300
	}
	return int64(r.TTL)
}

// checkType restricts writes to the types whose Route 53 value syntax is
// verbatim. TXT needs RFC-style double quoting in 255-byte chunks and is not
// handled yet, so it is rejected instead of being written wrongly.
func checkType(r dns.Record) error {
	switch r.Type {
	case "A", "AAAA", "CNAME":
		return nil
	}
	return fmt.Errorf("route53: record type %q is not supported for writes (A, AAAA, CNAME)", r.Type)
}

// setsAt lists every record set at exactly name (Route 53 sorts a name's sets
// together).
func (p *Provider) setsAt(ctx context.Context, zid, name string) ([]types.ResourceRecordSet, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	in := &r53.ListResourceRecordSetsInput{HostedZoneId: aws.String(zid), StartRecordName: aws.String(escName(name)), MaxItems: aws.Int32(100)}
	var out []types.ResourceRecordSet
	for page := 0; page < 20; page++ {
		resp, err := p.client().ListResourceRecordSets(ctx, in)
		if err != nil {
			return nil, p.wrapCtx(ctx, "get record", err)
		}
		if resp.MaxItems == nil {
			return nil, malformed("get record", "no MaxItems")
		}
		for _, s := range resp.ResourceRecordSets {
			if unescName(aws.ToString(s.Name)) != name {
				return out, nil
			}
			out = append(out, s)
		}
		if !resp.IsTruncated || resp.NextRecordName == nil {
			return out, nil
		}
		in.StartRecordName, in.StartRecordType, in.StartRecordIdentifier = resp.NextRecordName, resp.NextRecordType, resp.NextRecordIdentifier
	}
	return nil, errors.New("route53: get record: too many record sets at one name")
}

// cnameConflict enforces what Route 53 itself enforces: a CNAME set cannot
// coexist with ANY other record set at the same name (apex NS/SOA aside is
// irrelevant here because a CNAME at the apex is never created by this tool).
func (p *Provider) cnameConflict(ctx context.Context, zid string, r dns.Record) error {
	sets, err := p.setsAt(ctx, zid, r.Name)
	if err != nil {
		return err
	}
	for _, s := range sets {
		if r.Type == "CNAME" && s.Type != types.RRTypeCname {
			return fmt.Errorf("route53: %s already has a %s record set, which cannot coexist with CNAME: %w", r.Name, s.Type, dns.ErrRecordExists)
		}
		if r.Type != "CNAME" && s.Type == types.RRTypeCname {
			return fmt.Errorf("route53: %s already has a CNAME record set, which cannot coexist with %s: %w", r.Name, r.Type, dns.ErrRecordExists)
		}
	}
	return nil
}

func (p *Provider) CreateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if err := checkType(r); err != nil {
		return dns.Record{}, err
	}
	ref, err := p.zoneFor(ctx, zone)
	if err != nil {
		return dns.Record{}, err
	}
	cur, err := p.getSet(ctx, ref.id, r.Name, r.Type)
	if err != nil {
		return dns.Record{}, err
	}
	if cur != nil {
		if cur.AliasTarget == nil && len(cur.ResourceRecords) == 1 && aws.ToString(cur.ResourceRecords[0].Value) == r.Value {
			r.TTL = int(aws.ToInt64(cur.TTL))
			return r, nil
		}
		return dns.Record{}, dns.ErrRecordExists
	}
	if err := p.cnameConflict(ctx, ref.id, r); err != nil {
		return dns.Record{}, err
	}
	r.TTL = int(ttlOf(r))
	set := newSet(r, int64(r.TTL))
	if err := p.change(ctx, ref.id, "create record "+r.Name, types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: &set}); err != nil {
		if errors.Is(err, dns.ErrUnconfirmed) {
			return r, err // may exist: the caller must record ownership
		}
		return dns.Record{}, err
	}
	if err := p.verify(ctx, ref.id, "create record "+r.Name, r.Name, r.Type, nil, []string{r.Value}); err != nil {
		if errors.Is(err, dns.ErrUnconfirmed) {
			return r, err // accepted: the caller must record ownership
		}
		return dns.Record{}, err
	}
	return r, nil
}

func (p *Provider) UpdateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if r.ID != "" {
		return dns.Record{}, dns.ErrNotFound // route53 never issues record IDs
	}
	if err := checkType(r); err != nil {
		return dns.Record{}, err
	}
	ref, err := p.zoneFor(ctx, zone)
	if err != nil {
		return dns.Record{}, err
	}
	cur, err := p.getSet(ctx, ref.id, r.Name, r.Type)
	if err != nil {
		return dns.Record{}, err
	}
	if cur == nil {
		return dns.Record{}, dns.ErrNotFound
	}
	if cur.AliasTarget != nil {
		return dns.Record{}, fmt.Errorf("route53: %s %s is an alias record set; refusing to modify it: %w", r.Name, r.Type, dns.ErrRecordExists)
	}
	if n := len(cur.ResourceRecords); n != 1 {
		return dns.Record{}, fmt.Errorf("route53: %s %s set has %d values; refusing to modify values doorwarden does not manage: %w", r.Name, r.Type, n, dns.ErrRecordExists)
	}
	r.TTL = int(ttlOf(r))
	set := newSet(r, int64(r.TTL))
	// compare-and-swap: DELETE only succeeds if the set is still exactly what
	// was read, so a concurrent change fails the batch instead of being lost
	if err := p.change(ctx, ref.id, "update record "+r.Name,
		types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: cur},
		types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: &set}); err != nil {
		if errors.Is(err, dns.ErrUnconfirmed) {
			return r, err
		}
		return dns.Record{}, err
	}
	if err := p.verify(ctx, ref.id, "update record "+r.Name, r.Name, r.Type, valuesOf(cur), []string{r.Value}); err != nil {
		if errors.Is(err, dns.ErrUnconfirmed) {
			return r, err
		}
		return dns.Record{}, err
	}
	return r, nil
}

func (p *Provider) DeleteRecord(ctx context.Context, zone string, r dns.Record) error {
	if r.ID != "" {
		return nil // never issued: nothing can match
	}
	if err := checkType(r); err != nil {
		return err
	}
	ref, err := p.zoneFor(ctx, zone)
	if err != nil {
		return err
	}
	cur, err := p.getSet(ctx, ref.id, r.Name, r.Type)
	if err != nil || cur == nil || cur.AliasTarget != nil {
		return err
	}
	var rest []types.ResourceRecord
	var restVals []string
	found := false
	for _, rr := range cur.ResourceRecords {
		if aws.ToString(rr.Value) == r.Value {
			found = true
			continue
		}
		rest = append(rest, rr)
		restVals = append(restVals, aws.ToString(rr.Value))
	}
	if !found {
		return nil // never delete a record with a different value
	}
	op := "delete record " + r.Name
	changes := []types.Change{{Action: types.ChangeActionDelete, ResourceRecordSet: cur}}
	if len(rest) > 0 {
		keep := *cur
		keep.ResourceRecords = rest
		changes = append(changes, types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: &keep})
	}
	if err := p.change(ctx, ref.id, op, changes...); err != nil {
		return err
	}
	return p.verify(ctx, ref.id, op, r.Name, r.Type, valuesOf(cur), restVals)
}

// String, GoString and Format print only the type: a Provider holds no
// secret-bearing value (credentials live in closures, see dns.RedactedFormat),
// and these methods keep a copy of the struct from being dumped field by field.
func (p Provider) String() string             { return "route53.Provider <redacted>" }
func (p Provider) GoString() string           { return "route53.Provider <redacted>" }
func (p Provider) Format(f fmt.State, _ rune) { dns.RedactedFormat(f, "route53.Provider") }
