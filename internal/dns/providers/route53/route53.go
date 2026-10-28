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
package route53

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

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
}

// Provider implements dns.Provider.
type Provider struct {
	cl      *r53.Client
	pinned  string
	secrets []secrets.Secret

	mu    sync.Mutex
	cache map[string]string // zone -> hosted zone id
}

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
	return &Provider{cl: cl, pinned: strings.TrimPrefix(c.HostedZoneID, "/hostedzone/"), secrets: sec, cache: map[string]string{}}, nil
}

func (p *Provider) Type() string { return Type }

func (p *Provider) Capabilities() dns.Capabilities {
	c := staticCaps
	c.MultiZone = p.pinned == ""
	return c
}

func (p *Provider) scrub(s string) string {
	for _, x := range p.secrets {
		if v := x.Reveal(); v != "" {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	return s
}

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

type hostedZone struct {
	id      string
	name    string // lowercase, no trailing dot
	private bool
}

func (p *Provider) listZones(ctx context.Context) ([]hostedZone, error) {
	var out []hostedZone
	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("route53: list hosted zones: more than %d pages; refusing to continue", maxPages)
		}
		resp, err := p.cl.ListHostedZones(ctx, &r53.ListHostedZonesInput{Marker: marker})
		if err != nil {
			return nil, p.wrapCtx(ctx, "list hosted zones", err)
		}
		for _, z := range resp.HostedZones {
			priv := z.Config != nil && z.Config.PrivateZone
			out = append(out, hostedZone{
				id:      strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/"),
				name:    strings.ToLower(strings.TrimSuffix(aws.ToString(z.Name), ".")),
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

func (p *Provider) wrapCtx(ctx context.Context, op string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("route53: %s: %w", op, ctx.Err())
	}
	return p.mapErr(op, err)
}

// pick chooses the hosted zone for zone: the longest hosted-zone name that
// equals zone or is a parent domain of it; a private zone is never chosen
// implicitly (set hosted_zone_id).
func pick(zone string, zones []hostedZone) (string, error) {
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
				return "", fmt.Errorf("route53: only a private hosted zone matches %q; set hosted_zone_id to use it", zone)
			}
		}
		return "", fmt.Errorf("route53: no hosted zone found for %q (check the credentials can list hosted zones)", zone)
	}
	sort.SliceStable(cands, func(i, j int) bool { return len(cands[i].name) > len(cands[j].name) })
	if len(cands) > 1 && len(cands[0].name) == len(cands[1].name) {
		return "", fmt.Errorf("route53: several public hosted zones named %q; set hosted_zone_id", cands[0].name)
	}
	return cands[0].id, nil
}

func (p *Provider) zoneID(ctx context.Context, zone string) (string, error) {
	if p.pinned != "" {
		return p.pinned, nil
	}
	p.mu.Lock()
	id, ok := p.cache[zone]
	p.mu.Unlock()
	if ok {
		return id, nil
	}
	zs, err := p.listZones(ctx)
	if err != nil {
		return "", err
	}
	id, err = pick(zone, zs)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.cache[zone] = id
	p.mu.Unlock()
	return id, nil
}

// Test verifies credentials with a one-item hosted-zone listing (and the
// pinned zone when configured).
func (p *Provider) Test(ctx context.Context) error {
	if p.pinned != "" {
		if _, err := p.cl.GetHostedZone(ctx, &r53.GetHostedZoneInput{Id: aws.String(p.pinned)}); err != nil {
			return p.wrapCtx(ctx, "verify credentials", err)
		}
		return nil
	}
	if _, err := p.cl.ListHostedZones(ctx, &r53.ListHostedZonesInput{MaxItems: aws.Int32(1)}); err != nil {
		return p.wrapCtx(ctx, "verify credentials", err)
	}
	return nil
}

func escName(n string) string { return strings.ReplaceAll(n, "*", `\052`) }

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
		resp, err := p.cl.ListResourceRecordSets(ctx, in)
		if err != nil {
			return nil, p.wrapCtx(ctx, "list records", err)
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
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	sets, err := p.allSets(ctx, zid)
	if err != nil {
		return nil, err
	}
	var out []dns.Record
	for _, s := range sets {
		name := unescName(aws.ToString(s.Name))
		if !inZone(name, zone) || s.AliasTarget != nil {
			continue
		}
		for _, rr := range s.ResourceRecords {
			out = append(out, dns.Record{Name: name, Type: string(s.Type), Value: aws.ToString(rr.Value), TTL: int(aws.ToInt64(s.TTL))})
		}
	}
	return out, nil
}

// getSet fetches the record set for (name, type), if any.
func (p *Provider) getSet(ctx context.Context, zid, name, typ string) (*types.ResourceRecordSet, error) {
	resp, err := p.cl.ListResourceRecordSets(ctx, &r53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zid), StartRecordName: aws.String(escName(name)),
		StartRecordType: types.RRType(typ), MaxItems: aws.Int32(1),
	})
	if err != nil {
		return nil, p.wrapCtx(ctx, "get record", err)
	}
	for i := range resp.ResourceRecordSets {
		s := resp.ResourceRecordSets[i]
		if unescName(aws.ToString(s.Name)) == name && string(s.Type) == typ && s.SetIdentifier == nil {
			return &s, nil
		}
	}
	return nil, nil
}

func (p *Provider) change(ctx context.Context, zid string, action types.ChangeAction, set types.ResourceRecordSet, op string) error {
	_, err := p.cl.ChangeResourceRecordSets(ctx, &r53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zid),
		ChangeBatch:  &types.ChangeBatch{Changes: []types.Change{{Action: action, ResourceRecordSet: &set}}},
	})
	if err != nil {
		return p.wrapCtx(ctx, op, err)
	}
	return nil
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

func (p *Provider) CreateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if err := checkType(r); err != nil {
		return dns.Record{}, err
	}
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return dns.Record{}, err
	}
	cur, err := p.getSet(ctx, zid, r.Name, r.Type)
	if err != nil {
		return dns.Record{}, err
	}
	if cur != nil {
		if len(cur.ResourceRecords) == 1 && aws.ToString(cur.ResourceRecords[0].Value) == r.Value {
			r.TTL = int(aws.ToInt64(cur.TTL))
			return r, nil
		}
		return dns.Record{}, dns.ErrRecordExists
	}
	r.TTL = int(ttlOf(r))
	if err := p.change(ctx, zid, types.ChangeActionCreate, newSet(r, int64(r.TTL)), "create record "+r.Name); err != nil {
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
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return dns.Record{}, err
	}
	cur, err := p.getSet(ctx, zid, r.Name, r.Type)
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
	if err := p.change(ctx, zid, types.ChangeActionUpsert, newSet(r, int64(r.TTL)), "update record "+r.Name); err != nil {
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
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	cur, err := p.getSet(ctx, zid, r.Name, r.Type)
	if err != nil || cur == nil {
		return err
	}
	var rest []types.ResourceRecord
	found := false
	for _, rr := range cur.ResourceRecords {
		if aws.ToString(rr.Value) == r.Value {
			found = true
			continue
		}
		rest = append(rest, rr)
	}
	if !found {
		return nil // never delete a record with a different value
	}
	if len(rest) == 0 {
		return p.change(ctx, zid, types.ChangeActionDelete, *cur, "delete record "+r.Name)
	}
	upd := *cur
	upd.ResourceRecords = rest
	return p.change(ctx, zid, types.ChangeActionUpsert, upd, "delete record value "+r.Name)
}

// String and GoString keep credentials out of any formatted output of the
// provider (unexported struct fields are printed raw by fmt, bypassing the
// redaction of secrets.Secret).
func (p *Provider) String() string   { return "route53.Provider" }
func (p *Provider) GoString() string { return "route53.Provider" }
