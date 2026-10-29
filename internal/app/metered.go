package app

import (
	"context"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/metrics"
)

// meteredProvider counts every record call of a DNS provider in
// doorwarden_dns_operations_total: ListRecords as "list", CreateRecord as
// "ensure", UpdateRecord as "update", DeleteRecord as "delete". Type,
// Capabilities and Test pass through uncounted.
type meteredProvider struct {
	dns.Provider
	met *metrics.Metrics
}

func (p *meteredProvider) count(op string, err error) {
	res := "ok"
	if err != nil {
		res = "error"
	}
	p.met.DNSOperation(p.Type(), op, res)
}

func (p *meteredProvider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	rs, err := p.Provider.ListRecords(ctx, zone)
	p.count("list", err)
	return rs, err
}

func (p *meteredProvider) CreateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	out, err := p.Provider.CreateRecord(ctx, zone, r)
	p.count("ensure", err)
	return out, err
}

func (p *meteredProvider) UpdateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	out, err := p.Provider.UpdateRecord(ctx, zone, r)
	p.count("update", err)
	return out, err
}

func (p *meteredProvider) DeleteRecord(ctx context.Context, zone string, r dns.Record) error {
	err := p.Provider.DeleteRecord(ctx, zone, r)
	p.count("delete", err)
	return err
}
