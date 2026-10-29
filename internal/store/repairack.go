package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

// RepairMassOKPrefix starts every mass-repair acknowledgement key in kv.
//
// The DNS drift repair refuses to re-create the records of a provider/zone
// when most of them are missing at once (the mass-repair breaker, see
// internal/reconcile). An operator who checked that the records really are
// gone acknowledges it once for that provider/zone: the key
// RepairMassOKKey(provider, zone) holds the acknowledgement time (RFC3339,
// UTC). While it is younger than 24h the repairs run, capped per cycle; the
// DNS executor deletes the key once the zone has recovered, or when it
// expired.
const RepairMassOKPrefix = "dns/repair-mass-ok/"

// RepairMassOKKey is the kv key of the mass-repair acknowledgement of a
// provider/zone. The zone is normalized (lowercase, no surrounding space or
// trailing dot), so every writer and reader agree on one key.
func RepairMassOKKey(provider, zone string) string {
	return RepairMassOKPrefix + provider + "/" + normName(strings.TrimSpace(zone))
}

// ParseRepairMassOKKey splits a RepairMassOKKey into provider and zone. The
// zone is the part after the last "/" (zones never contain one).
func ParseRepairMassOKKey(key string) (provider, zone string, ok bool) {
	rest, found := strings.CutPrefix(key, RepairMassOKPrefix)
	i := strings.LastIndexByte(rest, '/')
	if !found || i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// ErrBadRepairAck: an acknowledgement names no provider or no zone.
var ErrBadRepairAck = errors.New("store: a mass-repair acknowledgement needs a provider and a zone")

// SetRepairMassOK records a mass-repair acknowledgement for provider/zone
// made at at.
func (s *Store) SetRepairMassOK(ctx context.Context, provider, zone string, at time.Time) error {
	if strings.TrimSpace(provider) == "" || provider != strings.TrimSpace(provider) || normName(strings.TrimSpace(zone)) == "" {
		return ErrBadRepairAck
	}
	return s.SetSetting(ctx, RepairMassOKKey(provider, zone), at.UTC().Format(time.RFC3339))
}

// AcknowledgeMassRepair is the operator's one-shot acknowledgement that the
// owned DNS records of provider/zone really are gone and may be re-created
// (capped per cycle) although most of them are missing. It lasts 24h and is
// cleared once the zone has recovered. (The API action POST
// /api/v1/dns/repair/ack {provider, zone} calls it.)
func (s *Store) AcknowledgeMassRepair(ctx context.Context, provider, zone string) error {
	return s.SetRepairMassOK(ctx, provider, zone, time.Now())
}

// ClearRepairMassOK deletes the acknowledgement of provider/zone (absent is
// not an error).
func (s *Store) ClearRepairMassOK(ctx context.Context, provider, zone string) error {
	return s.DeleteSetting(ctx, RepairMassOKKey(provider, zone))
}

// ListRepairMassOK returns every acknowledgement, keyed provider+"/"+zone.
// Keys or values that do not parse are left out (they never count as an
// acknowledgement).
func (s *Store) ListRepairMassOK(ctx context.Context) (map[string]time.Time, error) {
	kv, err := s.ListSettingsWithPrefix(ctx, RepairMassOKPrefix)
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	for k, v := range kv {
		p, z, ok := ParseRepairMassOKKey(k)
		at, perr := time.Parse(time.RFC3339, strings.TrimSpace(v))
		if !ok || perr != nil {
			continue
		}
		out[p+"/"+z] = at
	}
	return out, nil
}
