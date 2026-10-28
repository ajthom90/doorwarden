package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/store"
)

// DefaultDNSCallTimeout bounds every single provider call (and every listing
// in GatherObserved) when no other timeout is configured.
const DefaultDNSCallTimeout = 30 * time.Second

// OwnershipStore is the dns_records ownership table (*store.Store implements
// it). The DNS executor only ever modifies or deletes provider records that
// have a row here.
type OwnershipStore interface {
	AddOwnedRecord(ctx context.Context, r store.DNSRecord) error
	ListOwnedRecords(ctx context.Context, provider, zone string) ([]store.DNSRecord, error)
	DeleteOwnedRecord(ctx context.Context, provider, zone, name, typ string) error
	// SetOwnedRemoval sets or clears removed_after of the row, only if its
	// owner key equals owner (store.ErrOwnedRecordNotFound otherwise).
	SetOwnedRemoval(ctx context.Context, provider, zone, name, typ, owner string, at *time.Time) error
}

// ActivitySink receives user-visible activity entries (*store.Store
// implements it).
type ActivitySink interface {
	AppendActivity(ctx context.Context, e store.ActivityEntry) error
}

var (
	// ErrOwnerConflict: the ownership row for the record belongs to a
	// different owner key than the action's. It is store.ErrOwnerConflict, so
	// errors.Is matches either name.
	ErrOwnerConflict = store.ErrOwnerConflict
	// ErrForeignRecord: a record this tool does not own already holds the
	// name, so nothing was created.
	ErrForeignRecord = errors.New("reconcile: a DNS record not owned by doorwarden holds this name; not creating")
	// ErrListingUnavailable: the provider's records could not be listed, so
	// the pre-create foreign-record check could not run and nothing was
	// created.
	ErrListingUnavailable = errors.New("reconcile: provider listing unavailable; not creating a record blind")
	// ErrDNSRefused: the action is outside what the executor may touch
	// (unknown or unmanaged zone, provider mismatch, name outside the zone,
	// missing owner, the wildcard record on delete).
	ErrDNSRefused = errors.New("reconcile: DNS action refused")
)

// DNSExecutorConfig configures NewDNSExecutor.
type DNSExecutorConfig struct {
	// Config supplies the zones (records mode and provider). Required.
	Config *config.Config
	// Providers are constructed providers by config provider name
	// (zones[].records.provider).
	Providers map[string]dns.Provider
	// Store is the ownership table. Required.
	Store OwnershipStore
	// Activity receives user-visible entries; may be nil.
	Activity ActivitySink
	// Log receives operator logs; nil means slog.Default().
	Log *slog.Logger
	// Now stamps CreatedAt and activity; nil means time.Now.
	Now func() time.Time
	// CallTimeout bounds each provider call; 0 means DefaultDNSCallTimeout.
	CallTimeout time.Duration
}

type dnsZone struct{ name, provider, mode string }

// DNSExecutor applies DNSEnsure, DNSDelete, DNSScheduleRemoval and
// DNSCancelRemoval actions. It only ever updates
// or deletes provider records that have an ownership row whose owner key
// equals the action's Owner, and it only creates a record after its own
// listing of the zone showed that nothing else holds the name.
//
// DNSEnsure (Record.Name/Type/Value/TTL, Owner, Zone, Provider):
//   - an owned row with the same owner and an equal value: nothing to do (no
//     provider call);
//   - an owned row with the same owner and another value: UpdateRecord with
//     the STORED provider record ID (Action.Record.ID is ignored), then the
//     row is updated. A provider whose instance lacks the Update capability
//     gets a DeleteRecord of the stored record followed by a guarded create.
//     UpdateRecord answering dns.ErrNotFound (the record was removed out of
//     band) falls back to a guarded create, which refuses if any record
//     holds the name;
//   - an owned row with another owner: no provider call, a Conflict
//     activity and ErrOwnerConflict;
//   - no row: a guarded create. The zone is listed (once per Apply batch
//     and provider/zone; a failed listing is cached for the batch too) and
//     any listed record with the same name and the same type, or a CNAME
//     (any type when creating a CNAME), refuses the create with a Conflict
//     activity and ErrForeignRecord, because CreateRecord of an identical
//     record would silently adopt it. A failed listing refuses with
//     ErrListingUnavailable. dns.ErrRecordExists from CreateRecord is
//     treated like a listed foreign record. After a create the ownership
//     row is written (retried once); if that fails the created record is
//     deleted again (by its returned ID, or by exact name/type/value when
//     the provider returned none, which the listing proved was free) unless
//     an ownership row now references it, and an error names the record.
//
// DNSDelete: only a row for (provider, zone, name, type) whose owner key
// equals Action.Owner is deleted, using the STORED ID, name, type and value
// (never the action's). No row: no-op, no provider call. The wildcard record
// (owner key "zone:...", or a "*." name) is never deleted: such an action is
// refused with ErrDNSRefused (Action has no Force flag; a later UI path must
// use its own call). dns.ErrNotFound or nil from the provider forgets the
// row; any other error keeps it (the row, still past its RemovedAfter, makes
// the next Plan emit the DNSDelete again).
//
// DNSScheduleRemoval / DNSCancelRemoval: no provider call. The row for
// (provider, zone, name, type) gets RemovedAfter = Action.RemovedAfter
// (required for schedule) or nil, only if its owner key equals
// Action.Owner (store.SetOwnedRemoval). No such row (gone, or owned by
// another key) is a no-op. The wildcard record is refused with
// ErrDNSRefused, like its delete.
//
// Every action must name a zone configured with records mode wildcard or
// per-host, that zone's records provider, and a record name equal to the
// zone or inside it; otherwise it is refused with ErrDNSRefused. Names,
// types and zones are normalized (lowercase, no trailing dot; uppercase
// type) before every provider and store call. TTL is passed through.
//
// Each provider call runs under CallTimeout. A failing action does not stop
// the batch; errors are joined, each prefixed with
// "<kind> <provider>/<zone> <name> <type>". Cancellation of ctx stops the
// batch between actions; bookkeeping after a provider write (ownership row,
// rollback) is finished even if ctx is cancelled.
//
// Dry run: no provider call at all (not even the pre-create listing) and no
// store write; one activity entry per action says what would happen and
// that the pre-create foreign-record check was not performed.
//
// Known limitation: the listing is taken once per batch, so a foreign record
// identical to ours created between that listing and CreateRecord would be
// adopted by the provider's idempotent create.
type DNSExecutor struct {
	zones     map[string]dnsZone
	providers map[string]dns.Provider
	st        OwnershipStore
	act       ActivitySink
	log       *slog.Logger
	now       func() time.Time
	timeout   time.Duration

	mu sync.Mutex // serializes Apply (the Runner already does)
}

// NewDNSExecutor validates the configuration against the constructed
// providers. It fails loudly (no silent downgrade) when a zone with records
// mode wildcard or per-host names a provider that is not in Providers, or
// when a wildcard zone's provider instance lacks WildcardA (the instance's
// Capabilities() is authoritative; registry caps are only an upper bound).
func NewDNSExecutor(cfg DNSExecutorConfig) (*DNSExecutor, error) {
	if cfg.Config == nil {
		return nil, errors.New("dns executor: no config")
	}
	if cfg.Store == nil {
		return nil, errors.New("dns executor: no ownership store")
	}
	e := &DNSExecutor{zones: map[string]dnsZone{}, providers: map[string]dns.Provider{}, st: cfg.Store,
		act: cfg.Activity, log: cfg.Log, now: cfg.Now, timeout: cfg.CallTimeout}
	if e.log == nil {
		e.log = slog.Default()
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.timeout <= 0 {
		e.timeout = DefaultDNSCallTimeout
	}
	for n, p := range cfg.Providers {
		if p != nil {
			e.providers[n] = p
		}
	}
	seen := map[string]bool{}
	var errs []error
	for _, z := range cfg.Config.Zones {
		n := normName(z.Name)
		if n == "" || seen[n] {
			continue // first definition wins, as in Plan
		}
		seen[n] = true
		mode := z.Records.Mode
		if mode != "wildcard" && mode != "per-host" {
			continue // off/unset: no DNS actions are accepted for this zone
		}
		p := e.providers[z.Records.Provider]
		if p == nil {
			errs = append(errs, fmt.Errorf("dns executor: zone %q (records mode %s) uses records provider %q, which is not available",
				n, mode, z.Records.Provider))
			continue
		}
		if mode == "wildcard" && !p.Capabilities().WildcardA {
			errs = append(errs, fmt.Errorf("dns executor: zone %q uses records mode wildcard but provider %q (type %s) does not support wildcard A records on this instance; use records mode per-host or another provider",
				n, z.Records.Provider, p.Type()))
			continue
		}
		e.zones[n] = dnsZone{name: n, provider: z.Records.Provider, mode: mode}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return e, nil
}

// dnsTarget is a validated, normalized action target.
type dnsTarget struct {
	p                         dns.Provider
	provider, zone, name, typ string
	owner, value              string
	ttl                       int
}

func (t dnsTarget) String() string { return t.name + " " + t.typ }

// listing is one provider/zone listing cached for a batch.
type listing struct {
	recs []dns.Record
	err  error
}

type dnsBatch struct {
	e        *DNSExecutor
	listings map[string]*listing
}

// Apply implements Executor; kinds other than DNSEnsure, DNSDelete,
// DNSScheduleRemoval and DNSCancelRemoval are ignored.
func (e *DNSExecutor) Apply(ctx context.Context, actions []Action, dryRun bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := &dnsBatch{e: e, listings: map[string]*listing{}}
	var errs []error
	for _, a := range actions {
		if !isDNSKind(a.Kind) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if dryRun {
			b.dry(ctx, a)
			continue
		}
		if err := b.apply(ctx, a); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", a.Kind, describe(a), err))
		}
	}
	return errors.Join(errs...)
}

func isDNSKind(k ActionKind) bool {
	return k == DNSEnsure || k == DNSDelete || k == DNSScheduleRemoval || k == DNSCancelRemoval
}

// isWildcardTarget reports whether t is the zone's wildcard record (or names
// a "zone:" owner), which is never deleted or scheduled automatically.
func isWildcardTarget(t dnsTarget) bool {
	return strings.HasPrefix(strings.ToLower(t.owner), "zone:") || strings.HasPrefix(t.name, "*.")
}

// describe renders "<provider>/<zone> <name> <type>" for error prefixes.
func describe(a Action) string {
	name, typ := normName(a.Host), ""
	if a.Record != nil {
		name, typ = normName(a.Record.Name), normType(a.Record.Type)
	}
	return strings.TrimSpace(fmt.Sprintf("%s/%s %s %s", a.Provider, normName(a.Zone), name, typ))
}

// resolve validates the action's scope and normalizes its target.
func (e *DNSExecutor) resolve(a Action) (dnsTarget, error) {
	if a.Record == nil {
		return dnsTarget{}, fmt.Errorf("%w: action carries no record", ErrDNSRefused)
	}
	zn := normName(a.Zone)
	z, ok := e.zones[zn]
	if !ok {
		return dnsTarget{}, fmt.Errorf("%w: zone %q is not configured for managed records", ErrDNSRefused, zn)
	}
	if a.Provider != z.provider {
		return dnsTarget{}, fmt.Errorf("%w: provider %q is not the records provider (%q) of zone %q", ErrDNSRefused, a.Provider, z.provider, zn)
	}
	t := dnsTarget{p: e.providers[z.provider], provider: z.provider, zone: zn, name: normName(a.Record.Name),
		typ: normType(a.Record.Type), owner: strings.TrimSpace(a.Owner), value: strings.TrimSpace(a.Record.Value), ttl: a.Record.TTL}
	if t.p == nil {
		return dnsTarget{}, fmt.Errorf("%w: provider %q is not available", ErrDNSRefused, a.Provider)
	}
	if t.name == "" || t.typ == "" {
		return dnsTarget{}, fmt.Errorf("%w: record has no name or type", ErrDNSRefused)
	}
	if t.name != zn && !strings.HasSuffix(t.name, "."+zn) {
		return dnsTarget{}, fmt.Errorf("%w: record %s is outside zone %q", ErrDNSRefused, t.name, zn)
	}
	if t.owner == "" {
		return dnsTarget{}, fmt.Errorf("%w: action has no owner key", ErrDNSRefused)
	}
	// The wildcard record and the zone owner key go together: "*.zone" must be
	// owned by exactly WildcardOwnerKey(zone), and a "zone:" owner (prefix
	// compared case-insensitively) may own only "*.zone".
	if strings.HasPrefix(strings.ToLower(t.owner), "zone:") || strings.HasPrefix(t.name, "*.") {
		if t.owner != WildcardOwnerKey(zn) || t.name != "*."+zn {
			return dnsTarget{}, fmt.Errorf("%w: record %s with owner %q: the wildcard record *.%s must be owned by exactly %q",
				ErrDNSRefused, t.name, t.owner, zn, WildcardOwnerKey(zn))
		}
	}
	return t, nil
}

func (b *dnsBatch) apply(ctx context.Context, a Action) error {
	t, err := b.e.resolve(a)
	if err != nil {
		b.e.activity(ctx, "warn", fmt.Sprintf("refused %s %s: %v", a.Kind, describe(a), err))
		return err
	}
	switch a.Kind {
	case DNSDelete:
		return b.delete(ctx, t)
	case DNSScheduleRemoval, DNSCancelRemoval:
		return b.setRemoval(ctx, t, a)
	}
	return b.ensure(ctx, t)
}

// ownedRow returns the ownership row for t's (provider, zone, name, type),
// read fresh from the store (never cached across writes).
func (e *DNSExecutor) ownedRow(ctx context.Context, t dnsTarget) (*store.DNSRecord, error) {
	rows, err := e.st.ListOwnedRecords(ctx, t.provider, t.zone)
	if err != nil {
		return nil, fmt.Errorf("reading ownership rows: %w", err)
	}
	for i := range rows {
		if normName(rows[i].Name) == t.name && normType(rows[i].Type) == t.typ {
			return &rows[i], nil
		}
	}
	return nil, nil
}

func (b *dnsBatch) ensure(ctx context.Context, t dnsTarget) error {
	if t.value == "" {
		return fmt.Errorf("%w: record has no value", ErrDNSRefused)
	}
	row, err := b.e.ownedRow(ctx, t)
	if err != nil {
		return err
	}
	if row == nil {
		return b.create(ctx, t, nil)
	}
	if row.OwnerKey != t.owner {
		b.e.activity(ctx, "warn", fmt.Sprintf("conflict: %s at %s/%s is owned by %s, not %s; not touching it",
			t, t.provider, t.zone, row.OwnerKey, t.owner))
		return fmt.Errorf("%w: owned by %s, not %s", ErrOwnerConflict, row.OwnerKey, t.owner)
	}
	if sameValue(row.Value, t.value) {
		return nil
	}
	return b.update(ctx, t, row)
}

func (b *dnsBatch) update(ctx context.Context, t dnsTarget, row *store.DNSRecord) error {
	if row.ProviderRecordID == "" || !t.p.Capabilities().Update {
		// Never UpdateRecord without a stored ID: an ID-less update targets
		// (name, type) and would overwrite (and so adopt) whatever record
		// holds the name now, ours or not.
		return b.replace(ctx, t, row)
	}
	stored := dns.Record{ID: row.ProviderRecordID, Name: t.name, Type: t.typ, Value: row.Value}
	rec := dns.Record{ID: row.ProviderRecordID, Name: t.name, Type: t.typ, Value: t.value, TTL: t.ttl}
	var got dns.Record
	err := b.e.call(ctx, func(c context.Context) (err error) { got, err = t.p.UpdateRecord(c, t.zone, rec); return })
	if errors.Is(err, dns.ErrNotFound) {
		b.e.log.WarnContext(ctx, "owned DNS record is gone at the provider; re-creating after a foreign-record check",
			"provider", t.provider, "zone", t.zone, "name", t.name, "type", t.typ, "id", row.ProviderRecordID)
		b.forget(t, stored)
		return b.create(ctx, t, row)
	}
	if err != nil {
		return err
	}
	b.forget(t, stored)
	id := got.ID
	if id == "" {
		// The provider may have replaced the record (new ID) without saying
		// so: look the record up again rather than keep a possibly stale ID.
		id = b.findID(ctx, t)
		if id == "" {
			b.e.activity(ctx, "warn", fmt.Sprintf("updated %s at %s/%s but could not determine its provider id; stored without id (later changes use the replace path)",
				t, t.provider, t.zone))
		}
	} else {
		b.remember(t, dns.Record{ID: id, Name: t.name, Type: t.typ, Value: t.value, TTL: t.ttl})
	}
	nr := *row
	nr.Zone, nr.Name, nr.Type, nr.Value, nr.ProviderRecordID = t.zone, t.name, t.typ, t.value, id
	if err := b.e.persist(ctx, nr); err != nil {
		// The old ID state cannot be restored (the provider may have rotated
		// it): tell the operator exactly which record and ID to fix.
		b.e.activity(ctx, "error", fmt.Sprintf("UPDATED %s at %s/%s to %s (new provider id %q) BUT COULD NOT UPDATE ITS OWNERSHIP ROW (still value %s, id %q): %v",
			t, t.provider, t.zone, t.value, id, row.Value, row.ProviderRecordID, err))
		return fmt.Errorf("updated %s to %s (new provider id %q) but could not update its ownership row: %w", t, t.value, id, err)
	}
	b.e.activity(ctx, "info", fmt.Sprintf("updated %s at %s/%s: %s -> %s (owner %s, provider id %q)", t, t.provider, t.zone, row.Value, t.value, t.owner, id))
	return nil
}

// findID re-lists t's zone (refreshing the batch cache) and returns the ID of
// the single record with t's exact name, type and value, or "" when it cannot
// be determined.
func (b *dnsBatch) findID(ctx context.Context, t dnsTarget) string {
	delete(b.listings, t.provider+"/"+t.zone)
	l := b.listing(ctx, t)
	if l.err != nil {
		return ""
	}
	id, n := "", 0
	for _, r := range l.recs {
		if normName(r.Name) == t.name && normType(r.Type) == t.typ && sameValue(r.Value, t.value) {
			id, n = r.ID, n+1
		}
	}
	if n != 1 {
		return ""
	}
	return id
}

// isOwn reports whether listed record r is our stored record: by ID when both
// have one, otherwise by exact value.
func isOwn(r, stored dns.Record) bool {
	if stored.ID != "" && r.ID != "" {
		return r.ID == stored.ID
	}
	return sameValue(r.Value, stored.Value)
}

// replace changes an owned record's value without UpdateRecord (empty stored
// ID, or no in-place update on this provider instance). All checks run
// before anything is deleted: the listing must be available, and at t's name
// nothing but our stored record may exist (another value of the same type,
// or a CNAME, is a Conflict and nothing changes). Then our record is deleted
// by its stored identity (ID, or exact name/type/STORED value), the new
// value is created and the same ownership row is updated in place. If the
// create fails the old value is re-created (best effort, loudly) so the
// service keeps DNS; if that fails too the row is kept and the next cycle
// re-creates through the guarded path.
func (b *dnsBatch) replace(ctx context.Context, t dnsTarget, row *store.DNSRecord) error {
	stored := dns.Record{ID: row.ProviderRecordID, Name: t.name, Type: t.typ, Value: row.Value}
	l := b.listing(ctx, t)
	if l.err != nil {
		b.e.activity(ctx, "warn", fmt.Sprintf("not changing %s at %s/%s: listing the zone failed, so foreign records are unknown: %v",
			t, t.provider, t.zone, l.err))
		return fmt.Errorf("%w: %w", ErrListingUnavailable, l.err)
	}
	ownPresent := false
	for _, r := range l.recs {
		if normName(r.Name) != t.name {
			continue
		}
		if normType(r.Type) == t.typ && isOwn(r, stored) {
			ownPresent = true
			continue
		}
		if blocks(r, t) {
			b.e.activity(ctx, "warn", fmt.Sprintf("conflict: not changing %s at %s/%s: foreign record %s %s %s (id %q) exists next to ours; adopt or remove it",
				t, t.provider, t.zone, normName(r.Name), normType(r.Type), r.Value, r.ID))
			return fmt.Errorf("%w: %s %s %s (id %q)", ErrForeignRecord, normName(r.Name), normType(r.Type), r.Value, r.ID)
		}
	}
	if ownPresent {
		err := b.e.call(ctx, func(c context.Context) error { return t.p.DeleteRecord(c, t.zone, stored) })
		if err != nil && !errors.Is(err, dns.ErrNotFound) {
			return fmt.Errorf("deleting the old record (value %s, id %q) failed: %w", stored.Value, stored.ID, err)
		}
		b.forget(t, stored)
	}
	created, err := b.doCreate(ctx, t, row)
	if err == nil || created || !ownPresent || errors.Is(err, ErrForeignRecord) {
		return err
	}
	return b.restore(ctx, t, row, err)
}

// restore re-creates the old value of row after its replacement could not be
// created, and points the row at the restored record.
func (b *dnsBatch) restore(ctx context.Context, t dnsTarget, row *store.DNSRecord, cerr error) error {
	bctx := context.WithoutCancel(ctx)
	old := dns.Record{Name: t.name, Type: t.typ, Value: row.Value, TTL: t.ttl}
	var got dns.Record
	rerr := b.e.call(bctx, func(c context.Context) (err error) { got, err = t.p.CreateRecord(c, t.zone, old); return })
	if rerr != nil {
		msg := fmt.Sprintf("replacing %s at %s/%s: old value %s deleted, creating %s failed (%v) and restoring %s failed (%v); no record until the next cycle re-creates it",
			t, t.provider, t.zone, row.Value, t.value, cerr, row.Value, rerr)
		b.e.activity(ctx, "error", msg)
		return errors.New(msg)
	}
	b.remember(t, dns.Record{ID: got.ID, Name: t.name, Type: t.typ, Value: row.Value, TTL: t.ttl})
	nr := *row
	nr.Zone, nr.Name, nr.Type, nr.ProviderRecordID = t.zone, t.name, t.typ, got.ID
	if perr := b.e.persist(ctx, nr); perr != nil {
		msg := fmt.Sprintf("replacing %s at %s/%s: creating %s failed (%v); old value %s restored (new provider id %q) but its ownership row could not be updated: %v",
			t, t.provider, t.zone, t.value, cerr, row.Value, got.ID, perr)
		b.e.activity(ctx, "error", msg)
		return errors.New(msg)
	}
	b.e.activity(ctx, "error", fmt.Sprintf("replacing %s at %s/%s: creating %s failed (%v); old value %s restored (provider id %q)",
		t, t.provider, t.zone, t.value, cerr, row.Value, got.ID))
	return fmt.Errorf("creating %s failed: %w; old value %s restored (provider id %q)", t.value, cerr, row.Value, got.ID)
}

// blocks reports whether listed record r prevents creating t: same name and
// the same type, or a CNAME on either side. Deliberately not blocking: a
// record of another type at the name (so our AAAA may sit next to a foreign
// A, a dual-stack split, and our A next to foreign TXT/MX). NS delegations
// (a foreign NS at or above the name inside the zone) are not considered.
func blocks(r dns.Record, t dnsTarget) bool {
	if normName(r.Name) != t.name {
		return false
	}
	rt := normType(r.Type)
	return rt == t.typ || rt == "CNAME" || t.typ == "CNAME"
}

// create is the guarded create. base is the existing same-owner row when
// re-creating a record that vanished (its CreatedAt and RemovedAfter are
// kept; AddOwnedRecord then updates that row in place).
func (b *dnsBatch) create(ctx context.Context, t dnsTarget, base *store.DNSRecord) error {
	l := b.listing(ctx, t)
	if l.err != nil {
		b.e.activity(ctx, "warn", fmt.Sprintf("not creating %s at %s/%s: listing the zone failed, so foreign records are unknown: %v",
			t, t.provider, t.zone, l.err))
		return fmt.Errorf("%w: %w", ErrListingUnavailable, l.err)
	}
	for _, r := range l.recs {
		if !blocks(r, t) {
			continue
		}
		b.e.activity(ctx, "warn", fmt.Sprintf("conflict: not creating %s at %s/%s: foreign record %s %s %s (id %q) exists; adopt or remove it",
			t, t.provider, t.zone, normName(r.Name), normType(r.Type), r.Value, r.ID))
		return fmt.Errorf("%w: %s %s %s (id %q)", ErrForeignRecord, normName(r.Name), normType(r.Type), r.Value, r.ID)
	}
	_, err := b.doCreate(ctx, t, base)
	return err
}

// doCreate creates t at the provider (the caller ran the foreign-record
// checks) and records ownership, rolling back on failure. created reports
// whether the provider create succeeded.
func (b *dnsBatch) doCreate(ctx context.Context, t dnsTarget, base *store.DNSRecord) (created bool, err error) {
	want := dns.Record{Name: t.name, Type: t.typ, Value: t.value, TTL: t.ttl}
	var got dns.Record
	err = b.e.call(ctx, func(c context.Context) (err error) { got, err = t.p.CreateRecord(c, t.zone, want); return })
	if errors.Is(err, dns.ErrRecordExists) {
		delete(b.listings, t.provider+"/"+t.zone) // the cached listing is stale
		b.e.activity(ctx, "warn", fmt.Sprintf("conflict: not creating %s at %s/%s: a foreign record appeared", t, t.provider, t.zone))
		return false, fmt.Errorf("%w: %w", ErrForeignRecord, err)
	}
	if err != nil {
		return false, err
	}
	rec := dns.Record{ID: got.ID, Name: t.name, Type: t.typ, Value: t.value, TTL: t.ttl}
	b.remember(t, rec)
	row := store.DNSRecord{Provider: t.provider, Zone: t.zone, Name: t.name, Type: t.typ, Value: t.value,
		ProviderRecordID: got.ID, OwnerKey: t.owner, CreatedAt: b.e.now()}
	if base != nil {
		row.CreatedAt, row.RemovedAfter = base.CreatedAt, base.RemovedAfter
	}
	if err := b.e.persist(ctx, row); err != nil {
		return true, b.rollback(ctx, t, rec, base, err)
	}
	b.e.activity(ctx, "info", fmt.Sprintf("created %s %s at %s/%s (owner %s, provider id %q)", t, t.value, t.provider, t.zone, t.owner, got.ID))
	return true, nil
}

// rollback deletes a record just created whose ownership could not be
// recorded, so nothing is left that nobody would ever clean up.
func (b *dnsBatch) rollback(ctx context.Context, t dnsTarget, created dns.Record, base *store.DNSRecord, perr error) error {
	e := b.e
	bctx := context.WithoutCancel(ctx)
	e.log.ErrorContext(ctx, "DNS RECORD CREATED BUT OWNERSHIP NOT RECORDED; rolling back",
		"provider", t.provider, "zone", t.zone, "name", t.name, "type", t.typ, "id", created.ID, "error", perr)
	// Never delete a record an ownership row references (e.g. a row written
	// meanwhile under another owner). A failing read does not stop the
	// rollback: the listing proved the name was free before the create.
	if rows, err := e.st.ListOwnedRecords(bctx, t.provider, t.zone); err == nil {
		for _, r := range rows {
			if base != nil && r.OwnerKey == base.OwnerKey && normName(r.Name) == t.name && normType(r.Type) == t.typ &&
				r.ProviderRecordID == base.ProviderRecordID && r.Value == base.Value {
				continue // our own unchanged row (re-create/replace): it points at the old record, not this one
			}
			if (created.ID != "" && r.ProviderRecordID == created.ID) || (normName(r.Name) == t.name && normType(r.Type) == t.typ) {
				msg := fmt.Sprintf("created %s %s at %s/%s (provider id %q) but could not record ownership (%v); left in place because an ownership row of %s now references it",
					t, t.value, t.provider, t.zone, created.ID, perr, r.OwnerKey)
				e.activity(ctx, "error", msg)
				return errors.New(msg)
			}
		}
	}
	// Delete by the returned ID only; a provider that returned no ID gets the
	// exact (name, type, value) just created, which the Delete contract never
	// matches against a record with another value.
	del := dns.Record{ID: created.ID, Name: t.name, Type: t.typ, Value: t.value}
	if derr := e.call(bctx, func(c context.Context) error { return t.p.DeleteRecord(c, t.zone, del) }); derr != nil {
		msg := fmt.Sprintf("created %s %s at %s/%s (provider id %q) but could not record ownership (%v) and the rollback delete failed (%v): delete or adopt it by hand",
			t, t.value, t.provider, t.zone, created.ID, perr, derr)
		e.activity(ctx, "error", msg)
		return errors.New(msg)
	}
	b.forget(t, created)
	msg := fmt.Sprintf("created %s %s at %s/%s (provider id %q) but could not record ownership; rolled back", t, t.value, t.provider, t.zone, created.ID)
	e.activity(ctx, "error", fmt.Sprintf("%s (%v)", msg, perr))
	return fmt.Errorf("%s: %w", msg, perr)
}

// setRemoval persists (DNSScheduleRemoval) or clears (DNSCancelRemoval) the
// owned row's RemovedAfter, owner-guarded, without any provider call.
func (b *dnsBatch) setRemoval(ctx context.Context, t dnsTarget, a Action) error {
	if isWildcardTarget(t) {
		b.e.activity(ctx, "warn", fmt.Sprintf("refused %s for %s at %s/%s: the wildcard record is never removed automatically",
			a.Kind, t, t.provider, t.zone))
		return fmt.Errorf("%w: the wildcard record is never removed automatically", ErrDNSRefused)
	}
	var at *time.Time
	if a.Kind == DNSScheduleRemoval {
		if a.RemovedAfter == nil {
			return fmt.Errorf("%w: DNSScheduleRemoval without RemovedAfter", ErrDNSRefused)
		}
		v := *a.RemovedAfter
		at = &v
	}
	err := b.e.st.SetOwnedRemoval(ctx, t.provider, t.zone, t.name, t.typ, t.owner, at)
	if errors.Is(err, store.ErrOwnedRecordNotFound) {
		b.e.log.InfoContext(ctx, "no ownership row for this owner; nothing to (un)schedule", "kind", string(a.Kind),
			"provider", t.provider, "zone", t.zone, "name", t.name, "type", t.typ, "owner", t.owner)
		return nil
	}
	if err != nil {
		return err
	}
	if at != nil {
		b.e.activity(ctx, "info", fmt.Sprintf("scheduled removal of %s at %s/%s (owner %s) after %s: %s",
			t, t.provider, t.zone, t.owner, at.UTC().Format(time.RFC3339), a.Reason))
	} else {
		b.e.activity(ctx, "info", fmt.Sprintf("cancelled the scheduled removal of %s at %s/%s (owner %s): %s",
			t, t.provider, t.zone, t.owner, a.Reason))
	}
	return nil
}

func (b *dnsBatch) delete(ctx context.Context, t dnsTarget) error {
	if isWildcardTarget(t) {
		b.e.activity(ctx, "warn", fmt.Sprintf("refused to delete %s at %s/%s: the wildcard record is never deleted automatically",
			t, t.provider, t.zone))
		return fmt.Errorf("%w: the wildcard record is never deleted automatically", ErrDNSRefused)
	}
	row, err := b.e.ownedRow(ctx, t)
	if err != nil {
		return err
	}
	if row == nil {
		return nil // not ours (or already forgotten): never touch it
	}
	if row.OwnerKey != t.owner {
		b.e.activity(ctx, "warn", fmt.Sprintf("refused to delete %s at %s/%s: owned by %s, not %s", t, t.provider, t.zone, row.OwnerKey, t.owner))
		return fmt.Errorf("%w: owned by %s, not %s", ErrOwnerConflict, row.OwnerKey, t.owner)
	}
	stored := dns.Record{ID: row.ProviderRecordID, Name: normName(row.Name), Type: normType(row.Type), Value: row.Value}
	err = b.e.call(ctx, func(c context.Context) error { return t.p.DeleteRecord(c, t.zone, stored) })
	if err != nil && !errors.Is(err, dns.ErrNotFound) {
		return err
	}
	b.forget(t, stored)
	if err := b.e.st.DeleteOwnedRecord(context.WithoutCancel(ctx), t.provider, t.zone, t.name, t.typ); err != nil {
		return fmt.Errorf("deleted %s (provider id %q) but could not forget its ownership row: %w", t, stored.ID, err)
	}
	b.e.activity(ctx, "info", fmt.Sprintf("deleted %s %s at %s/%s (owner %s, provider id %q)", t, stored.Value, t.provider, t.zone, t.owner, stored.ID))
	return nil
}

// listing returns the batch's cached listing of t's zone, listing once.
func (b *dnsBatch) listing(ctx context.Context, t dnsTarget) *listing {
	k := t.provider + "/" + t.zone
	if l, ok := b.listings[k]; ok {
		return l
	}
	l := &listing{}
	l.err = b.e.call(ctx, func(c context.Context) (err error) { l.recs, err = t.p.ListRecords(c, t.zone); return })
	b.listings[k] = l
	return l
}

// remember adds a record just written to the cached listing (if any).
func (b *dnsBatch) remember(t dnsTarget, r dns.Record) {
	if l, ok := b.listings[t.provider+"/"+t.zone]; ok && l.err == nil {
		l.recs = append(l.recs, r)
	}
}

// forget drops a record just deleted or replaced from the cached listing.
func (b *dnsBatch) forget(t dnsTarget, r dns.Record) {
	l, ok := b.listings[t.provider+"/"+t.zone]
	if !ok || l.err != nil {
		return
	}
	out := make([]dns.Record, 0, len(l.recs))
	for _, x := range l.recs {
		same := (r.ID != "" && x.ID == r.ID) ||
			(r.ID == "" && normName(x.Name) == normName(r.Name) && normType(x.Type) == normType(r.Type) && x.Value == r.Value)
		if !same {
			out = append(out, x)
		}
	}
	l.recs = out
}

// dry records what an action would do without calling any provider or
// writing the ownership table (it reads the table to say what it would do).
func (b *dnsBatch) dry(ctx context.Context, a Action) {
	e := b.e
	t, err := e.resolve(a)
	if err != nil {
		e.activity(ctx, "warn", fmt.Sprintf("dry run: would refuse %s %s: %v", a.Kind, describe(a), err))
		return
	}
	where := t.provider + "/" + t.zone
	row, err := e.ownedRow(ctx, t)
	if err != nil {
		e.activity(ctx, "warn", fmt.Sprintf("dry run: %s %s at %s: %v", a.Kind, t, where, err))
		return
	}
	var msg string
	switch {
	case (a.Kind == DNSDelete || a.Kind == DNSScheduleRemoval || a.Kind == DNSCancelRemoval) && isWildcardTarget(t):
		msg = fmt.Sprintf("dry run: would refuse %s of wildcard record %s at %s", a.Kind, t, where)
	case (a.Kind == DNSScheduleRemoval || a.Kind == DNSCancelRemoval) && (row == nil || row.OwnerKey != t.owner):
		msg = fmt.Sprintf("dry run: nothing to change for %s %s at %s (no row owned by %s)", a.Kind, t, where, t.owner)
	case a.Kind == DNSScheduleRemoval && a.RemovedAfter == nil:
		msg = fmt.Sprintf("dry run: would refuse %s %s at %s: no RemovedAfter", a.Kind, t, where)
	case a.Kind == DNSScheduleRemoval:
		msg = fmt.Sprintf("dry run: would schedule removal of %s %s at %s (owner %s) after %s", t, row.Value, where, t.owner,
			a.RemovedAfter.UTC().Format(time.RFC3339))
	case a.Kind == DNSCancelRemoval:
		msg = fmt.Sprintf("dry run: would cancel the scheduled removal of %s at %s (owner %s)", t, where, t.owner)
	case a.Kind == DNSDelete && row == nil:
		msg = fmt.Sprintf("dry run: nothing to delete for %s at %s (not owned)", t, where)
	case a.Kind == DNSDelete && row.OwnerKey != t.owner:
		msg = fmt.Sprintf("dry run: would refuse to delete %s at %s: owned by %s", t, where, row.OwnerKey)
	case a.Kind == DNSDelete:
		msg = fmt.Sprintf("dry run: would delete %s %s at %s (provider id %q)", t, row.Value, where, row.ProviderRecordID)
	case t.value == "":
		msg = fmt.Sprintf("dry run: would refuse %s at %s: record has no value", t, where)
	case row == nil:
		msg = fmt.Sprintf("dry run: would create %s %s at %s (owner %s); pre-create foreign-record check not performed in dry run",
			t, t.value, where, t.owner)
	case row.OwnerKey != t.owner:
		msg = fmt.Sprintf("dry run: would refuse (conflict) %s at %s: owned by %s", t, where, row.OwnerKey)
	case sameValue(row.Value, t.value):
		msg = fmt.Sprintf("dry run: %s at %s already up to date", t, where)
	case row.ProviderRecordID == "" || !t.p.Capabilities().Update:
		msg = fmt.Sprintf("dry run: would replace %s at %s: %s -> %s (delete + create; pre-checks not performed in dry run)", t, where, row.Value, t.value)
	default:
		msg = fmt.Sprintf("dry run: would update %s at %s: %s -> %s (provider id %q)", t, where, row.Value, t.value, row.ProviderRecordID)
	}
	e.activity(ctx, "info", msg)
}

// call runs one provider call under the per-call timeout.
func (e *DNSExecutor) call(ctx context.Context, f func(context.Context) error) error {
	c, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	return f(c)
}

// persist writes an ownership row, retrying once on an error other than an
// owner conflict. ctx cancellation does not stop it: the provider write
// already happened.
func (e *DNSExecutor) persist(ctx context.Context, r store.DNSRecord) error {
	c := context.WithoutCancel(ctx)
	err := e.st.AddOwnedRecord(c, r)
	if err == nil || errors.Is(err, store.ErrOwnerConflict) {
		return err
	}
	e.log.WarnContext(ctx, "recording DNS ownership failed; retrying once", "provider", r.Provider, "zone", r.Zone,
		"name", r.Name, "type", r.Type, "error", err)
	return e.st.AddOwnedRecord(c, r)
}

// activity logs msg and appends it to the activity sink (kind "dns").
func (e *DNSExecutor) activity(ctx context.Context, level, msg string) {
	switch level {
	case "error":
		e.log.ErrorContext(ctx, msg)
	case "warn":
		e.log.WarnContext(ctx, msg)
	default:
		e.log.InfoContext(ctx, msg)
	}
	if e.act == nil {
		return
	}
	if err := e.act.AppendActivity(context.WithoutCancel(ctx), store.ActivityEntry{TS: e.now(), Level: level, Kind: "dns", Message: msg}); err != nil {
		e.log.WarnContext(ctx, "recording activity failed", "error", err)
	}
}

// ZoneRef names one provider/zone pair whose records are managed.
type ZoneRef struct{ Provider, Zone string }

// DNSZoneRefs returns the (provider, normalized zone) pairs of every zone with
// records mode wildcard or per-host and a provider, deduplicated (first zone
// definition wins, as in Plan) and sorted: the pairs the caller passes to
// GatherObserved each cycle.
func DNSZoneRefs(cfg *config.Config) []ZoneRef {
	if cfg == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []ZoneRef
	for _, z := range cfg.Zones {
		n := normName(z.Name)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if (z.Records.Mode == "wildcard" || z.Records.Mode == "per-host") && z.Records.Provider != "" {
			out = append(out, ZoneRef{Provider: z.Records.Provider, Zone: n})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Zone != out[j].Zone {
			return out[i].Zone < out[j].Zone
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

// GatherObserved builds Observed.Owned and Observed.Foreign for the given
// provider/zone pairs (deduplicated after normalizing the zone). owned holds
// the ownership rows of every pair whose rows could be read. foreign is keyed
// provider+"/"+zone and holds the provider's listing minus the records that
// have an ownership row (matched on normalized name and type), records of
// every type included, names and types normalized. A pair whose listing or
// ownership rows could not be read, or whose provider is missing, is ABSENT
// from foreign (unknown: Plan then creates nothing there) and its error is
// returned in errs. A successful empty listing is present and empty. Each
// listing runs under timeout (0 means DefaultDNSCallTimeout).
func GatherObserved(ctx context.Context, providers map[string]dns.Provider, st OwnershipStore, zones []ZoneRef,
	timeout time.Duration) (owned []store.DNSRecord, foreign map[string][]dns.Record, errs []error) {
	if timeout <= 0 {
		timeout = DefaultDNSCallTimeout
	}
	foreign = map[string][]dns.Record{}
	seen := map[string]bool{}
	for _, zr := range zones {
		zn := normName(zr.Zone)
		key := zr.Provider + "/" + zn
		if zn == "" || seen[key] {
			continue
		}
		seen[key] = true
		if st == nil {
			errs = append(errs, fmt.Errorf("%s: no ownership store", key))
			continue
		}
		rows, err := st.ListOwnedRecords(ctx, zr.Provider, zn)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: reading ownership rows: %w", key, err))
			continue
		}
		owned = append(owned, rows...)
		p := providers[zr.Provider]
		if p == nil {
			errs = append(errs, fmt.Errorf("%s: provider %q is not available", key, zr.Provider))
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, timeout)
		recs, err := p.ListRecords(lctx, zn)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: listing records: %w", key, err))
			continue
		}
		mine := map[string]bool{}
		for _, r := range rows {
			mine[normName(r.Name)+" "+normType(r.Type)] = true
		}
		out := make([]dns.Record, 0, len(recs))
		for _, r := range recs {
			r.Name, r.Type = normName(r.Name), normType(r.Type)
			if !mine[r.Name+" "+r.Type] {
				out = append(out, r)
			}
		}
		foreign[key] = out
	}
	return owned, foreign, errs
}
