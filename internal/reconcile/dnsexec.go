package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
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
	// ListAllOwnedRecords returns every ownership row, of every provider
	// and zone (GatherObserved's Owned).
	ListAllOwnedRecords(ctx context.Context) ([]store.DNSRecord, error)
	// DeleteOwnedRecordIfDue deletes the row only if it is owned by owner and
	// its removed_after is set and strictly before notAfter.
	DeleteOwnedRecordIfDue(ctx context.Context, provider, zone, name, typ, owner string, notAfter time.Time) (bool, error)
	// SetOwnedRemoval sets or clears removed_after of the row, only if its
	// owner key equals owner (store.ErrOwnedRecordNotFound otherwise).
	SetOwnedRemoval(ctx context.Context, provider, zone, name, typ, owner string, at *time.Time) error
	// ReassignOwnedRecord moves the row from oldOwner to newOwner and clears
	// its removed_after (store.ErrOwnedRecordNotFound when oldOwner does not
	// own it).
	ReassignOwnedRecord(ctx context.Context, provider, zone, name, typ, oldOwner, newOwner string) error
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
	// RepairState keeps the drift-repair backoff (kv). nil means Store, when
	// it implements RepairStateStore (*store.Store does); without either,
	// every repair is refused.
	RepairState RepairStateStore
}

// RepairStateStore is a small key/value store (*store.Store implements it
// with its kv table) holding the per-record drift-repair backoff.
type RepairStateStore interface {
	GetSetting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
	DeleteSetting(ctx context.Context, key string) error
}

type dnsZone struct{ name, provider, mode string }

// DNSExecutor applies every kind in DNSActionKinds: DNSEnsure, DNSDelete,
// DNSScheduleRemoval, DNSCancelRemoval and DNSReassign. It only ever updates
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
// DNSEnsure with Repair (an owned record the listing showed missing): the
// sameValue early return is bypassed. The stored row must still match the
// action (owner, value, provider ID, no schedule), the per-record backoff
// must be due, and a listing refreshed once per batch and provider/zone (by
// the pair's first repair) must show neither our record (present: no-op,
// backoff reset) nor any record blocking the name (Conflict,
// ErrForeignRecord); then the guarded create re-creates it and refreshes the
// same row. See the package documentation, "Drift repair".
//
// DNSDelete: only a row for (provider, zone, name, type) whose owner key
// equals Action.Owner is deleted, using the STORED ID, name, type and value
// (never the action's). No row: no-op, no provider call. The plan may be
// stale (Observed is gathered outside the Runner's lock), so the row is
// re-read and the delete runs only if the row still has exactly the
// schedule the action was planned for (Action.RemovedAfter, required) and
// that schedule is due at the executor's now; otherwise nothing happens
// (an info activity says why). The provider delete comes first, then the
// row is deleted with store.DeleteOwnedRecordIfDue (owner and due schedule
// re-checked in the DELETE itself). If that finds the row changed in
// between, the record is already gone at the provider: the row is kept,
// its value and provider ID are blanked so the next plan's DNSEnsure
// re-creates the record, and an error activity says so. The wildcard
// record (owner key "zone:...", or a "*." name) is never deleted: such an
// action is refused with ErrDNSRefused (Action has no Force flag; a later
// UI path must use its own call). dns.ErrNotFound or nil from the provider
// forgets the row; any other error keeps it (the row, still past its
// RemovedAfter, makes the next Plan emit the DNSDelete again).
//
// DNSReassign: no provider call. The row is moved from Action.Owner to
// Action.NewOwner and its RemovedAfter cleared (store.ReassignOwnedRecord,
// guarded by the old owner), only if the stored row still has the old owner
// and the action's value, and only to a valid, Published, non-"zone:" new
// owner carried in Action.Svc; the wildcard record is refused.
//
// DNSScheduleRemoval / DNSCancelRemoval: no provider call. The row for
// (provider, zone, name, type) gets RemovedAfter = Action.RemovedAfter
// (required for schedule) or nil, only if its owner key equals
// Action.Owner (store.SetOwnedRemoval). The row is re-read first and
// nothing changes unless it still matches what the plan saw: same owner,
// same value, and unscheduled (schedule; an existing schedule is never
// moved) or scheduled (cancel). No such row is a no-op. The wildcard record
// is refused with ErrDNSRefused, like its delete.
//
// Every action must name a zone configured with records mode wildcard or
// per-host, that zone's records provider, and a record name equal to the
// zone or inside it; otherwise it is refused with ErrDNSRefused. Names,
// types and zones are normalized (lowercase, no trailing dot; uppercase
// type) before every provider and store call. TTL is passed through.
//
// dns.ErrUnconfirmed (the provider accepted a write, or may have applied
// it, but could not confirm it): a CreateRecord answering it with a record
// that names the target (same name and type, and the target value or no
// value) counts as created: the ownership row is written with the target
// value and that record's provider ID (which may be empty),
// the action succeeds, a warn activity says "write accepted but
// unconfirmed; will verify on a later cycle" and LastWarnings lists it; the
// next cycles' drift check verifies the record exists (Repair above). This
// holds for a plain create, a re-create, the create step of a replace and a
// restore. An UpdateRecord answering it with such a record keeps the row's
// OLD value (storing the returned provider ID, if any, and a pending update
// in kv, see the package documentation) so the next plan repeats the
// update; the update is idempotent if it landed. Without a
// usable record the outcome is ambiguous: the error is returned, no row is
// written or changed, an error activity says so, and a replace does not
// restore the old value (the new one may exist). A DeleteRecord answering
// it keeps the ownership row and its schedule (the next plan deletes again);
// a rollback delete answering it reports that the record may remain without
// an owner.
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
	repairKV  RepairStateStore

	mu       sync.Mutex // serializes Apply (the Runner already does)
	warnings []DNSWarning
	sweptAt  time.Time // last sweepRepairState
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
	e.repairKV = cfg.RepairState
	if e.repairKV == nil {
		e.repairKV, _ = cfg.Store.(RepairStateStore)
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
	// repairListed: provider/zone pairs a repair already re-listed in this
	// batch; later repairs of the pair use the cached listing (kept current
	// by remember/forget).
	repairListed map[string]bool
}

// Apply implements Executor; kinds not in DNSActionKinds are ignored.
func (e *DNSExecutor) Apply(ctx context.Context, actions []Action, dryRun bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := &dnsBatch{e: e, listings: map[string]*listing{}, repairListed: map[string]bool{}}
	if !dryRun {
		e.warnings = nil
		e.sweepRepairState(ctx)
	}
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

// DNSActionKinds are every kind the DNS executor applies. Register the DNS
// executor for all of them (RegisterDNSExecutor); a missing one makes
// MultiExecutor fail that batch with ErrNoExecutor.
var DNSActionKinds = []ActionKind{DNSEnsure, DNSDelete, DNSScheduleRemoval, DNSCancelRemoval, DNSReassign}

// RegisterDNSExecutor registers e for every kind in DNSActionKinds and
// returns m.
func RegisterDNSExecutor(m *MultiExecutor, e Executor) *MultiExecutor {
	for _, k := range DNSActionKinds {
		m.Handle(k, e)
	}
	return m
}

func isDNSKind(k ActionKind) bool {
	for _, d := range DNSActionKinds {
		if k == d {
			return true
		}
	}
	return false
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
		return b.delete(ctx, t, a)
	case DNSScheduleRemoval, DNSCancelRemoval:
		return b.setRemoval(ctx, t, a)
	case DNSReassign:
		return b.reassign(ctx, t, a)
	}
	if a.Repair {
		return b.repair(ctx, t, a)
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
	if pu, ok := b.e.pendingUpdate(ctx, t); errors.Is(err, dns.ErrNotFound) && ok && pu.OldID != "" && pu.OldID != rec.ID {
		// An unconfirmed update gave the row a provider ID that does not
		// exist: the update did not land and our record may still be the one
		// under the ID the row held before. Update that one (it is ours by
		// ID) instead of re-creating next to it, which would find it and
		// refuse it as foreign every cycle.
		b.e.log.WarnContext(ctx, "owned DNS record not found under the id an unconfirmed update returned; updating it under its previous id",
			"provider", t.provider, "zone", t.zone, "name", t.name, "type", t.typ, "id", rec.ID, "previous_id", pu.OldID)
		rec.ID, stored.ID = pu.OldID, pu.OldID
		err = b.e.call(ctx, func(c context.Context) (err error) { got, err = t.p.UpdateRecord(c, t.zone, rec); return })
	}
	if errors.Is(err, dns.ErrNotFound) {
		b.e.log.WarnContext(ctx, "owned DNS record is gone at the provider; re-creating after a foreign-record check",
			"provider", t.provider, "zone", t.zone, "name", t.name, "type", t.typ, "id", row.ProviderRecordID)
		b.forget(t, stored)
		return b.create(ctx, t, row)
	}
	if errors.Is(err, dns.ErrUnconfirmed) {
		return b.updateUnconfirmed(ctx, t, row, rec.ID, got, err)
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
	b.e.clearKV(ctx, pendingKey(t.provider, t.zone, t.name, t.typ))
	b.e.activity(ctx, "info", fmt.Sprintf("updated %s at %s/%s: %s -> %s (owner %s, provider id %q)", t, t.provider, t.zone, row.Value, t.value, t.owner, id))
	return nil
}

// updateUnconfirmed handles an UpdateRecord that answered
// dns.ErrUnconfirmed. With a record naming t the row KEEPS its old value (its
// provider ID becomes the returned one, when there is one), so the next plan
// sees the value still differs and sends the same update again: idempotent
// if it landed, completing it if it did not. Recording the new value instead
// would hide an update that never landed (the value is then never checked
// again). Without such a record nothing changes and the error is returned.
// sentID is the provider ID the update was sent to; it is kept as a pending
// update (kv, see pendingUpdate) so that, if the provider returned a new ID
// but the update did not land, the next update can still reach the record.
func (b *dnsBatch) updateUnconfirmed(ctx context.Context, t dnsTarget, row *store.DNSRecord, sentID string, got dns.Record, uerr error) error {
	delete(b.listings, t.provider+"/"+t.zone) // which value is live is unknown
	w, ok := unconfirmedRecord(t, got)
	if !ok {
		b.ambiguous(ctx, "update", t, t.value, uerr, fmt.Sprintf("the ownership row keeps value %s; the next cycle updates again", row.Value))
		return uerr
	}
	b.e.recordPendingUpdate(ctx, t, pendingUpdate{Value: t.value, OldID: sentID, NewID: w.ID, At: b.e.now().Unix()})
	if w.ID != "" && w.ID != row.ProviderRecordID {
		nr := *row
		nr.Zone, nr.Name, nr.Type, nr.ProviderRecordID = t.zone, t.name, t.typ, w.ID
		if err := b.e.persist(ctx, nr); err != nil {
			b.e.activity(ctx, "error", fmt.Sprintf("updating %s at %s/%s to %s is unconfirmed (new provider id %q) and its ownership row could not be updated: %v",
				t, t.provider, t.zone, w.Value, w.ID, err))
			return fmt.Errorf("unconfirmed update of %s (new provider id %q): ownership row not updated: %w", t, w.ID, err)
		}
	}
	b.unconfirmed(ctx, "update", t, w, uerr, fmt.Sprintf("updating %s at %s/%s: %s -> %s (owner %s, provider id %q); the row keeps %s until a later cycle repeats the update",
		t, t.provider, t.zone, row.Value, w.Value, t.owner, w.ID, row.Value))
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
		if err != nil && (errors.Is(err, dns.ErrUnconfirmed) || !errors.Is(err, dns.ErrNotFound)) {
			if errors.Is(err, dns.ErrUnconfirmed) {
				delete(b.listings, t.provider+"/"+t.zone) // it may or may not be gone
			}
			return fmt.Errorf("deleting the old record (value %s, id %q) failed: %w", stored.Value, stored.ID, err)
		}
		b.forget(t, stored)
	}
	created, err := b.doCreate(ctx, t, row)
	if err == nil || created || !ownPresent || errors.Is(err, ErrForeignRecord) {
		return err
	}
	if errors.Is(err, dns.ErrUnconfirmed) {
		// The new value may exist: re-creating the old one could leave two
		// values at the name. The row is left as it is (old value); the next
		// cycle re-checks the name with a fresh listing.
		b.e.activity(ctx, "error", fmt.Sprintf("replacing %s at %s/%s: old value %s deleted, creating %s is unconfirmed (%v); not restoring the old value",
			t, t.provider, t.zone, row.Value, t.value, err))
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
	var uerr error
	if errors.Is(rerr, dns.ErrUnconfirmed) {
		if w, ok := unconfirmedRecord(dnsTarget{name: t.name, typ: t.typ, value: row.Value, ttl: t.ttl}, got); ok {
			got, uerr, rerr = w, rerr, nil
		} else {
			delete(b.listings, t.provider+"/"+t.zone)
		}
	}
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
	if uerr != nil {
		b.unconfirmed(ctx, "restore", t, got, uerr, fmt.Sprintf("restored %s %s at %s/%s (provider id %q)", t, row.Value, t.provider, t.zone, got.ID))
	}
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
	rec := dns.Record{ID: got.ID, Name: t.name, Type: t.typ, Value: t.value, TTL: t.ttl}
	var uerr error
	if errors.Is(err, dns.ErrUnconfirmed) {
		w, ok := unconfirmedRecord(t, got)
		if !ok {
			delete(b.listings, t.provider+"/"+t.zone) // the record may exist now
			b.ambiguous(ctx, "create", t, t.value, err, "NO ownership row was written; if the record exists it shows as foreign until adopted or removed")
			return false, err
		}
		rec, uerr, err = w, err, nil
	}
	if err != nil {
		return false, err
	}
	b.remember(t, rec)
	row := store.DNSRecord{Provider: t.provider, Zone: t.zone, Name: t.name, Type: t.typ, Value: rec.Value,
		ProviderRecordID: rec.ID, OwnerKey: t.owner, CreatedAt: b.e.now()}
	if base != nil {
		row.CreatedAt, row.RemovedAfter = base.CreatedAt, base.RemovedAfter
	}
	if err := b.e.persist(ctx, row); err != nil {
		return true, b.rollback(ctx, t, rec, base, err)
	}
	what := fmt.Sprintf("created %s %s at %s/%s (owner %s, provider id %q)", t, rec.Value, t.provider, t.zone, t.owner, rec.ID)
	if uerr != nil {
		b.unconfirmed(ctx, "create", t, rec, uerr, what)
		return true, nil
	}
	if base != nil {
		b.e.clearKV(ctx, pendingKey(t.provider, t.zone, t.name, t.typ)) // the row names a confirmed record now
	}
	b.e.activity(ctx, "info", what)
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
					t, created.Value, t.provider, t.zone, created.ID, perr, r.OwnerKey)
				e.activity(ctx, "error", msg)
				return errors.New(msg)
			}
		}
	}
	// Delete by the returned ID only; a provider that returned no ID gets the
	// exact (name, type, value) just created, which the Delete contract never
	// matches against a record with another value.
	del := dns.Record{ID: created.ID, Name: t.name, Type: t.typ, Value: created.Value}
	derr := e.call(bctx, func(c context.Context) error { return t.p.DeleteRecord(c, t.zone, del) })
	if errors.Is(derr, dns.ErrUnconfirmed) {
		// never claim the rollback happened, and keep the record in the
		// batch listing: it may still exist, owned by nobody
		msg := fmt.Sprintf("created %s %s at %s/%s (provider id %q) but could not record ownership (%v); the rollback delete was not confirmed, so the record may still exist without an owner: delete or adopt it by hand",
			t, created.Value, t.provider, t.zone, created.ID, perr)
		e.activity(ctx, "error", msg)
		return fmt.Errorf("%s: %w", msg, derr)
	}
	if derr != nil {
		msg := fmt.Sprintf("created %s %s at %s/%s (provider id %q) but could not record ownership (%v) and the rollback delete failed (%v): delete or adopt it by hand",
			t, created.Value, t.provider, t.zone, created.ID, perr, derr)
		e.activity(ctx, "error", msg)
		return errors.New(msg)
	}
	b.forget(t, created)
	msg := fmt.Sprintf("created %s %s at %s/%s (provider id %q) but could not record ownership; rolled back", t, created.Value, t.provider, t.zone, created.ID)
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
	// The plan may be stale: re-read the row and act only on the state the
	// plan saw (same owner and value; unscheduled for a schedule, scheduled
	// for a cancel). Otherwise the next plan decides again.
	row, err := b.e.ownedRow(ctx, t)
	if err != nil {
		return err
	}
	if why := removalStale(row, t, a.Kind); why != "" {
		b.e.log.InfoContext(ctx, "not changing the removal schedule: the stored row changed since the plan", "kind", string(a.Kind),
			"provider", t.provider, "zone", t.zone, "name", t.name, "type", t.typ, "owner", t.owner, "why", why)
		return nil
	}
	err = b.e.st.SetOwnedRemoval(ctx, t.provider, t.zone, t.name, t.typ, t.owner, at)
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

// reassignRefusal returns why a DNSReassign must be refused outright, or "".
func reassignRefusal(t dnsTarget, a Action) string {
	no := strings.TrimSpace(a.NewOwner)
	switch {
	case isWildcardTarget(t):
		return "the wildcard record's owner never changes"
	case no == "" || no != a.NewOwner:
		return "no valid new owner key"
	case strings.HasPrefix(strings.ToLower(no), "zone:"):
		return "a zone owner key may own only the wildcard record"
	case no == t.owner:
		return "new owner equals the current owner"
	case a.Svc == nil || a.Svc.Key != no:
		return "the action does not carry the new owner's service"
	case a.Svc.State != model.StatePublished:
		return "the new owner is not Published"
	case t.value == "":
		return "the action names no stored value"
	}
	return ""
}

// reassign transfers t's ownership row from t.owner to a.NewOwner (no
// provider call), only if the row still has the owner and value the plan
// saw.
func (b *dnsBatch) reassign(ctx context.Context, t dnsTarget, a Action) error {
	if why := reassignRefusal(t, a); why != "" {
		b.e.activity(ctx, "warn", fmt.Sprintf("refused to reassign %s at %s/%s from %s to %q: %s", t, t.provider, t.zone, t.owner, a.NewOwner, why))
		return fmt.Errorf("%w: %s", ErrDNSRefused, why)
	}
	row, err := b.e.ownedRow(ctx, t)
	if err != nil {
		return err
	}
	if why := reassignStale(row, t); why != "" {
		b.e.log.InfoContext(ctx, "not reassigning: the stored row changed since the plan", "provider", t.provider, "zone", t.zone,
			"name", t.name, "type", t.typ, "owner", t.owner, "new_owner", a.NewOwner, "why", why)
		return nil
	}
	err = b.e.st.ReassignOwnedRecord(ctx, t.provider, t.zone, t.name, t.typ, t.owner, a.NewOwner)
	if errors.Is(err, store.ErrOwnedRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	b.e.activity(ctx, "info", fmt.Sprintf("reassigned %s %s at %s/%s from %s to %s (record unchanged): %s",
		t, row.Value, t.provider, t.zone, t.owner, a.NewOwner, a.Reason))
	return nil
}

// reassignStale returns why a DNSReassign no longer matches row, or "".
func reassignStale(row *store.DNSRecord, t dnsTarget) string {
	switch {
	case row == nil:
		return "no ownership row"
	case row.OwnerKey != t.owner:
		return "owned by " + row.OwnerKey
	case !sameValue(row.Value, t.value):
		return "value is now " + row.Value
	}
	return ""
}

// removalStale returns why a DNSScheduleRemoval/DNSCancelRemoval no longer
// matches the stored row (row nil when there is none), or "" when it does.
func removalStale(row *store.DNSRecord, t dnsTarget, k ActionKind) string {
	switch {
	case row == nil:
		return "no ownership row"
	case row.OwnerKey != t.owner:
		return "owned by " + row.OwnerKey
	case !sameValue(row.Value, t.value):
		return "value is now " + row.Value
	case k == DNSScheduleRemoval && row.RemovedAfter != nil:
		return "already scheduled for " + row.RemovedAfter.UTC().Format(time.RFC3339) + "; not moving it"
	case k == DNSCancelRemoval && row.RemovedAfter == nil:
		return "not scheduled"
	}
	return ""
}

// deleteStale returns why a DNSDelete planned for schedule planned must not
// run against row (owned by the action's owner) at now, or "" when the row
// still has exactly that schedule and it is due. Times compare in whole
// seconds, the store's precision (as store.DeleteOwnedRecordIfDue does).
func deleteStale(row *store.DNSRecord, planned, now time.Time) string {
	switch {
	case row.RemovedAfter == nil:
		return "its removal is not scheduled (cancelled since the plan)"
	case row.RemovedAfter.Unix() != planned.Unix():
		return fmt.Sprintf("its removal is now scheduled for %s; the delete was planned for %s",
			row.RemovedAfter.UTC().Format(time.RFC3339), planned.UTC().Format(time.RFC3339))
	case row.RemovedAfter.Unix() >= now.Unix():
		return "its removal is not due until " + row.RemovedAfter.UTC().Format(time.RFC3339)
	}
	return ""
}

func (b *dnsBatch) delete(ctx context.Context, t dnsTarget, a Action) error {
	if isWildcardTarget(t) {
		b.e.activity(ctx, "warn", fmt.Sprintf("refused to delete %s at %s/%s: the wildcard record is never deleted automatically",
			t, t.provider, t.zone))
		return fmt.Errorf("%w: the wildcard record is never deleted automatically", ErrDNSRefused)
	}
	if a.RemovedAfter == nil {
		return fmt.Errorf("%w: DNSDelete without the schedule it was planned for (RemovedAfter)", ErrDNSRefused)
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
	now := b.e.now()
	if why := deleteStale(row, *a.RemovedAfter, now); why != "" {
		b.e.activity(ctx, "info", fmt.Sprintf("not deleting %s at %s/%s (owner %s): %s", t, t.provider, t.zone, t.owner, why))
		return nil
	}
	stored := dns.Record{ID: row.ProviderRecordID, Name: normName(row.Name), Type: normType(row.Type), Value: row.Value}
	if stored.ID != "" || strings.TrimSpace(stored.Value) != "" {
		err = b.e.call(ctx, func(c context.Context) error { return t.p.DeleteRecord(c, t.zone, stored) })
		if errors.Is(err, dns.ErrUnconfirmed) {
			// The record may or may not be gone yet: keep the row (and its
			// schedule), so the next plan emits the DNSDelete again.
			b.e.activity(ctx, "warn", fmt.Sprintf("deleting %s %s at %s/%s (provider id %q) was not confirmed; keeping its ownership row, the next cycle deletes it again: %v",
				t, stored.Value, t.provider, t.zone, stored.ID, err))
			return err
		}
		if err != nil && !errors.Is(err, dns.ErrNotFound) {
			return err
		}
		b.forget(t, stored)
	}
	// else: a blanked row (its record is already known to be gone, see
	// rowChangedAfterDelete): never send a delete without an ID or a value.
	bctx := context.WithoutCancel(ctx)
	deleted, err := b.e.st.DeleteOwnedRecordIfDue(bctx, t.provider, t.zone, t.name, t.typ, t.owner, now)
	if err != nil {
		return b.rowNotForgotten(bctx, t, stored, err)
	}
	if !deleted {
		return b.rowChangedAfterDelete(bctx, t, stored)
	}
	b.e.clearKV(ctx, repairKey(t.provider, t.zone, t.name, t.typ), pendingKey(t.provider, t.zone, t.name, t.typ))
	b.e.activity(ctx, "info", fmt.Sprintf("deleted %s %s at %s/%s (owner %s, provider id %q)", t, stored.Value, t.provider, t.zone, t.owner, stored.ID))
	return nil
}

// rowNotForgotten handles a store error from the conditional row delete
// after the provider delete: the record is gone but the row still claims it.
// Like rowChangedAfterDelete the row's value and provider ID are blanked
// (best effort: the store just failed), so neither a returning owner (whose
// plan then sees another value and re-creates through the guarded path) nor
// the next DNSDelete (which then forgets the row without a provider call)
// relies on a record that no longer exists.
func (b *dnsBatch) rowNotForgotten(ctx context.Context, t dnsTarget, stored dns.Record, serr error) error {
	msg := fmt.Sprintf("DELETED %s %s at %s/%s (provider id %q) BUT COULD NOT FORGET ITS OWNERSHIP ROW (%v)",
		t, stored.Value, t.provider, t.zone, stored.ID, serr)
	if stored.ID != "" || stored.Value != "" {
		b.blankRow(ctx, t, stored, &msg)
	}
	b.e.activity(ctx, "error", msg)
	return fmt.Errorf("deleted %s (provider id %q) but could not forget its ownership row: %w", t, stored.ID, serr)
}

// blankRow clears the value and provider ID of t's row (keeping owner and
// schedule) if it still names stored, appending a failure note to msg.
func (b *dnsBatch) blankRow(ctx context.Context, t dnsTarget, stored dns.Record, msg *string) {
	cur, err := b.e.ownedRow(ctx, t)
	if err != nil {
		*msg += fmt.Sprintf(" (marking the row for re-creation failed: %v)", err)
		return
	}
	if cur == nil || cur.Value != stored.Value || cur.ProviderRecordID != stored.ID {
		return
	}
	nr := *cur
	nr.Value, nr.ProviderRecordID = "", ""
	if perr := b.e.persist(ctx, nr); perr != nil {
		*msg += fmt.Sprintf(" (marking the row for re-creation failed: %v)", perr)
	}
}

// rowChangedAfterDelete handles a row that changed (removal cancelled or
// re-scheduled, or re-owned) between its provider delete and the
// conditional row delete: the record is gone at the provider but the row
// says it is wanted. The row's value and provider ID are blanked (keeping
// owner and schedule), so the next plan sees a different value and its
// DNSEnsure re-creates the record through the guarded create path.
func (b *dnsBatch) rowChangedAfterDelete(ctx context.Context, t dnsTarget, stored dns.Record) error {
	msg := fmt.Sprintf("DELETED %s %s at %s/%s (provider id %q) BUT ITS OWNERSHIP ROW CHANGED meanwhile (removal cancelled, re-scheduled or re-owned); the row is kept and the next cycle re-creates the record",
		t, stored.Value, t.provider, t.zone, stored.ID)
	b.blankRow(ctx, t, stored, &msg)
	b.e.activity(ctx, "error", msg)
	return errors.New("row changed during the delete: " + msg)
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
	case a.Kind == DNSReassign && reassignRefusal(t, a) != "":
		msg = fmt.Sprintf("dry run: would refuse to reassign %s at %s: %s", t, where, reassignRefusal(t, a))
	case a.Kind == DNSReassign && reassignStale(row, t) != "":
		msg = fmt.Sprintf("dry run: nothing to reassign for %s at %s (%s)", t, where, reassignStale(row, t))
	case a.Kind == DNSReassign:
		msg = fmt.Sprintf("dry run: would reassign %s %s at %s from %s to %s (no provider change)", t, row.Value, where, t.owner, a.NewOwner)
	case (a.Kind == DNSDelete || a.Kind == DNSScheduleRemoval || a.Kind == DNSCancelRemoval) && isWildcardTarget(t):
		msg = fmt.Sprintf("dry run: would refuse %s of wildcard record %s at %s", a.Kind, t, where)
	case (a.Kind == DNSScheduleRemoval || a.Kind == DNSCancelRemoval) && (row == nil || row.OwnerKey != t.owner):
		msg = fmt.Sprintf("dry run: nothing to change for %s %s at %s (no row owned by %s)", a.Kind, t, where, t.owner)
	case a.Kind == DNSScheduleRemoval && a.RemovedAfter == nil:
		msg = fmt.Sprintf("dry run: would refuse %s %s at %s: no RemovedAfter", a.Kind, t, where)
	case (a.Kind == DNSScheduleRemoval || a.Kind == DNSCancelRemoval) && removalStale(row, t, a.Kind) != "":
		msg = fmt.Sprintf("dry run: nothing to change for %s %s at %s (%s)", a.Kind, t, where, removalStale(row, t, a.Kind))
	case a.Kind == DNSScheduleRemoval:
		msg = fmt.Sprintf("dry run: would schedule removal of %s %s at %s (owner %s) after %s", t, row.Value, where, t.owner,
			a.RemovedAfter.UTC().Format(time.RFC3339))
	case a.Kind == DNSCancelRemoval:
		msg = fmt.Sprintf("dry run: would cancel the scheduled removal of %s at %s (owner %s)", t, where, t.owner)
	case a.Kind == DNSDelete && row == nil:
		msg = fmt.Sprintf("dry run: nothing to delete for %s at %s (not owned)", t, where)
	case a.Kind == DNSDelete && row.OwnerKey != t.owner:
		msg = fmt.Sprintf("dry run: would refuse to delete %s at %s: owned by %s", t, where, row.OwnerKey)
	case a.Kind == DNSDelete && a.RemovedAfter == nil:
		msg = fmt.Sprintf("dry run: would refuse to delete %s at %s: the action names no schedule", t, where)
	case a.Kind == DNSDelete && deleteStale(row, *a.RemovedAfter, e.now()) != "":
		msg = fmt.Sprintf("dry run: would not delete %s at %s: %s", t, where, deleteStale(row, *a.RemovedAfter, e.now()))
	case a.Kind == DNSDelete:
		msg = fmt.Sprintf("dry run: would delete %s %s at %s (provider id %q)", t, row.Value, where, row.ProviderRecordID)
	case t.value == "":
		msg = fmt.Sprintf("dry run: would refuse %s at %s: record has no value", t, where)
	case a.Repair && repairStale(row, t, a) != "":
		msg = fmt.Sprintf("dry run: would not re-create %s at %s: %s", t, where, repairStale(row, t, a))
	case a.Repair:
		msg = fmt.Sprintf("dry run: would re-create missing owned record %s %s at %s (owner %s), subject to its backoff; foreign-record check not performed in dry run",
			t, t.value, where, t.owner)
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

// Drift repair backoff: attempts are spaced repairBackoffMin << (attempts-1),
// capped at repairBackoffMax; a state older than repairStateStale (since its
// last attempt) is ignored, so a new incident starts again at the minimum.
const (
	repairBackoffMin = time.Minute
	repairBackoffMax = time.Hour
	repairStateStale = 2 * time.Hour
)

// repairState is the kv value under repairKey (unix seconds).
type repairState struct {
	Attempts int   `json:"attempts"`
	NextAt   int64 `json:"next_at"`
	LastAt   int64 `json:"last_at"`
}

// repairKey is the kv key of a record's repair backoff.
func repairKey(provider, zone, name, typ string) string {
	return "dns/repair/" + provider + "/" + normName(zone) + "/" + normName(name) + "/" + normType(typ)
}

func repairDelay(attempts int) time.Duration {
	if attempts < 1 {
		return 0
	}
	if attempts > 7 { // 1m << 6 already exceeds the cap
		return repairBackoffMax
	}
	return min(repairBackoffMin<<(attempts-1), repairBackoffMax)
}

// repairStale reports why a Repair action no longer matches the stored row
// ("" when it does): the row must exist, belong to the action's owner, hold
// the action's value and provider ID (Record.ID) and have no removal
// scheduled.
func repairStale(row *store.DNSRecord, t dnsTarget, a Action) string {
	switch {
	case row == nil:
		return "no ownership row"
	case row.OwnerKey != t.owner:
		return "owned by " + row.OwnerKey + ", not " + t.owner
	case !sameValue(row.Value, t.value):
		return "the stored value is now " + row.Value
	case strings.TrimSpace(a.Record.ID) != row.ProviderRecordID:
		return fmt.Sprintf("the stored provider id is now %q", row.ProviderRecordID)
	case row.RemovedAfter != nil:
		return "its removal is scheduled"
	}
	return ""
}

// repair re-creates an owned record a listing showed missing (a DNSEnsure
// with Repair). Unlike a plain ensure it does not stop at an up-to-date
// row: after the stale-plan check and the backoff it re-lists the zone
// (once per batch and provider/zone);
// our record present (by stored ID, or by value when the row has none) is a
// no-op that resets the backoff; any other record blocking the name is a
// Conflict (ErrForeignRecord); otherwise the guarded create runs and the
// same row is refreshed. Every attempt that reaches the listing counts.
func (b *dnsBatch) repair(ctx context.Context, t dnsTarget, a Action) error {
	e := b.e
	if t.value == "" {
		return fmt.Errorf("%w: record has no value", ErrDNSRefused)
	}
	row, err := e.ownedRow(ctx, t)
	if err != nil {
		return err
	}
	if why := repairStale(row, t, a); why != "" {
		e.activity(ctx, "info", fmt.Sprintf("not re-creating %s at %s/%s: %s (the plan is stale)", t, t.provider, t.zone, why))
		return nil
	}
	if e.repairKV == nil {
		e.activity(ctx, "warn", fmt.Sprintf("refused to re-create missing %s at %s/%s: no store for the repair backoff", t, t.provider, t.zone))
		return fmt.Errorf("%w: no repair backoff store", ErrDNSRefused)
	}
	key := repairKey(t.provider, t.zone, t.name, t.typ)
	now := e.now()
	st, err := loadRepairState(ctx, e.repairKV, key, now)
	if err != nil {
		return fmt.Errorf("reading the repair backoff of %s: %w", t, err) // never unbounded
	}
	if st.Attempts > 0 && now.Unix() < st.NextAt {
		e.log.DebugContext(ctx, "owned DNS record missing; repair not due yet", "provider", t.provider, "zone", t.zone,
			"name", t.name, "type", t.typ, "attempts", st.Attempts, "next_at", time.Unix(st.NextAt, 0).UTC())
		return nil
	}
	bump := func() error {
		st.Attempts++
		st.LastAt, st.NextAt = now.Unix(), now.Add(repairDelay(st.Attempts)).Unix()
		v, _ := json.Marshal(st)
		if err := e.repairKV.SetSetting(context.WithoutCancel(ctx), key, string(v)); err != nil {
			return fmt.Errorf("recording the repair attempt of %s: %w", t, err)
		}
		return nil
	}
	if pk := t.provider + "/" + t.zone; !b.repairListed[pk] {
		// re-list once per batch and pair: the plan's listing may be stale.
		// Later repairs of the pair use this listing, which remember/forget
		// keep current with this batch's own writes.
		delete(b.listings, pk)
		b.repairListed[pk] = true
	}
	l := b.listing(ctx, t)
	if l.err != nil {
		e.activity(ctx, "warn", fmt.Sprintf("not re-creating missing %s at %s/%s: listing the zone failed: %v", t, t.provider, t.zone, l.err))
		return errors.Join(fmt.Errorf("%w: %w", ErrListingUnavailable, l.err), bump())
	}
	stored := dns.Record{ID: row.ProviderRecordID, Name: t.name, Type: t.typ, Value: row.Value}
	for _, r := range l.recs {
		if normName(r.Name) == t.name && normType(r.Type) == t.typ && isOwn(r, stored) {
			if err := e.repairKV.DeleteSetting(context.WithoutCancel(ctx), key); err != nil {
				e.log.WarnContext(ctx, "resetting the DNS repair backoff failed", "key", key, "error", err)
			}
			e.activity(ctx, "info", fmt.Sprintf("%s at %s/%s is present at the provider after all (provider id %q); nothing re-created",
				t, t.provider, t.zone, r.ID))
			return nil
		}
	}
	for _, r := range l.recs {
		if !blocks(r, t) {
			continue
		}
		e.activity(ctx, "warn", fmt.Sprintf("conflict: not re-creating missing %s at %s/%s: foreign record %s %s %s (id %q) exists; adopt or remove it",
			t, t.provider, t.zone, normName(r.Name), normType(r.Type), r.Value, r.ID))
		return errors.Join(fmt.Errorf("%w: %s %s %s (id %q)", ErrForeignRecord, normName(r.Name), normType(r.Type), r.Value, r.ID), bump())
	}
	if err := bump(); err != nil {
		return err // without a recorded attempt the backoff cannot hold: create nothing
	}
	e.activity(ctx, "warn", fmt.Sprintf("owned record %s %s at %s/%s (owner %s, provider id %q) is missing at the provider; re-creating it (attempt %d)",
		t, row.Value, t.provider, t.zone, t.owner, row.ProviderRecordID, st.Attempts))
	warned := len(e.warnings)
	created, err := b.doCreate(ctx, t, row)
	if created && err == nil && len(e.warnings) == warned {
		// confirmed: the incident is over (an unconfirmed create keeps the
		// backoff until a listing shows the record)
		if derr := e.repairKV.DeleteSetting(context.WithoutCancel(ctx), key); derr != nil {
			e.log.WarnContext(ctx, "resetting the DNS repair backoff failed", "key", key, "error", derr)
		}
	}
	return err
}

// loadRepairState reads key; absent, unreadable JSON or a state older than
// repairStateStale is a fresh state. NextAt is clamped to now+repairBackoffMax,
// so a clock stepped back never holds a repair longer than the cap.
func loadRepairState(ctx context.Context, kv RepairStateStore, key string, now time.Time) (repairState, error) {
	v, ok, err := kv.GetSetting(ctx, key)
	if err != nil || !ok {
		return repairState{}, err
	}
	var st repairState
	if json.Unmarshal([]byte(v), &st) != nil || st.Attempts < 0 || now.Sub(time.Unix(st.LastAt, 0)) > repairStateStale {
		return repairState{}, nil
	}
	if lim := now.Add(repairBackoffMax).Unix(); st.NextAt > lim {
		// the clock went back: clamp, and persist it so the wait ends at
		// most repairBackoffMax after the first read that saw it
		st.NextAt, st.LastAt = lim, min(st.LastAt, now.Unix())
		v, _ := json.Marshal(st)
		if err := kv.SetSetting(context.WithoutCancel(ctx), key, string(v)); err != nil {
			return repairState{}, err
		}
	}
	return st, nil
}

// pendingUpdateTTL: a pending update older than this is ignored.
const pendingUpdateTTL = 2 * time.Hour

// pendingUpdate is the kv value under pendingKey: an UpdateRecord that
// answered dns.ErrUnconfirmed with a usable record. The ownership row keeps
// its old value (and takes NewID); OldID is the ID the update was sent to.
// Value is the attempted value. It is dropped by the next confirmed write of
// the row (update, re-create), by the row's deletion, or after
// pendingUpdateTTL.
type pendingUpdate struct {
	Value string `json:"value"`
	OldID string `json:"old_id"`
	NewID string `json:"new_id"`
	At    int64  `json:"at"`
}

// pendingKey is the kv key of a record's pending (unconfirmed) update.
func pendingKey(provider, zone, name, typ string) string {
	return "dns/pending-update/" + provider + "/" + normName(zone) + "/" + normName(name) + "/" + normType(typ)
}

// recordPendingUpdate stores pu for t (best effort: without it a rotated ID
// that did not land shows as a foreign record, reported, never written over).
func (e *DNSExecutor) recordPendingUpdate(ctx context.Context, t dnsTarget, pu pendingUpdate) {
	if e.repairKV == nil {
		return
	}
	v, _ := json.Marshal(pu)
	if err := e.repairKV.SetSetting(context.WithoutCancel(ctx), pendingKey(t.provider, t.zone, t.name, t.typ), string(v)); err != nil {
		e.log.WarnContext(ctx, "recording a pending DNS update failed", "provider", t.provider, "zone", t.zone,
			"name", t.name, "type", t.typ, "error", err)
	}
}

// pendingUpdate returns t's pending update, if one younger than
// pendingUpdateTTL is stored.
func (e *DNSExecutor) pendingUpdate(ctx context.Context, t dnsTarget) (pendingUpdate, bool) {
	if e.repairKV == nil {
		return pendingUpdate{}, false
	}
	v, ok, err := e.repairKV.GetSetting(ctx, pendingKey(t.provider, t.zone, t.name, t.typ))
	if err != nil || !ok {
		return pendingUpdate{}, false
	}
	var pu pendingUpdate
	if json.Unmarshal([]byte(v), &pu) != nil || e.now().Sub(time.Unix(pu.At, 0)) > pendingUpdateTTL {
		return pendingUpdate{}, false
	}
	return pu, true
}

// clearKV deletes kv keys (best effort, logged).
func (e *DNSExecutor) clearKV(ctx context.Context, keys ...string) {
	if e.repairKV == nil {
		return
	}
	for _, k := range keys {
		if err := e.repairKV.DeleteSetting(context.WithoutCancel(ctx), k); err != nil {
			e.log.WarnContext(ctx, "deleting a DNS state key failed", "key", k, "error", err)
		}
	}
}

// repairStateLister lists kv keys by prefix (*store.Store implements it);
// optional, found on the RepairStateStore by type assertion.
type repairStateLister interface {
	ListSettingsWithPrefix(ctx context.Context, prefix string) (map[string]string, error)
}

// repairSweepEvery spaces the sweeps of leftover repair/pending-update keys.
const repairSweepEvery = time.Hour

// sweepRepairState deletes repair and pending-update kv keys whose ownership
// row no longer exists. It runs at the first non-dry Apply and then at most
// every repairSweepEvery; failures are logged and never fail the batch.
func (e *DNSExecutor) sweepRepairState(ctx context.Context) {
	l, ok := e.repairKV.(repairStateLister)
	now := e.now()
	if !ok || (!e.sweptAt.IsZero() && !now.Before(e.sweptAt) && now.Sub(e.sweptAt) < repairSweepEvery) {
		return
	}
	rows, err := e.st.ListAllOwnedRecords(ctx)
	if err != nil {
		e.log.WarnContext(ctx, "sweeping DNS repair state: reading ownership rows failed", "error", err)
		return
	}
	keep := map[string]bool{}
	for _, r := range rows {
		keep[repairKey(r.Provider, r.Zone, r.Name, r.Type)] = true
		keep[pendingKey(r.Provider, r.Zone, r.Name, r.Type)] = true
	}
	for _, prefix := range []string{"dns/repair/", "dns/pending-update/"} {
		kv, err := l.ListSettingsWithPrefix(ctx, prefix)
		if err != nil {
			e.log.WarnContext(ctx, "sweeping DNS repair state: listing keys failed", "prefix", prefix, "error", err)
			return
		}
		for k := range kv {
			if !keep[k] {
				e.clearKV(ctx, k)
			}
		}
	}
	e.sweptAt = now
}

// DNSObservation is what GatherObserved saw; Fill copies it into an
// Observed.
type DNSObservation struct {
	Owned        []store.DNSRecord
	Foreign      map[string][]dns.Record
	OwnedMissing map[string]bool
	OwnedDrifted map[string][]dns.Record
}

// Fill sets o's Owned, Foreign, OwnedMissing and OwnedDrifted.
func (d DNSObservation) Fill(o *Observed) {
	o.Owned, o.Foreign, o.OwnedMissing, o.OwnedDrifted = d.Owned, d.Foreign, d.OwnedMissing, d.OwnedDrifted
}

// GatherObserved builds Observed.Owned, Foreign, OwnedMissing and
// OwnedDrifted. Owned is EVERY
// ownership row in the store, of any provider or zone, including rows under
// a provider or zone no pair names (Plan reports those with a Skip and never
// removes them). When the rows cannot be read, Owned is empty and Foreign is
// empty for every pair (nothing is known: Plan creates and removes nothing).
// Foreign covers the given provider/zone pairs (deduplicated after
// normalizing the zone) and is keyed
// provider+"/"+zone and holds the provider's listing minus the records that
// have an ownership row (matched on normalized name and type, whatever their
// value: a record at an owned name+type is never foreign, so the executor's
// own listing, not Foreign, is what guards a repair), records of
// every type included, names and types normalized. A pair whose listing or
// ownership rows could not be read, or whose provider is missing, is ABSENT
// from Foreign (unknown: Plan then creates nothing there) and its error is
// returned in errs. A successful empty listing is present and empty.
//
// For each pair listed successfully, every row of that pair is classified:
// no listed record at its name+type puts it in OwnedMissing; listed records
// there, none with the stored value, put it in OwnedDrifted; otherwise it is
// present. Rows of a pair that was not listed are in neither. Each listing
// runs under timeout (0 means DefaultDNSCallTimeout).
func GatherObserved(ctx context.Context, providers map[string]dns.Provider, st OwnershipStore, zones []ZoneRef,
	timeout time.Duration) (obs DNSObservation, errs []error) {
	if timeout <= 0 {
		timeout = DefaultDNSCallTimeout
	}
	obs.Foreign = map[string][]dns.Record{}
	obs.OwnedMissing = map[string]bool{}
	obs.OwnedDrifted = map[string][]dns.Record{}
	if st == nil {
		return obs, []error{errors.New("no ownership store")}
	}
	all, err := st.ListAllOwnedRecords(ctx)
	if err != nil {
		return obs, []error{fmt.Errorf("reading ownership rows: %w", err)}
	}
	obs.Owned = all
	seen := map[string]bool{}
	for _, zr := range zones {
		zn := normName(zr.Zone)
		key := zr.Provider + "/" + zn
		if zn == "" || seen[key] {
			continue
		}
		seen[key] = true
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
		var rows []store.DNSRecord
		for _, r := range all {
			if r.Provider == zr.Provider && normName(r.Zone) == zn {
				mine[normName(r.Name)+" "+normType(r.Type)] = true
				rows = append(rows, r)
			}
		}
		out := make([]dns.Record, 0, len(recs))
		at := map[string][]dns.Record{}
		for _, r := range recs {
			r.Name, r.Type = normName(r.Name), normType(r.Type)
			k := r.Name + " " + r.Type
			if mine[k] {
				at[k] = append(at[k], r)
			} else {
				out = append(out, r)
			}
		}
		obs.Foreign[key] = out
		for _, r := range rows {
			listed := at[normName(r.Name)+" "+normType(r.Type)]
			rk := OwnedRowKey(r.Provider, r.Zone, r.Name, r.Type)
			switch {
			case len(listed) == 0:
				obs.OwnedMissing[rk] = true
			case !anySameValue(listed, r.Value):
				obs.OwnedDrifted[rk] = listed
			}
		}
	}
	return obs, errs
}

func anySameValue(rs []dns.Record, v string) bool {
	for _, r := range rs {
		if sameValue(r.Value, v) {
			return true
		}
	}
	return false
}

// DNSWarning is a typed, non-failing outcome of the last Apply: a provider
// write that was accepted but not confirmed (dns.ErrUnconfirmed).
type DNSWarning struct {
	// Op is "create", "update" or "restore".
	Op                                    string
	Provider, Zone, Name, Type, Value, ID string
	Err                                   error
}

// LastWarnings returns the warnings of the last non-dry Apply.
func (e *DNSExecutor) LastWarnings() []DNSWarning {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]DNSWarning(nil), e.warnings...)
}

// unconfirmedRecord returns the record a write that answered
// dns.ErrUnconfirmed says it wrote, normalized, when that record names t
// (same name and type, and t's value or none). Its Value is always t.value.
// ok is false when the provider returned no record, or one naming something
// else or another value (a provider bug): then the outcome is ambiguous and
// nothing may be recorded from it.
func unconfirmedRecord(t dnsTarget, got dns.Record) (dns.Record, bool) {
	if normName(got.Name) == "" || normName(got.Name) != t.name || normType(got.Type) != t.typ {
		return dns.Record{}, false
	}
	if v := strings.TrimSpace(got.Value); v != "" && !sameValue(v, t.value) {
		return dns.Record{}, false
	}
	return dns.Record{ID: strings.TrimSpace(got.ID), Name: t.name, Type: t.typ, Value: t.value, TTL: t.ttl}, true
}

// unconfirmed records a typed warning and a warn activity for a write that
// was accepted but not confirmed.
func (b *dnsBatch) unconfirmed(ctx context.Context, op string, t dnsTarget, r dns.Record, err error, what string) {
	b.e.warnings = append(b.e.warnings, DNSWarning{Op: op, Provider: t.provider, Zone: t.zone, Name: t.name, Type: t.typ,
		Value: r.Value, ID: r.ID, Err: err})
	b.e.activity(ctx, "warn", fmt.Sprintf("%s; write accepted but unconfirmed; will verify on a later cycle (%v)", what, err))
}

// ambiguous reports a write whose outcome is unknown and for which the
// provider returned no usable record: nothing is recorded from it.
func (b *dnsBatch) ambiguous(ctx context.Context, op string, t dnsTarget, value string, err error, consequence string) {
	b.e.activity(ctx, "error", fmt.Sprintf("%s of %s %s at %s/%s: OUTCOME UNKNOWN and the provider returned no usable record describing it (none, or one naming another name, type or value) (%v); %s",
		op, t, value, t.provider, t.zone, err, consequence))
}
