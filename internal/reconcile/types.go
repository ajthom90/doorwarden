package reconcile

import (
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// ActionKind names what an Action asks an executor to do.
type ActionKind string

const (
	// Invalid: the service cannot be planned (bad name, unknown zone, hostname
	// too long, duplicate key, no backend). Informational; nothing else is
	// emitted for it.
	Invalid ActionKind = "Invalid"
	// Conflict: a hostname lost to a higher-precedence service, or a foreign
	// DNS record blocks the managed record. Informational.
	Conflict ActionKind = "Conflict"
	// Skip: nothing could be done for an existing route and nothing is
	// removed (e.g. a stopped service without a last-known backend).
	// Informational.
	Skip ActionKind = "Skip"
	// CancelRemoval: a service with a scheduled removal is present again;
	// the caller must clear its RemovedAfter.
	CancelRemoval ActionKind = "CancelRemoval"
	// ScheduleRemoval: a previously published service is gone; the caller
	// must persist Action.RemovedAfter for it.
	ScheduleRemoval ActionKind = "ScheduleRemoval"
	// DNSCancelRemoval: an owned per-host record with a scheduled removal is
	// wanted again; the DNS executor clears the ownership row's
	// RemovedAfter (owner-guarded, no provider call).
	DNSCancelRemoval ActionKind = "DNSCancelRemoval"
	// DNSScheduleRemoval: an owned per-host record is an orphan; the DNS
	// executor persists Action.RemovedAfter on its ownership row
	// (owner-guarded, no provider call). DNSDelete follows once now is after
	// it.
	DNSScheduleRemoval ActionKind = "DNSScheduleRemoval"
	// DNSReassign: an owned per-host record whose owner no longer wants it is
	// wanted, with exactly the stored value, by the present Published
	// hostname winner Action.NewOwner: the DNS executor transfers the
	// ownership row from Action.Owner to NewOwner and clears its
	// RemovedAfter (owner-guarded, no provider call), so the record is never
	// deleted and re-created.
	DNSReassign ActionKind = "DNSReassign"
	DNSEnsure   ActionKind = "DNSEnsure"
	CertEnsure  ActionKind = "CertEnsure"
	RouteWrite  ActionKind = "RouteWrite"
	RouteRemove ActionKind = "RouteRemove"
	DNSDelete   ActionKind = "DNSDelete"
)

// KindOrder is the order Plan emits kinds in: reports first, then
// bookkeeping, then creations (DNS and certs before the routes that use
// them), then removals (route before its DNS record).
var KindOrder = []ActionKind{Invalid, Conflict, Skip, CancelRemoval, ScheduleRemoval,
	DNSCancelRemoval, DNSScheduleRemoval, DNSReassign, DNSEnsure, CertEnsure, RouteWrite, RouteRemove, DNSDelete}

// Informational reports whether k only reports and changes nothing.
func Informational(k ActionKind) bool { return k == Invalid || k == Conflict || k == Skip }

// Action is one step of a plan. Fields not relevant to a Kind are zero.
type Action struct {
	Kind ActionKind
	// Zone is the normalized zone name; Host the normalized hostname (for
	// DNS actions the record name, for wildcard records "*.zone"; for zone
	// certs the first name).
	Zone, Host string
	// Key is the service key; empty for zone-level actions (wildcard record,
	// wildcard/san certs).
	Key string
	// Svc is a copy of the desired service, when there is one.
	Svc *model.Service
	// Backend is the backend a RouteWrite must render (for a stopped
	// service, its last-known backend).
	Backend *model.Backend
	// Reason explains Invalid, Conflict, Skip and removals.
	Reason string
	// Provider is the records provider config key (zones[].records.provider).
	Provider string
	// Record is the desired record for DNSEnsure (ID set to the owned
	// record's provider ID when updating) or the stored owned record for
	// DNSDelete, DNSScheduleRemoval, DNSCancelRemoval and DNSReassign.
	Record *dns.Record
	// Owner is the ownership owner_key the DNS executor must store/match:
	// the service key for per-host records, WildcardOwnerKey(zone) for the
	// wildcard record. For DNSReassign it is the current (old) owner.
	Owner string
	// NewOwner is the owner key a DNSReassign transfers the row to (the
	// service key of Svc).
	NewOwner string
	// Repair marks a DNSEnsure that re-creates an owned record which a
	// successful listing showed missing at the provider (Observed.
	// OwnedMissing). Record carries the stored row's identity (ID = the row's
	// provider record ID, the stored value). The executor re-checks the row
	// and its own listing, never writes over a record it does not own, and
	// bounds attempts with a backoff (see doc.go).
	Repair bool
	// Alert, on an informational action, names a condition an operator must
	// act on (the caller notifies): AlertDNSMassMissing. Empty otherwise.
	Alert string
	// Names are the certificate names for CertEnsure; Issuer its issuer key.
	Names  []string
	Issuer string
	// RemovedAfter is set on ScheduleRemoval and DNSScheduleRemoval (the new
	// deadline), on DNSDelete (the row's schedule the delete was planned for;
	// the executor refuses unless the stored row still has exactly that
	// schedule and it is due) and on a RouteRemove with CauseRemovalGrace
	// (informational).
	RemovedAfter *time.Time
	// Cause says why a RouteRemove was planned (see RemovalCause).
	Cause RemovalCause
}

// RemovalCause is why a RouteRemove was planned.
type RemovalCause string

const (
	// CauseRemovalGrace: the service is gone and its grace period expired.
	// The route executor deletes the route only if its stored removed_after
	// is still set and in the past (store.DeleteRouteIfDue), so a stale plan
	// never removes a route whose removal a newer cycle cancelled. An empty
	// Cause is treated the same way.
	CauseRemovalGrace RemovalCause = "removal-grace"
	// CauseTakeover: a Published, routable service of the same or a higher
	// source rank takes the hostname over. Decided on the current
	// claimants; the executor trusts the plan.
	CauseTakeover RemovalCause = "takeover"
	// CauseRename: a hostname loser renamed away from its persisted
	// hostname. Decided on current labels; the executor trusts the plan.
	CauseRename RemovalCause = "rename"
)

// KnownService is what the caller remembers about a service that was
// previously published (from the services table).
type KnownService struct {
	Key, Source, Zone, Hostname string
	RemovedAfter                *time.Time
}

// Observed is the world as last seen by the caller.
type Observed struct {
	// Owned are the dns_records ownership rows (all providers and zones).
	Owned []store.DNSRecord
	// Foreign are provider listings keyed by provider+"/"+zone. They may also
	// contain owned records; only those absent from Owned count as foreign.
	Foreign map[string][]dns.Record
	Certs   []store.Cert
	// Unavailable maps a source name to true when its List failed this cycle.
	Unavailable map[string]bool
	// LastKnown maps a service key to the last backend persisted from a
	// Discovered/Published (never Stopped/Error) state.
	LastKnown map[string]model.Backend
	// Known maps a service key to a previously published service.
	Known map[string]KnownService
	// OwnedMissing holds OwnedRowKey of every Owned row whose normalized
	// name+type is absent from a SUCCESSFUL listing of its provider/zone.
	// Rows of a pair that was not listed are never in it (unknown).
	OwnedMissing map[string]bool
	// OwnedDrifted maps OwnedRowKey of every Owned row whose name+type is
	// listed but with none of the records carrying the stored value, to
	// what is listed there (normalized). Informational: Plan reports it and
	// never overwrites it.
	OwnedDrifted map[string][]dns.Record
	// RepairMassOK maps provider+"/"+zone (normalized) to the time an
	// operator acknowledged that the pair's owned records really are gone
	// (store.AcknowledgeMassRepair). While it is younger than RepairMassOKTTL
	// a tripped mass-repair breaker lets the capped repairs through.
	RepairMassOK map[string]time.Time
	// RepairDue maps OwnedRowKey of an Owned row with a live repair backoff
	// (kv dns/repair/...) to whether its next attempt is due at the time
	// given to GatherObservedAt. A row absent from it is due. Plan spends
	// the per-zone repair cap only on due rows; a row that is not due is
	// skipped silently but still counts toward the mass-repair breaker.
	RepairDue map[string]bool
}

// OwnedRowKey identifies an ownership row in Observed.OwnedMissing and
// Observed.OwnedDrifted: provider|zone|name|TYPE, normalized.
func OwnedRowKey(provider, zone, name, typ string) string {
	return provider + "|" + normName(zone) + "|" + normName(name) + "|" + normType(typ)
}

// WildcardOwnerKey is the owner_key used for a zone's "*.zone" record.
func WildcardOwnerKey(zone string) string { return "zone:" + normName(zone) }

// normName lowercases a DNS name or zone and strips surrounding space and
// trailing dots (the dns/store FQDN convention).
func normName(n string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(n)), ".") }

func normType(t string) string { return strings.ToUpper(strings.TrimSpace(t)) }
