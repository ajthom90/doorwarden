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
	DNSEnsure       ActionKind = "DNSEnsure"
	CertEnsure      ActionKind = "CertEnsure"
	RouteWrite      ActionKind = "RouteWrite"
	RouteRemove     ActionKind = "RouteRemove"
	DNSDelete       ActionKind = "DNSDelete"
)

// KindOrder is the order Plan emits kinds in: reports first, then
// bookkeeping, then creations (DNS and certs before the routes that use
// them), then removals (route before its DNS record).
var KindOrder = []ActionKind{Invalid, Conflict, Skip, CancelRemoval, ScheduleRemoval,
	DNSEnsure, CertEnsure, RouteWrite, RouteRemove, DNSDelete}

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
	// record's provider ID when updating) or the owned record for DNSDelete.
	Record *dns.Record
	// Owner is the ownership owner_key the DNS executor must store/match:
	// the service key for per-host records, WildcardOwnerKey(zone) for the
	// wildcard record.
	Owner string
	// Names are the certificate names for CertEnsure; Issuer its issuer key.
	Names  []string
	Issuer string
	// RemovedAfter is set on ScheduleRemoval.
	RemovedAfter *time.Time
}

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
}

// WildcardOwnerKey is the owner_key used for a zone's "*.zone" record.
func WildcardOwnerKey(zone string) string { return "zone:" + normName(zone) }

// normName lowercases a DNS name or zone and strips surrounding space and
// trailing dots (the dns/store FQDN convention).
func normName(n string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(n)), ".") }

func normType(t string) string { return strings.ToUpper(strings.TrimSpace(t)) }
