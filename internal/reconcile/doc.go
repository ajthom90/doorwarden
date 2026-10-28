// Package reconcile decides what DNS records, certificates and routes should
// exist (Plan, pure) and hands the decisions to executors (Executor,
// MultiExecutor, Runner). Real DNS, ACME and Traefik executors live in later
// tasks; this package fixes the contract they implement.
//
// # Plan rules
//
// Plan(desired, observed, cfg, now) has no I/O and no clock; equal inputs give
// equal output, sorted by KindOrder, then zone, host, key. Inputs are never
// modified and actions carry copies. A nil cfg yields no actions.
//
// Zones and names: zone names and record names are compared lowercased
// without trailing dots (the dns/store FQDN convention). A service without a
// zone uses the FIRST configured zone (config has no explicit default zone);
// with no zones configured it is Invalid.
//
// Invalid: a hostname error (unknown zone, name with no DNS-valid
// characters), a hostname over 253 characters, an earlier duplicate of a key
// (the last occurrence wins, like the approval gate), or a Published service
// with neither a backend nor a last-known backend. Nothing else is emitted for
// it, and it still counts as present (so it is never scheduled for removal).
//
// Hostname conflicts are decided on the resulting hostname, case-insensitive,
// among every desired service with a valid hostname, whatever its state (a
// Pending static service blocks a Published docker one: surfacing the
// conflict beats silently publishing the lower-precedence one). Precedence:
// static > truenas > docker > other, taken from the stable key prefix
// ("static:", "truenas:", "docker:") because source names are configurable;
// Service.Source is only a fallback. Ties break on the lexicographically
// smaller key. Losers get one Conflict naming the winner and nothing else; a
// loser's existing route is not removed. Known services of an unavailable
// source still claim their stored hostname (their route may exist), so a new
// service cannot take it over during an outage.
//
// States: only Published services get DNSEnsure/CertEnsure. A Published
// service whose backend is not authoritative (empty host or port 0) uses its
// last-known backend. Stopped and Error services carry no authoritative
// backend: if previously published (in Known) and a last-known backend
// exists, RouteWrite carries the LAST-KNOWN backend (so a writer that renders
// all routes each cycle keeps the route); without one a Skip is emitted and
// nothing is removed. Pending, Discovered and the rest emit nothing.
// RouteRemove is the only signal that removes a route: route executors must
// not remove a route merely because no RouteWrite for it appeared. Route
// identity is the service key.
//
// Records (zones[].records.mode): "off" and unset emit no DNS actions (routes
// and certs still happen). "wildcard": one "*.zone" record per zone that has
// at least one routed service. "per-host": one record per Published hostname.
// The record is A (or AAAA for an IPv6 target_ip) with value target_ip. An
// owned row for the same (provider, zone, name, type) with an equal value
// means nothing to do; with another value, DNSEnsure carries the row's
// provider record ID (update). Otherwise a listed record with the same name
// and the same type, or a CNAME, that is not owned yields Conflict
// ("foreign record exists") and no DNSEnsure, even if its value is already
// right: the user must adopt it. A DNS conflict does not block the route or
// cert. Owner keys: the service key for per-host records, WildcardOwnerKey
// for the wildcard record. If an owned row with the right value belongs to
// another owner key nothing is emitted (ownership transfer is not the plan's
// job).
//
// Certs need zones[].certificate.issuer; without one no CertEnsure is
// emitted. Strategy (unset = wildcard): wildcard => one CertEnsure per zone
// with a routed service for ["*.zone", "zone"]; per-host => one per Published
// hostname; san => one per zone naming ALL routed hostnames when any of them
// is uncovered. A name is covered when some cert row lists it (or a "*.parent"
// wildcard one level up) and its NotAfter is after now. Status is ignored and
// early renewal (renew_before) is left to the ACME manager, so the plan never
// double-orders. Certs are never deleted by the plan.
//
// Removal: a Known service absent from desired is removed only when its source
// is available (Known.Source non-empty and not in Unavailable; an outage
// means unknown, never "gone", and also suspends removals already due). With
// no RemovedAfter, ScheduleRemoval carries now+grace (settings.grace_period,
// 24h when unset) for the caller to persist; nothing is deleted. Once now is
// strictly after RemovedAfter: RouteRemove, and in per-host zones DNSDelete
// for owned rows of that hostname whose owner key is the service key, unless
// a current service now resolves to the same hostname. Foreign records and
// the wildcard record are never deleted automatically (a later UI action
// may). A present service with a RemovedAfter gets CancelRemoval in any state.
//
// Known gaps, resolved conservatively: when a published service changes
// hostname or zone, the old per-host record stays owned and is not deleted;
// when a published service becomes Pending (fingerprint changed) its route is
// left as last written, not removed.
//
// # Execution
//
// Dry run records activity and calls no provider: MultiExecutor never
// dispatches in dry run. Runner serializes Plan+Apply with a mutex and is dry
// if settings.dry_run OR its DryRun func says so. The caller persists
// ScheduleRemoval/CancelRemoval and passes desired for every available source
// in one call. It persists last-known backends ONLY from Action.Backend of
// RouteWrite actions (for a stopped service that already is the last-known
// one) or from Discovered/Published services, never from Svc.Backend of a
// Stopped/Error service.
package reconcile
