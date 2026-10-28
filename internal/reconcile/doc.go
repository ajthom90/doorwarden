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
// zone (e.g. TrueNAS apps) uses settings.default_zone when set; otherwise,
// when exactly one zone is configured, that zone; otherwise it is Invalid
// ("service has no zone and no default_zone is set while N zones are
// configured"). It never falls back to "the first configured zone".
//
// Invalid: a hostname error (unknown zone, including a zone removed from the
// config; a name with no DNS-valid characters; no zone and no default), a
// hostname over 253 characters, an earlier duplicate of a key (the last
// occurrence wins, like the approval gate), or a Published service with
// neither a backend nor a last-known backend. Nothing else is emitted for it;
// it still counts as present, so it is never scheduled for removal and its
// existing route is left as is.
//
// Hostname conflicts are decided on the resulting hostname, case-insensitive,
// among every desired service with a valid hostname plus the Known services
// of unavailable sources (whose routes may still exist). Tiers, highest
// first: (a) services whose current state in desired is Published; (b)
// everything else (Pending, Discovered, Stopped, Error, Known-only services of
// an unavailable source). A tier (b) claimant never beats a Published one,
// even with a higher source rank or an existing route. Within a tier: static >
// truenas > docker > other, taken from the stable key prefix ("static:",
// "truenas:", "docker:") because source names are configurable
// (Service.Source is only a fallback for unknown prefixes), then the
// lexicographically smaller key. Every loser gets a Conflict naming the
// winner. A loser to a PUBLISHED winner that has an existing route (it is in
// Known) also gets RouteRemove naming the winner; its DNS is untouched (the
// winner's record of the same value is already there, and owned rows are
// never deleted for losers). After the caller forgets the Known entry the
// loser gets only Conflict (no flapping); when the winner goes away, the
// loser wins again and gets its route back. A loser to a non-published winner
// keeps its route. A Known-only claimant of an unavailable source still beats
// lower-ranked tier (b) claimants, so a stopped or pending service cannot take
// its name during an outage.
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
// at least one routed service. Routed includes a Stopped/Error service that
// gets a RouteWrite with its last-known backend, so a zone whose only services
// are stopped still gets the wildcard DNSEnsure and the wildcard/san
// CertEnsure (both no-ops when they already exist). "per-host": one record per
// Published hostname. The record is A (or AAAA for an IPv6 target_ip) with
// value target_ip; an unparsable target_ip yields a Skip and no DNS action
// (routes and certs proceed). An owned row for the same (provider, zone, name,
// type) with an equal value means nothing to do; with another value, DNSEnsure
// carries the row's provider record ID (update). Otherwise a listed record
// with the same name and the same type, or a CNAME, that is not owned yields
// Conflict ("foreign record exists") and no DNSEnsure, even if its value is
// already right: the user must adopt it. A DNS conflict does not block the
// route or cert. Owner keys: the service key for per-host records,
// WildcardOwnerKey for the wildcard record. If an owned row with the right
// value belongs to another owner key nothing is emitted (ownership transfer is
// not the plan's job).
//
// HARD CONTRACT for Observed.Foreign (T14/T19): every cycle the caller must
// set Foreign[provider+"/"+zone] for every provider/zone in use to that
// provider's listing (an empty or nil slice means "listed, none"), and must
// leave the key ABSENT when listing failed. An absent key means UNKNOWN: Plan
// then creates no record in that zone (it emits a Skip "foreign records for
// <provider>/<zone> unknown"), while still updating an owned row whose value
// must change and still planning routes and certs. Keys are normalized and
// merged in sorted order.
//
// Certs need zones[].certificate.issuer; without one no CertEnsure is
// emitted. Strategy (unset = wildcard): wildcard => one CertEnsure per zone
// with a routed service for ["*.zone", "zone"]; per-host => one per Published
// hostname; san => one per zone naming ALL routed hostnames when any of them
// is uncovered. A name is covered when some cert row lists it (or a "*.parent"
// wildcard one level up) and its NotAfter is after now. The row's Issuer,
// Staging and Status are ignored (a staging or other-issuer cert counts as
// covering; switching issuers is a UI-driven re-issue), and early renewal
// (renew_before) is left to the ACME manager, so the plan never double-orders.
// The san strategy does not split at the ACME limit of 100 names per
// certificate; a zone with more routed hostnames must use wildcard or
// per-host. Certs are never deleted by the plan.
//
// Removal: a Known service absent from desired is removed only when its source
// is available (Known.Source non-empty and not in Unavailable; an outage
// means unknown, never "gone", and also suspends removals already due). With
// no RemovedAfter, ScheduleRemoval carries now+grace (settings.grace_period,
// 24h when unset) for the caller to persist; nothing is deleted. Once now is
// strictly after RemovedAfter: RouteRemove, and in per-host zones that are
// still configured DNSDelete for owned rows of that hostname whose owner key
// is the service key, unless a current service now resolves to the same
// hostname. Foreign records and the wildcard record are never deleted
// automatically (a later UI action may). A present service with a
// RemovedAfter gets CancelRemoval in any state.
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
// if settings.dry_run OR its DryRun func says so.
//
// Caller duties (T19): pass desired for every available source in one call;
// persist ScheduleRemoval/CancelRemoval; forget a service's Known entry once
// its RouteRemove was applied (removal past grace, or a conflict loser) and
// its ownership rows once their DNSDelete was applied; mark a source
// Unavailable when it failed to construct, its List failed, or its approvals
// failed to load; key Unavailable (and fill Known.Source) with the value
// services carry in Service.Source, which is what Plan compares, not
// necessarily Source.Name(). Persist last-known backends ONLY from
// Action.Backend of RouteWrite actions (for a stopped service that already is
// the last-known one) or from Discovered/Published services, never from
// Svc.Backend of a Stopped/Error service.
package reconcile
