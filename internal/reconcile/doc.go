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
// occurrence wins, like the approval gate), a middleware reference that is
// malformed or resolves to no valid definition in cfg.Middlewares and is not
// in cfg.Traefik.ExternalMiddlewares (model.CheckMiddlewareRef over
// model.ValidateMiddlewareDefs, exactly the Traefik renderer's rule), or a
// Published service with neither a backend nor a last-known backend. It is never planned (no DNS,
// cert or RouteWrite) and, being present, never scheduled for removal. It is
// not routable, so it never causes another service's route to be removed.
// Its existing route is left as is UNLESS a Published, routable claimant that
// outranks or out-tiers it takes over its hostname: an Invalid Published
// service with a Known route claims its stored (Known) zone and hostname as a
// non-serving holder (see Stored-hostname claim), so it then gets Conflict
// and its stored row is removed like any loser. When nobody takes the name
// over (e.g. its Known zone was removed from the config) only Invalid is
// emitted and nothing is removed.
//
// Middlewares fail closed: a service with an undefined middleware is Invalid
// and so never routable, and it can never evict a working neighbor. A route
// it already has stays as last written: its stored middlewares are what the
// renderer serves (so a label typo keeps the old, defined auth in place).
// When a stored middleware itself becomes undefined (its definition was
// removed or broken), the renderer, which re-checks every row, stops serving
// that route: the hostname goes dark rather than serve without its auth.
//
// The same rule has an unfavourable half: when labels ADD a middleware with
// a typo (e.g. auth to a route that had none), the old route WITHOUT that
// middleware keeps being served as last written. In auto approval mode the
// service stays Published and Plan reports it only as an Invalid action
// each cycle; in approve mode the changed fingerprint makes it Pending (a
// Skip) and it waits for review, and approving it as is would only make it
// Invalid. Either way the old route stays up, so an admin must act on
// Invalid actions (fix the label or the definition): doorwarden does not
// take a running route down because a newer label is broken. Plan and the
// renderer must both be given cfg.MiddlewareDefs() and
// cfg.Traefik.ExternalMiddlewares, or they disagree on what is defined.
//
// Hostname conflicts are decided on the resulting hostname, case-insensitive,
// among every desired service with a valid hostname (or a stored-hostname
// claim, below), the Known services of unavailable sources ("phantoms", whose
// routes may still exist), and the Known services of available sources that
// are absent from desired ("absent": removal scheduled or due, route not yet
// removed, grace period not over; once now is after RemovedAfter it no longer
// claims, so the past-grace removal and a newcomer's RouteWrite happen in the
// same plan with no dark route cycle). Source rank is compared FIRST, so an absent
// service keeps its hostname against every lower-ranked claimant until its
// grace period ends (the newcomer gets a Conflict naming it): a lower-trust
// source never takes a hostname from a higher-trust one, even a briefly
// absent one. Within its own rank an absent claimant yields to every present
// claimant; when the winner is a present Published, routable service of the
// same or a higher rank, its route is removed at once (RouteRemove, no grace,
// no ScheduleRemoval; its DNS record follows the orphan rule). Against a
// present but non-routable winner it keeps its route until its grace period
// ends. The same takeover rule (planner.takesOver: winner Published,
// routable, not a phantom, rank <= loser's; loser's source available)
// decides the RouteRemove of present losers and of absent services.
//
// Absent is admin intent: a service the approval gate filters out (a source
// or service set to approval "off", or Skip) is absent from desired, not
// unavailable. A whole source set to approval "off" therefore has its routes
// removed after the grace period, and before that they can be evicted only
// by same-or-higher-rank newcomers. A source whose state is unknown must be
// marked Unavailable instead (see Caller duties).
//
// Stored-hostname claim: a present service that is NOT Published, or is
// Published but Invalid because its labels no longer resolve, and has a
// Known entry claims Known's zone and hostname (what its persisted route
// actually serves), not the ones derived from its current labels, because
// the route executor never applies a non-Published RouteWrite. This claim is
// used for conflict resolution, for its own actions (Zone/Host) and for the
// routed-zone sets of wildcard DNS and wildcard/san certificates. If its
// current labels no longer resolve to a hostname, the claim still stands and
// a Skip reports the label problem instead of Invalid. A non-Published
// service without a Known entry claims from its labels as before (it has no
// route); a Published service always claims from its current labels. Its
// tier is unchanged: it is not in the serving tier, so a Published service of
// the same source rank still takes the name over (and its route is removed).
//
// Renamed Published loser: when a Published service's current labels name
// a different hostname than its persisted row and it LOSES that hostname,
// its old row is removed in the same plan (RouteRemove, whoever the winner
// is, unless its source is Unavailable): otherwise nothing would claim the
// old name and a newcomer there would share it with the stale row. The
// renamed service is served under neither name until it wins its new one.
//
// Invariant (checked by TestPropertyRouteInvariants): after a plan is fully
// applied, every route row's key is a claimant of the row's hostname
// (present non-Published and Invalid holders via the stored-hostname claim,
// phantoms, absent services in grace; past-grace and renamed-away rows are
// removed in the same plan), a row is removed whenever a Published, routable
// claimant of the same or a higher source rank takes its name, and a
// Published RouteWrite only happens for the hostname's winner. Rows that did
// not share a hostname before a cycle can come to share one only in:
//   - a crash window: between the winner's RouteWrite and the loser's
//     RouteRemove of one Apply (a crash, or a failed RouteRemove batch); the
//     next cycle re-emits the RouteRemove and converges to one row;
//   - a source outage: a phantom's row is never removed, so if a present
//     Published service outranks it (higher source rank, or same rank with a
//     smaller key; both are in the serving tier) both rows exist until the
//     source is back and the phantom loses as a present service.
//
// In both the renderer's rule (source rank, then key) picks Plan's winner.
// Rows that already share a hostname for any other reason (left by an
// outage whose claimants then changed state, or written outside Plan)
// converge only when a claimant takes the name over or an absent row's grace
// period ends, not necessarily in the next cycle; until then a same-rank
// absent row with a smaller key can be what the renderer serves while Plan's
// winner is a non-routable holder. A higher-ranked non-routable holder keeps
// its row and the newcomer gets only a Conflict, without a RouteWrite.
// A no-op RouteWrite whose stored zone is no longer configured says so in
// its Reason.
//
// Order is SOURCE-FIRST:
//  1. key-prefix source rank: static > truenas > docker > other, taken from
//     the stable key prefix ("static:", "truenas:", "docker:") because source
//     names are configurable (Service.Source is only a fallback for unknown
//     prefixes);
//  2. within one source rank, the serving tier first: a Published service
//     that will get a RouteWrite this cycle (authoritative backend or an
//     authoritative last-known one), or a phantom (it still has a Known
//     route); everything else (Pending, Discovered, Stopped, Error, Published
//     without any backend) is the lower tier;
//  3. the lexicographically smaller key.
//
// A lower-trust source can therefore never take a hostname from a
// higher-trust one, whatever their states. Trade-off, chosen fail-safe: a
// Pending, Error or Stopped static/truenas entry blocks a Published docker
// service of the same hostname until it is fixed, approved or removed; this
// is visible as a Conflict on the docker service. Within one source a
// Stopped v1 never beats a Published v2, and equal-tier claimants are decided
// by key whichever of them is Known (no flapping). During an outage a
// phantom keeps its name, and a lower-ranked or non-serving claimant gets
// only a Conflict; recovery does not flip the name either.
//
// Every loser gets a Conflict naming the winner. A loser that has an existing
// route (it is in Known) also gets RouteRemove ONLY when the winner really
// takes the name over in this same plan: the winner is Published, gets a
// RouteWrite now, is not a phantom, and ranks at least as high; and the
// loser's source is available. Otherwise (the winner is pending, invalid,
// backend-less, or a phantom) the loser keeps its working route. A loser's
// DNS record is governed only by the orphan rule (see Orphan DNS records). After the caller forgets the Known entry the loser gets
// only Conflict; when the winner goes away the loser wins again and gets its
// route back.
//
// States: only Published services get DNSEnsure/CertEnsure. A backend is
// authoritative (routable) when it passes model.ValidateBackend (scheme http
// or https, valid host, port 1..65535), the same predicate the route store
// enforces. A Published service whose backend is not authoritative uses its
// last-known backend, and a Skip plus the RouteWrite's Reason ("current
// backend invalid (<problem>); using last-known backend") make the
// misconfiguration visible; without a last-known backend it is Invalid.
// Stopped and Error services carry no authoritative backend: if previously
// published (in Known) and a last-known backend exists, RouteWrite carries
// the LAST-KNOWN backend; without one a Skip is emitted and nothing is
// removed. Pending, Discovered and the rest emit nothing. Such a RouteWrite
// also carries the service's CURRENT labels (name, so Host; middlewares;
// websockets), which are not trustworthy while it is stopped or errored, so
// the route executor (NewRouteExecutor) treats a RouteWrite for a
// non-Published service as a no-op: the route is left as last written, and
// only a Published service can change it. Such a RouteWrite carries the
// stored zone/hostname (see Stored-hostname claim) and the Reason "persisted
// route unchanged (service is <state>, not Published); last-known backend
// kept". RouteRemove is the only signal that removes a route: route
// executors must not remove a route merely because no RouteWrite for it
// appeared. Route identity is the service key.
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
// type) with an equal value means nothing to do (unless the listing shows it
// missing or changed: see Drift repair); with another value, DNSEnsure
// carries the row's provider record ID (update). Otherwise a listed record
// with the same name and the same type, or a CNAME, that is not owned yields
// Conflict ("foreign record exists") and no DNSEnsure, even if its value is
// already right: the user must adopt it. A DNS conflict does not block the
// route or cert. Owner keys: the service key for per-host records,
// WildcardOwnerKey for the wildcard record. If an owned row with the right
// value belongs to another owner key nothing is emitted (ownership transfer is
// not the plan's job); with another value a Skip ("owned by <key> with another
// value") is emitted instead of a DNSEnsure the executor would refuse
// (ErrOwnerConflict), so the row's owner can still clean it up.
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
// strictly after RemovedAfter: RouteRemove{Cause: removal-grace,
// RemovedAfter: the schedule}. An absent service whose hostname is taken
// over by a present Published, routable service of the same or a higher
// source rank is removed earlier (RouteRemove{Cause: takeover}; see Hostname
// conflicts), and a loser that renamed away loses its old route
// (Cause: rename). A present service with a RemovedAfter gets CancelRemoval
// in any state. Route removal never deletes DNS: records have exactly one
// deletion path, the orphan rule.
//
// # Orphan DNS records
//
// Every owned row in Observed.Owned is checked each cycle (planOrphans, after
// all other planning). An owned per-host row (owner key not starting with
// "zone:", name not starting with "*.") is an ORPHAN when no present
// service with that owner key wants exactly its (provider, zone, normalized
// name, type). A present service wants a row when it is Published, its
// labels resolve (not Invalid, not a held-Invalid holder), its source is not
// Unavailable, it has a route backend (its own or a last-known one), its
// zone has records mode per-host, and the row is (zone provider, zone,
// hostname, A/AAAA from target_ip): exactly the DNSEnsure set planService
// computes. Hostname losers are included: a Conflict loser that still
// declares the hostname wants its record (the winner meanwhile uses that
// record silently); once it renames away or is gone the record is an orphan.
//
// Lifecycle (no provider call until the delete):
//   - orphan, RemovedAfter nil: DNSScheduleRemoval{Record: stored row,
//     Owner, RemovedAfter}. The deadline is now+grace; for an owner absent
//     from desired whose Known route has a RemovedAfter, that same deadline,
//     so route and record go together (an unscheduled route gets now+grace
//     in the same plan, the same value). The executor persists it on the
//     ownership row (store.SetOwnedRemoval, owner-guarded).
//   - orphan, now not strictly after RemovedAfter: nothing.
//   - orphan, now strictly after RemovedAfter: DNSDelete with the STORED row
//     (provider, zone, name, type, value, provider ID, owner) and the
//     planned RemovedAfter. The executor deletes by stored ID/value only (a
//     foreign record that took the name is never hit) and forgets the row on
//     success. On failure the row stays, past its deadline, so every
//     following cycle emits the DNSDelete again until it succeeds, even after
//     RouteRemove forgot the Known entry.
//   - orphan whose hostname winner (resolveHostnames) is another present,
//     cleanly Published service that wants exactly this (provider, zone,
//     name, type) and the stored value equals the zone's desired value:
//     DNSReassign{Owner: old, NewOwner: winner} instead of any schedule or
//     delete, whatever the row's RemovedAfter. The executor moves the row to
//     the new owner and clears its RemovedAfter (store.ReassignOwnedRecord,
//     owner-guarded, no provider call): a rename without a stable id or a
//     container recreate keeps the record continuously. A loser that also
//     wants the row never gets it; when the values differ the row takes the
//     schedule/delete path and the winner creates its record after the
//     delete (see Hostname takeover delay). A row gets at most one of
//     DNSEnsure, DNSReassign, DNSScheduleRemoval, DNSCancelRemoval and
//     DNSDelete per plan.
//   - wanted again (the owner wants the row) with RemovedAfter set:
//     DNSCancelRemoval (executor clears it). A wanted row is never scheduled
//     or deleted, whatever its RemovedAfter.
//
// Exclusions (never scheduled, never deleted, never reassigned):
//   - (a) the owner is present but does not cleanly want records: not
//     Published (Pending, Stopped, Error, Discovered, ...), Invalid (labels or
//     middlewares), a held-Invalid holder, its source Unavailable (carried
//     forward), Published without any backend, or its zone's target_ip does
//     not parse (wanted type unknown). Stopped containers never lose DNS; a
//     Pending service keeps what it had. A RemovedAfter set while the owner
//     was absent is CANCELLED (DNSCancelRemoval, "service is present again"):
//     a deadline frozen during the absence must not delete the record in the
//     first cycle that publishes it under another name; once Published and no
//     longer wanting the row, a fresh grace period starts.
//   - (b) the owner is absent and its source is unknown this cycle. With a
//     Known entry, Known.Source decides (empty or Unavailable: unknown).
//     Without one (route already removed) the key prefix must be "static:",
//     "truenas:" or "docker:" (anything else, or an empty owner: never
//     orphaned), and the source is unknown when any candidate name for that
//     prefix is Unavailable (the prefix itself, case-insensitively, and every
//     Source carried this cycle by a desired service or Known entry with
//     that prefix) or when an Unavailable source name maps to no prefix at
//     all (it might be this owner's renamed source). Only that evidence maps
//     a name to a prefix: a name that merely looks like a prefix does not (a
//     TrueNAS source may be named "docker").
//   - (c) the wildcard record ("zone:" owner, or a "*." name): never removed
//     automatically, as before; the executor refuses it too.
//   - (d) a zone with records mode off (or unset): nothing is touched, and
//     nothing is reported. In mode wildcard, per-host rows left from an
//     earlier per-host mode ARE orphans (the wildcard record covers their
//     names), on the same grace schedule, but only once the zone's own
//     "*.zone" row (owner WildcardOwnerKey) is in Observed.Owned; until then
//     they are left alone so no name goes dark.
//   - (e) the row's zone is no longer configured, or the zone's records
//     provider is not the row's provider: a Skip per row says so; nothing is
//     changed (it cannot be verified). GatherObserved returns every row in
//     the store, so such rows are seen and reported.
//   - a row for which the same plan emits a DNSEnsure (same provider, zone,
//     name, type) is never scheduled or deleted.
//
// Absent owners (removed, or filtered out by approval "off"/Skip) are removal
// by admin intent: their rows are scheduled like their routes. Rename and
// zone move: the old row is an orphan of the still-present owner (scheduled
// now+grace, deleted after it) while DNSEnsure creates the new one; renaming
// back within the grace period cancels the removal. A records type change
// (target_ip switched between IPv4 and IPv6) makes the old-type row an orphan
// the same way.
//
// Hostname takeover delay (values differ only): when the loser's stored value
// is not the winner's desired value there is no reassign. While the loser's
// row exists the winner's ensure is a Skip; after the loser's row is deleted
// (grace expired) the winner's DNSEnsure creates its own record in the NEXT
// cycle (the plan that deletes has the row in Observed, so it emits no
// create). The name then has no record for one reconcile interval (plus
// negative-caching TTLs). With the same value the row is reassigned and
// there is no gap.
//
// Stale plans: Observed is gathered outside Runner's lock, so a plan may
// act on a view an applied newer cycle has already changed. Every
// destructive or bookkeeping action re-checks the stored state before it
// acts, and does nothing (logged) when it differs from what the plan saw:
//   - DNSDelete carries its planned RemovedAfter; the executor re-reads the
//     row and deletes only if it has the same owner and RemovedAfter, and
//     that is due (strictly before now, in whole seconds). The value is NOT
//     compared: the provider delete always uses the STORED row's ID and
//     value, never the action's, so a stale value in the action cannot
//     target another record. It deletes at the provider first, then the row
//     with store.DeleteOwnedRecordIfDue. If the row changed between the two
//     (a cancel, reschedule or reassign won the race), or that row delete
//     fails, the record is gone but the row is not: the executor logs an
//     error activity and blanks the row's stored value and provider ID. A
//     returning owner's plan then sees another value and its DNSEnsure
//     re-creates the record (bounded gap, never a permanent loss; drift
//     repair covers any other case), and a DNSDelete of a blank row forgets
//     it without a provider call.
//   - DNSScheduleRemoval acts only on an unscheduled row, DNSCancelRemoval
//     only on a scheduled one, and DNSReassign only on a row that still has
//     the old owner; all require the same owner and value.
//   - RouteRemove{Cause: removal-grace} (or no Cause) deletes only through
//     store.DeleteRouteIfDue (removed_after set and due at apply time).
//     takeover and rename removals are decided on the hostname state of the
//     plan and are applied as planned: a stale one removes a route the next
//     cycle writes again.
//
// Known gaps, resolved conservatively: when a published service becomes
// Pending (fingerprint changed) its route is left as last written, not
// removed; likewise a Stopped/Error service's route is left as last written
// (its RouteWrite is a no-op in the route executor). The re-checks above are
// read-then-write, not one transaction; the final row write in each is
// owner- and schedule-guarded in SQL. store.DeleteOwnedRecord (unconditional)
// is for the UI/admin only; reconcile never calls it (its only row deletion
// is store.DeleteOwnedRecordIfDue).
//
// # Drift repair
//
// GatherObserved classifies every ownership row of a provider/zone it listed
// successfully: no listed record at the row's normalized name+type puts its
// OwnedRowKey in Observed.OwnedMissing; listed records there, none with the
// stored value, put it in Observed.OwnedDrifted; rows of a pair whose listing
// failed (or that was not listed) are in neither (unknown, never repaired).
// GatherObserved strips from Foreign every record at an owned name+type,
// whatever its value, so Plan cannot tell a foreign record there from ours:
// the executor's own listing is the load-bearing guard of a repair.
//
// Plan, for a WANTED owned row with the zone's desired value:
//   - drifted: a Skip "owned record ... changed out of band (the provider has
//     X, doorwarden stored Y); not overwriting it" each cycle; never a write.
//     A row whose desired value also changed is updated only when the
//     provider already lists the desired value (our own unconfirmed update);
//     any other out-of-band value is a Skip.
//   - missing: DNSEnsure{Repair: true} carrying the stored row's identity
//     (Record.ID = its provider ID, its value, Owner = its owner), emitted
//     every cycle while it stays missing. Wanted means: the owner is a
//     present, cleanly Published service from an available source and the
//     row is its per-host record in a per-host zone (a hostname winner via
//     ensureRecord, a loser via planOrphans), or the row is the "*.zone" row
//     owned by WildcardOwnerKey in a wildcard zone with a routed service. A
//     listed foreign record at the name (same type, or a CNAME) makes it a
//     Conflict instead. Never repaired: orphans (absent owner, or one that no
//     longer wants the row), protected owners (present but not cleanly
//     Published), owners whose source is Unavailable, zones with records
//     mode off, rows under another provider or an unconfigured zone, and
//     zones without a listing. A scheduled wanted row is cancelled
//     (DNSCancelRemoval runs first) and repaired in the same plan.
//
// The executor (DNSEnsure with Repair) does not stop at an up-to-date row:
//  1. stale-plan check: the stored row must still exist with the action's
//     owner, value and provider ID and no removal scheduled; otherwise
//     nothing happens (info activity);
//  2. backoff (kv key dns/repair/<provider>/<zone>/<name>/<type>, JSON
//     {attempts, next_at, last_at} in unix seconds, via RepairStateStore):
//     not due means no provider call at all. Attempt n is followed by a wait
//     of 1m << (n-1), capped at 1h. A state whose last attempt is more than
//     2h old is ignored (a new incident starts at 1m). Without a state store
//     the repair is refused (ErrDNSRefused): attempts are never unbounded;
//  3. the zone is RE-LISTED (the batch cache is dropped): a failed listing
//     counts an attempt and returns ErrListingUnavailable; our record present
//     (same name and type and our stored ID, or our value when the row has
//     no ID) is a no-op that deletes the backoff state; any other record
//     blocking the name (same type, even with an identical value, or a
//     CNAME) counts an attempt, is a Conflict activity and ErrForeignRecord;
//  4. otherwise the attempt is recorded (a failure to record it creates
//     nothing) and the guarded create runs; the SAME row is refreshed
//     (CreatedAt kept, new provider ID), with the usual rollback.
//
// Every attempt that reaches the listing counts, successful or not; only the
// executor seeing our record present resets the state (plus the 2h
// staleness). After a successful repair the plan no longer emits the repair,
// so its state stays in kv until it goes stale (harmless: ignored after 2h;
// a recurrence within 2h continues the backoff where it was).
//
// The unconfirmed-write contract feeds this: a create that answered
// dns.ErrUnconfirmed with a usable record wrote its ownership row; if it
// never landed the next listing shows the row missing and it is repaired;
// if it landed but a lagging listing hides it, the repair's own listing (or
// the provider's idempotent create) finds it and nothing is duplicated.
//
// # Execution
//
// Dry run records activity and calls no provider: MultiExecutor never
// dispatches in dry run. Runner serializes Plan+Apply with a mutex and is dry
// if settings.dry_run OR its DryRun func says so.
//
// Caller duties (T19): pass desired for every available source in one call;
// persist ScheduleRemoval/CancelRemoval; forget a service's Known entry once
// its RouteRemove was applied (removal past grace, or a conflict loser);
// pass Observed.Owned (with RemovedAfter) as EVERY ownership row in the
// store, not only the configured provider/zone pairs, plus Foreign,
// OwnedMissing and OwnedDrifted (GatherObserved does all of it:
// DNSObservation.Fill); give the DNS executor a RepairStateStore (a
// *store.Store as its Store is enough) or every repair is refused; register the DNS executor for every kind in DNSActionKinds
// (RegisterDNSExecutor; it persists, reassigns and forgets ownership rows
// itself) and the route executor for RouteWrite, RouteRemove,
// ScheduleRemoval and CancelRemoval (its store must implement
// DeleteRouteIfDue); mark a source
// Unavailable when it failed to construct, its List failed, its services
// could not be resolved (a Resolve/merge error), or its approvals failed to
// load (otherwise its services would look absent and be removed); key
// Unavailable (and fill Known.Source) with the value services carry in
// Service.Source, which is what Plan compares, not necessarily
// Source.Name(). For an absent owner without a Known entry, Plan maps an
// Unavailable name to a key prefix only through this cycle's evidence, so
// either Service.Source equals the key prefix ("static", "truenas",
// "docker") or every Known entry carries its Source; otherwise any outage
// of an unmapped name blocks every such owner's removals (safe, but nothing
// is cleaned up until the source is back). Persist last-known backends ONLY from
// Action.Backend of RouteWrite actions (for a stopped service that already is
// the last-known one) or from Discovered/Published services, never from
// Svc.Backend of a Stopped/Error service.
package reconcile
