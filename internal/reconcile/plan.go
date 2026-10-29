package reconcile

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

const (
	maxHostname  = 253
	defaultGrace = 24 * time.Hour
)

type zoneInfo struct {
	name, mode, strategy, provider, issuer string
	recType, value                         string // desired record; recType "" if target_ip is unusable
}

// entry is one unique desired service with its resolved hostname.
type entry struct {
	svc        model.Service
	zone, host string
	err        error
	// heldInvalid: a Published service whose labels are invalid (err set)
	// that claims its Known zone/hostname as a non-serving holder.
	heldInvalid bool
}

type planner struct {
	obs       Observed
	now       time.Time
	grace     time.Duration
	zones     map[string]*zoneInfo
	zoneNames []string // config order, normalized
	defZone   string   // settings.default_zone, or the only zone; "" if none
	foreign   map[string][]dns.Record
	// mwValid are the usable middleware definitions and mwExternal the
	// allowlist (the renderer's rule, model.ValidateMiddlewareDefs).
	mwValid    map[string]bool
	mwExternal []string
	out        []Action
	// presenceChecked: OwnedRowKey of rows ownedPresence already handled.
	presenceChecked map[string]bool
	// repairPairs: per provider+"/"+zone, the wanted rows eligible for
	// repair and the missing ones (planRepairs decides what is emitted).
	repairPairs map[string]*repairPair
}

// repairPair counts, for one provider/zone, the wanted owned rows eligible
// for repair (wanted) and those of them a listing showed missing (missing,
// including rows a foreign record blocks), with the repairs that could be
// emitted (cands, unblocked missing rows: DNSEnsure{Repair} for a row with
// the desired value, the update for a row whose desired value changed).
type repairPair struct {
	provider, zone  string
	wanted, missing int
	cands           []Action
}

// Mass-repair limits per provider/zone and cycle (see planRepairs).
const (
	// RepairCapPerZone bounds the repairs emitted per provider/zone and cycle.
	RepairCapPerZone = 5
	// repairBreakerMinMissing: the breaker needs MORE than this many missing
	// rows (and more than half of the wanted ones).
	repairBreakerMinMissing = 3
	// RepairMassOKTTL: a mass-repair acknowledgement older than this is
	// ignored (and cleared by the DNS executor).
	RepairMassOKTTL = 24 * time.Hour
	// repairMassOKSkew: an acknowledgement dated further than this in the
	// future (a clock stepped back) is ignored too.
	repairMassOKSkew = 5 * time.Minute
)

// AlertDNSMassMissing marks the Skip planRepairs emits when most owned
// records of a provider/zone are missing (Action.Alert).
const AlertDNSMassMissing = "dns-mass-missing"

// RepairBreakerKey is the Key of the breaker Skip of provider/zone (zone
// normalized): stable, and never a service key.
func RepairBreakerKey(provider, zone string) string {
	return "repair-breaker:" + provider + "/" + normName(zone)
}

// massOKValid reports whether a mass-repair acknowledgement made at at still
// counts at now.
func massOKValid(at, now time.Time) bool {
	return now.Sub(at) < RepairMassOKTTL && !at.After(now.Add(repairMassOKSkew))
}

// Plan computes the actions that bring the world in line with desired. It is
// pure: no I/O, no clock, inputs are not modified, output order is
// deterministic. See the package documentation for the rules.
func Plan(desired []model.Service, obs Observed, cfg *config.Config, now time.Time) []Action {
	acts, _ := planWithWinners(desired, obs, cfg, now)
	return acts
}

// planWithWinners is Plan that also returns the hostname winners (by
// normalized hostname), for tests that check the renderer agrees with Plan.
func planWithWinners(desired []model.Service, obs Observed, cfg *config.Config, now time.Time) ([]Action, map[string]claimant) {
	if cfg == nil {
		return nil, nil // fail closed: no config, no changes
	}
	p := newPlanner(obs, cfg, now)

	entries := p.dedupe(desired)
	for i := range entries {
		p.claimKnown(&entries[i])
	}
	present := map[string]bool{}
	var claims []claimant
	for _, e := range entries {
		present[e.svc.Key] = true
		if e.heldInvalid {
			// not routable, so never serving and never able to evict anyone
			claims = append(claims, claimant{key: e.svc.Key, source: e.svc.Source, host: e.host, published: true})
		} else if e.err == nil {
			pubd := e.svc.State == model.StatePublished
			_, routable := p.routeBackend(e.svc)
			routable = routable && pubd
			claims = append(claims, claimant{key: e.svc.Key, source: e.svc.Source, host: e.host,
				published: pubd, routable: routable, serving: routable})
		}
	}
	for _, k := range sortedKnown(obs.Known) {
		if !present[k.Key] && p.unavailable(k) && k.Hostname != "" {
			// it is Known, i.e. it still has a route: serving tier
			claims = append(claims, claimant{key: k.Key, source: k.Source, host: k.Hostname, phantom: true, serving: true})
		} else if !present[k.Key] && k.Hostname != "" && (k.RemovedAfter == nil || !now.After(*k.RemovedAfter)) {
			// gone from an available source, route not yet removed and grace
			// not over: it holds its hostname as a non-serving claimant (past
			// grace it is removed this cycle, so it must not hold the name)
			claims = append(claims, claimant{key: k.Key, source: k.Source, host: k.Hostname, absent: true})
		}
	}
	winners, losers := resolveHostnames(claims)

	routed := map[string][]string{} // zone -> hostnames that get a RouteWrite
	for _, e := range entries {
		if k, ok := obs.Known[e.svc.Key]; ok && k.RemovedAfter != nil {
			p.emit(Action{Kind: CancelRemoval, Zone: e.zone, Host: e.host, Key: e.svc.Key, Svc: copySvc(e.svc),
				Reason: "service is present again"})
		}
		if e.err != nil {
			p.emit(Action{Kind: Invalid, Zone: e.zone, Host: e.host, Key: e.svc.Key, Svc: copySvc(e.svc), Reason: e.err.Error()})
			if l, lost := losers[e.svc.Key]; lost && e.heldInvalid {
				p.planLoser(e, l)
			}
			continue // never planService: its zone may no longer be configured
		}
		if l, lost := losers[e.svc.Key]; lost {
			p.planLoser(e, l)
			continue
		}
		if p.planService(e) {
			routed[e.zone] = append(routed[e.zone], e.host)
		}
	}
	for _, zn := range p.zoneNames {
		if hosts := routed[zn]; len(hosts) > 0 {
			p.planZone(p.zones[zn], hosts)
		}
	}
	p.planRemovals(present, losers)
	p.planOrphans(entries, winners)
	p.planRepairs()

	sortActions(p.out)
	return p.out, winners
}

func newPlanner(obs Observed, cfg *config.Config, now time.Time) *planner {
	p := &planner{obs: obs, now: now, grace: cfg.Settings.GracePeriod, zones: map[string]*zoneInfo{},
		foreign: map[string][]dns.Record{}, presenceChecked: map[string]bool{}, repairPairs: map[string]*repairPair{}}
	if p.grace <= 0 {
		p.grace = defaultGrace
	}
	p.mwValid, _ = model.ValidateMiddlewareDefs(cfg.MiddlewareDefs(), cfg.Traefik.ExternalMiddlewares)
	p.mwExternal = cfg.Traefik.ExternalMiddlewares
	for _, z := range cfg.Zones {
		n := normName(z.Name)
		if n == "" || p.zones[n] != nil {
			continue // first definition wins; validation rejects duplicates
		}
		zi := &zoneInfo{name: n, mode: z.Records.Mode, strategy: z.Certificate.Strategy,
			provider: z.Records.Provider, issuer: z.Certificate.Issuer}
		if zi.strategy == "" {
			zi.strategy = "wildcard"
		}
		if ip, err := netip.ParseAddr(strings.TrimSpace(z.TargetIP)); err == nil {
			zi.recType, zi.value = "A", ip.String()
			if !ip.Unmap().Is4() {
				zi.recType = "AAAA"
			} else {
				zi.value = ip.Unmap().String()
			}
		}
		p.zones[n] = zi
		p.zoneNames = append(p.zoneNames, n)
	}
	if dz := normName(cfg.Settings.DefaultZone); dz != "" {
		p.defZone = dz // validated by config; an unknown one makes services Invalid
	} else if len(p.zoneNames) == 1 {
		p.defZone = p.zoneNames[0]
	}
	// A present key (even with a nil/empty slice) means "listed"; an absent
	// key means "unknown". Keys are visited in sorted order so collapsing
	// unnormalized duplicates is deterministic.
	fkeys := make([]string, 0, len(obs.Foreign))
	for k := range obs.Foreign {
		fkeys = append(fkeys, k)
	}
	sort.Strings(fkeys)
	for _, k := range fkeys {
		if i := strings.LastIndexByte(k, '/'); i >= 0 {
			nk := k[:i] + "/" + normName(k[i+1:])
			p.foreign[nk] = append(p.foreign[nk], obs.Foreign[k]...)
		}
	}
	return p
}

func (p *planner) emit(a Action) { p.out = append(p.out, a) }

// unavailable reports whether a known service's source state is unknown this
// cycle. A known service without a recorded source is treated as unknown.
func (p *planner) unavailable(k KnownService) bool {
	return k.Source == "" || p.obs.Unavailable[k.Source]
}

// dedupe keeps the last occurrence of each key (matching the approval gate's
// last-wins), reports earlier ones as Invalid, resolves hostnames and returns
// the entries sorted by key.
func (p *planner) dedupe(desired []model.Service) []entry {
	last := map[string]int{}
	for i, s := range desired {
		last[s.Key] = i
	}
	var out []entry
	for i, s := range desired {
		e := p.resolve(s)
		if last[s.Key] != i {
			p.emit(Action{Kind: Invalid, Zone: e.zone, Host: e.host, Key: s.Key, Svc: copySvc(s),
				Reason: fmt.Sprintf("duplicate service key %q; the later entry wins", s.Key)})
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].svc.Key < out[j].svc.Key })
	return out
}

func (p *planner) resolve(s model.Service) entry {
	e := entry{svc: s, zone: normName(s.Zone)}
	if e.zone == "" {
		if p.defZone == "" {
			e.err = fmt.Errorf("service has no zone and no default_zone is set while %d zones are configured", len(p.zoneNames))
			return e
		}
		e.zone = p.defZone
	}
	h, err := model.Hostname(s, p.zoneNames, p.defZone)
	switch {
	case err != nil:
		e.err = err
	case len(h) > maxHostname:
		e.host, e.err = h, fmt.Errorf("hostname %s is %d characters; the limit is %d (253)", h, len(h), maxHostname)
	default:
		e.host = normName(h)
		e.err = p.middlewareProblem(s)
	}
	return e
}

// middlewareProblem fails a service closed when one of its middleware
// references is malformed or resolves to no valid definition and is not
// allowlisted (model.CheckMiddlewareRef, the renderer's own check). Such a
// service is Invalid: never routable, so it can never evict a working
// neighbor; a route it already has stays as last written.
func (p *planner) middlewareProblem(s model.Service) error {
	defined := func(n string) bool { return p.mwValid[n] }
	for _, ref := range s.Options.Middlewares {
		err := model.CheckMiddlewareRef(ref, defined, p.mwExternal)
		switch {
		case err == nil:
		case errors.Is(err, model.ErrInvalidMiddlewareRef):
			return fmt.Errorf("middleware reference %q is invalid; the service is not routed (fail closed)", ref)
		default:
			return fmt.Errorf("middleware %q is not defined (middlewares, or traefik.external_middlewares for other providers); the service is not routed (fail closed)", ref)
		}
	}
	return nil
}

// planLoser emits Conflict for a hostname loser and, when the winner really
// takes the name over, RouteRemove for its existing route (only if it has
// one, so this does not repeat once the caller forgets the Known entry). DNS
// is untouched.
func (p *planner) planLoser(e entry, l loss) {
	p.emit(Action{Kind: Conflict, Zone: e.zone, Host: e.host, Key: e.svc.Key, Svc: copySvc(e.svc), Reason: l.reason})
	k, ok := p.obs.Known[e.svc.Key]
	if !ok {
		return
	}
	old := normName(k.Hostname)
	switch {
	case p.mayRemoveLoserRoute(e.svc, l.winner):
		p.emit(Action{Kind: RouteRemove, Zone: normName(k.Zone), Host: old, Key: e.svc.Key, Cause: CauseTakeover,
			Svc: copySvc(e.svc), Reason: "hostname " + e.host + " now belongs to published " + l.winner.key})
	case p.renamedAway(e, old):
		// It no longer declares its old hostname and nothing else claims
		// that name on its behalf: keeping the row would leave an orphan
		// that a newcomer at the old name shares with it. It is served
		// under neither name until it wins its new one.
		p.emit(Action{Kind: RouteRemove, Zone: normName(k.Zone), Host: old, Key: e.svc.Key, Cause: CauseRename,
			Svc: copySvc(e.svc), Reason: "service now declares " + e.host + " (held by " + l.winner.key +
				"); its old route for " + old + " is removed"})
	}
}

// renamedAway reports whether a hostname loser is a Published service whose
// current labels name a different hostname than its persisted route (old),
// from an available source. Held-Invalid and non-Published services claim
// their stored hostname, so they never qualify.
func (p *planner) renamedAway(e entry, old string) bool {
	if e.heldInvalid || e.svc.State != model.StatePublished {
		return false
	}
	if e.svc.Source == "" || p.obs.Unavailable[e.svc.Source] {
		return false
	}
	return old != "" && old != e.host
}

// claimKnown makes a present non-Published service that has a Known route
// claim what it actually serves: the Known zone and hostname, not the ones
// derived from its current labels (which the route executor never applies
// while it is not Published). If its labels no longer resolve, the claim
// still stands and a Skip reports the label problem. A Published service
// whose labels do not resolve (e.err) and that has a Known route also claims
// the Known zone/hostname, as a non-serving holder (heldInvalid): it stays
// Invalid and is never planned, but as a hostname loser its route can be
// removed. A service without a Known route, and a Published service whose
// labels resolve, are left as resolved.
func (p *planner) claimKnown(e *entry) {
	k, ok := p.obs.Known[e.svc.Key]
	zn, host := normName(k.Zone), normName(k.Hostname)
	if !ok || zn == "" || host == "" {
		return
	}
	if e.svc.State == model.StatePublished {
		if e.err != nil {
			// Invalid labels: hold the stored hostname as a non-serving
			// claimant; it stays Invalid and gets no planService.
			e.zone, e.host, e.heldInvalid = zn, host, true
		}
		return
	}
	if e.err != nil {
		p.emit(Action{Kind: Skip, Zone: zn, Host: host, Key: e.svc.Key, Svc: copySvc(e.svc),
			Reason: fmt.Sprintf("current labels invalid (%v); persisted route for %s still claims the hostname", e.err, host)})
		e.err = nil
	}
	e.zone, e.host = zn, host
}

// planService emits the per-service actions for a hostname winner and
// reports whether a RouteWrite was emitted.
func (p *planner) planService(e entry) bool {
	s, z := e.svc, p.zones[e.zone]
	lk, haveLK := p.obs.LastKnown[s.Key]
	_, isKnown := p.obs.Known[s.Key]
	switch s.State {
	case model.StatePublished:
		b, ok := p.routeBackend(s)
		if !ok {
			p.emit(Action{Kind: Invalid, Zone: e.zone, Host: e.host, Key: s.Key, Svc: copySvc(s),
				Reason: "published service has no valid backend (" + backendProblem(s.Backend) + ") and no last-known backend"})
			return false
		}
		if z.mode == "per-host" {
			p.ensureRecord(z, e.host, s.Key, &s)
		}
		if z.issuer != "" && z.strategy == "per-host" && !p.covered(e.host) {
			p.emit(Action{Kind: CertEnsure, Zone: e.zone, Host: e.host, Key: s.Key, Svc: copySvc(s),
				Names: []string{e.host}, Issuer: z.issuer})
		}
		reason := ""
		if !authoritative(s.Backend) {
			// Keep serving, but make the misconfiguration visible.
			reason = "current backend invalid (" + backendProblem(s.Backend) + "); using last-known backend"
			p.emit(Action{Kind: Skip, Zone: e.zone, Host: e.host, Key: s.Key, Svc: copySvc(s), Reason: reason})
		}
		p.emit(Action{Kind: RouteWrite, Zone: e.zone, Host: e.host, Key: s.Key, Svc: copySvc(s), Backend: &b, Reason: reason})
		return true
	case model.StateStopped, model.StateError:
		if !isKnown {
			return false
		}
		if !haveLK || !authoritative(lk) {
			p.emit(Action{Kind: Skip, Zone: e.zone, Host: e.host, Key: s.Key, Svc: copySvc(s),
				Reason: "service is " + s.State + " and has no last-known backend; existing route left untouched"})
			return false
		}
		b := lk
		reason := "persisted route unchanged (service is " + s.State + ", not Published); last-known backend kept"
		if z == nil {
			reason += "; zone " + e.zone + " is no longer configured"
		}
		p.emit(Action{Kind: RouteWrite, Zone: e.zone, Host: e.host, Key: s.Key, Svc: copySvc(s), Backend: &b, Reason: reason})
		return true
	}
	return false // pending, discovered, ...: nothing is created and nothing removed
}

// planZone emits zone-level actions (wildcard record, wildcard/san certs)
// for a zone with at least one routed hostname.
func (p *planner) planZone(z *zoneInfo, hosts []string) {
	if z.mode == "wildcard" {
		p.ensureRecord(z, "*."+z.name, "", nil)
	}
	if z.issuer == "" {
		return
	}
	switch z.strategy {
	case "wildcard":
		names := []string{"*." + z.name, z.name}
		if !p.covered(names...) {
			p.emit(Action{Kind: CertEnsure, Zone: z.name, Host: names[0], Names: names, Issuer: z.issuer})
		}
	case "san":
		names := append([]string{}, hosts...)
		sort.Strings(names)
		if !p.covered(names...) {
			p.emit(Action{Kind: CertEnsure, Zone: z.name, Host: names[0], Names: names, Issuer: z.issuer})
		}
	}
}

// ensureRecord emits DNSEnsure for name unless an owned record already has
// the desired value, or Conflict if a foreign record holds the name. key is
// the service key ("" for the wildcard record). An owned record with the
// desired value that a listing showed missing is repaired (see
// ownedPresence). An owned record with another value is updated (see
// ownedUpdate).
func (p *planner) ensureRecord(z *zoneInfo, name, key string, s *model.Service) {
	owner := key
	if owner == "" {
		owner = WildcardOwnerKey(z.name)
	}
	if z.recType == "" {
		p.emit(Action{Kind: Skip, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
			Reason: "zone target_ip is not a valid IP; no DNS record planned"})
		return
	}
	want := dns.Record{Name: name, Type: z.recType, Value: z.value}
	if o := p.owned(z, name, z.recType); o != nil {
		if sameValue(o.Value, z.value) {
			if o.OwnerKey == owner {
				p.ownedPresence(z, o, key, s)
			}
			return // idempotent; ownership transfer between keys is not the plan's job
		}
		if o.OwnerKey != owner {
			// The executor would refuse it (ErrOwnerConflict), and a DNSEnsure
			// here would keep the row's owner from ever cleaning it up.
			p.emit(Action{Kind: Skip, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
				Reason: fmt.Sprintf("record %s %s is owned by %s with another value; not changing it (it is removed once %s no longer wants it)",
					name, z.recType, o.OwnerKey, o.OwnerKey)})
			return
		}
		want.ID = o.ProviderRecordID
		p.ownedUpdate(z, o, key, s, Action{Kind: DNSEnsure, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
			Record: &want, Owner: owner, Reason: "owned record has a different value"})
		return
	}
	if _, listed := p.foreign[z.provider+"/"+z.name]; !listed {
		p.emit(Action{Kind: Skip, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
			Reason: fmt.Sprintf("foreign records for %s/%s unknown; not creating %s", z.provider, z.name, name)})
		return
	}
	if fr := p.foreignBlocker(z, name); fr != nil {
		p.emit(Action{Kind: Conflict, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
			Record: fr, Owner: owner,
			Reason: fmt.Sprintf("foreign record exists: %s %s %s (adopt or skip it)", fr.Name, fr.Type, fr.Value)})
		return
	}
	p.emit(Action{Kind: DNSEnsure, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
		Record: &want, Owner: owner})
}

// foreignBlocker returns the first listed foreign record at name that a
// create of the zone's record type would collide with (same type, or a
// CNAME), or nil.
func (p *planner) foreignBlocker(z *zoneInfo, name string) *dns.Record {
	for _, f := range p.foreign[z.provider+"/"+z.name] {
		ft := normType(f.Type)
		if normName(f.Name) != name || (ft != z.recType && ft != "CNAME") || p.owned(z, name, ft) != nil {
			continue
		}
		return &dns.Record{ID: f.ID, Name: normName(f.Name), Type: ft, Value: f.Value, TTL: f.TTL}
	}
	return nil
}

// ownedUpdate plans upd, the update of the wanted owned row o (same owner)
// to the zone's desired value, against the provider listing:
//   - changed out of band to neither the stored nor the desired value: a
//     drift Skip, never overwritten (listed with the desired value is our
//     own unconfirmed update: the update is repeated, idempotently);
//   - present (or the pair not listed): the update is emitted, uncapped: an
//     in-place change of a record we own and the provider lists (a target_ip
//     migration touches every record of the zone);
//   - missing at a successful listing: the update would re-create the record
//     (UpdateRecord answers not-found, then the guarded create), so it is
//     REPAIR-CLASS: it counts toward the pair's breaker like a missing
//     same-value row and is a candidate of planRepairs (breaker, cap, due
//     rows only), or a Conflict when a foreign record holds the name; never
//     planned while the owner's source is unavailable.
//
// An eligible row (see ownedPresence) counts as wanted in every case.
func (p *planner) ownedUpdate(z *zoneInfo, o *store.DNSRecord, key string, s *model.Service, upd Action) {
	rk := OwnedRowKey(o.Provider, o.Zone, o.Name, o.Type)
	if p.presenceChecked[rk] {
		return // once per row
	}
	p.presenceChecked[rk] = true
	pair := p.eligiblePair(z, s)
	if pair != nil {
		pair.wanted++
	}
	if d, ok := p.obs.OwnedDrifted[rk]; ok && !anySameValue(d, z.value) {
		p.emit(p.driftSkip(z, o, key, s, d))
		return
	}
	if !p.obs.OwnedMissing[rk] {
		p.emit(upd)
		return
	}
	if pair == nil {
		return // the owner's state is unknown this cycle: never re-create blind
	}
	pair.missing++
	name := normName(o.Name)
	if fr := p.foreignBlocker(z, name); fr != nil {
		p.emit(Action{Kind: Conflict, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
			Record: fr, Owner: o.OwnerKey,
			Reason: fmt.Sprintf("owned record %s %s is missing and a foreign record exists: %s %s %s; not re-creating it (adopt or remove it)",
				name, z.recType, fr.Name, fr.Type, fr.Value)})
		return
	}
	upd.Reason = "owned record has a different value and is missing at the provider; re-creating it with the new value"
	pair.cands = append(pair.cands, upd)
}

// eligiblePair returns the breaker counters of z's provider/zone when a row
// of owner service s (nil for the wildcard row) is eligible for repair: the
// pair was listed and the owner's source is available. nil otherwise.
func (p *planner) eligiblePair(z *zoneInfo, s *model.Service) *repairPair {
	pk := z.provider + "/" + z.name
	if _, listed := p.foreign[pk]; !listed || (s != nil && (s.Source == "" || p.obs.Unavailable[s.Source])) {
		return nil
	}
	pair := p.repairPairs[pk]
	if pair == nil {
		pair = &repairPair{provider: z.provider, zone: z.name}
		p.repairPairs[pk] = pair
	}
	return pair
}

// ownedPresence checks a wanted owned row o (owner o.OwnerKey, value equal to
// the zone's desired value) against the provider listing: changed out of
// band is reported with a Skip and never overwritten; missing is a repair
// candidate (DNSEnsure{Repair: true} carrying the stored row's identity,
// emitted by planRepairs subject to the mass-repair breaker and cap), unless
// the owner's source is unavailable or a foreign record now holds the name
// (Conflict). s is the owner's service (nil for the wildcard row).
func (p *planner) ownedPresence(z *zoneInfo, o *store.DNSRecord, key string, s *model.Service) {
	rk := OwnedRowKey(o.Provider, o.Zone, o.Name, o.Type)
	if p.presenceChecked[rk] {
		return // once per row (a winner's row is not re-checked for its owner as a loser)
	}
	p.presenceChecked[rk] = true
	// eligible: the owner's state is known and the pair was listed; only
	// such rows count for the breaker
	pair := p.eligiblePair(z, s)
	if pair != nil {
		pair.wanted++
	}
	if d, ok := p.obs.OwnedDrifted[rk]; ok {
		p.emit(p.driftSkip(z, o, key, s, d))
		return
	}
	if pair == nil || !p.obs.OwnedMissing[rk] {
		return // present, or unknown this cycle: never repair blind
	}
	pair.missing++
	name := normName(o.Name)
	if fr := p.foreignBlocker(z, name); fr != nil {
		p.emit(Action{Kind: Conflict, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
			Record: fr, Owner: o.OwnerKey,
			Reason: fmt.Sprintf("owned record %s %s is missing and a foreign record exists: %s %s %s; not re-creating it (adopt or remove it)",
				name, z.recType, fr.Name, fr.Type, fr.Value)})
		return
	}
	pair.cands = append(pair.cands, Action{Kind: DNSEnsure, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
		Record: &dns.Record{ID: o.ProviderRecordID, Name: name, Type: z.recType, Value: z.value}, Owner: o.OwnerKey,
		Repair: true, Reason: "owned record is missing at the provider; re-creating it"})
}

// planRepairs emits the repair candidates ownedPresence and ownedUpdate
// collected, per
// provider/zone. Breaker: when more than repairBreakerMinMissing wanted rows
// are missing AND they are more than half of the pair's wanted rows, the
// listing is more likely wrong (a wiped server, a zone pinned to the wrong
// hosted zone, a misconfigured provider) than the records gone: ONE Skip
// (Alert AlertDNSMassMissing) is emitted and no repair at all for that pair.
// It holds every cycle while the condition does, and clears by itself once
// it no longer holds. An operator acknowledgement of the pair
// (Observed.RepairMassOK, valid for RepairMassOKTTL) lets the capped repairs
// through instead. Otherwise at most RepairCapPerZone repairs are emitted,
// the first by (name, type, owner key); the rest wait for later cycles.
func (p *planner) planRepairs() {
	keys := make([]string, 0, len(p.repairPairs))
	for k := range p.repairPairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rp := p.repairPairs[k]
		ackAt, acked := p.obs.RepairMassOK[k]
		acked = acked && massOKValid(ackAt, p.now)
		tripped := rp.missing > repairBreakerMinMissing && 2*rp.missing > rp.wanted
		if tripped && !acked {
			p.emit(Action{Kind: Skip, Zone: rp.zone, Host: rp.zone, Key: RepairBreakerKey(rp.provider, rp.zone),
				Provider: rp.provider, Alert: AlertDNSMassMissing, Reason: breakerReason(rp)})
			continue
		}
		// only due rows take a slot; the rest wait for their backoff (still
		// counted in wanted/missing above)
		var c []Action
		for _, a := range rp.cands {
			if due, ok := p.obs.RepairDue[OwnedRowKey(a.Provider, a.Zone, a.Record.Name, a.Record.Type)]; !ok || due {
				c = append(c, a)
			}
		}
		if tripped {
			for i := range c {
				c[i].Reason += fmt.Sprintf(" (mass repair of %s/%s acknowledged at %s: %d of %d missing)",
					rp.provider, rp.zone, ackAt.UTC().Format(time.RFC3339), rp.missing, rp.wanted)
			}
		}
		sort.SliceStable(c, func(i, j int) bool {
			a, b := c[i], c[j]
			if a.Record.Name != b.Record.Name {
				return a.Record.Name < b.Record.Name
			}
			if a.Record.Type != b.Record.Type {
				return a.Record.Type < b.Record.Type
			}
			return a.Owner < b.Owner
		})
		off := RepairRotation(k, p.now, len(c))
		for i := 0; i < len(c) && i < RepairCapPerZone; i++ {
			p.emit(c[(off+i)%len(c)])
		}
	}
}

// RepairRotation is where, in the sorted due repairs of the pair pk
// (provider+"/"+zone), the RepairCapPerZone repairs sent at now start
// (wrapping around): 0 when all fit, else a hash of pk and now's minute
// modulo n. It moves every minute, so rows that fail without a backoff
// cannot hold the cap forever, and being hashed it never locks onto the
// same few offsets whatever the cycle interval is.
func RepairRotation(pk string, now time.Time, n int) int {
	if n <= RepairCapPerZone {
		return 0
	}
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%d", pk, now.Unix()/60)
	return int(h.Sum64() % uint64(n))
}

// breakerReason is the self-describing text of a breaker Skip: what is
// refused, why, and the two ways out (fix the configuration, or acknowledge
// that the records really are gone). The API action lands in T20; the kv
// fallback works before it.
func breakerReason(rp *repairPair) string {
	key := store.RepairMassOKKey(rp.provider, rp.zone)
	return fmt.Sprintf("most owned records missing at %[1]s/%[2]s (%[3]d of %[4]d); refusing mass repair: check the provider and zone configuration. "+
		"Repairs resume by themselves once most records are listed again. "+
		"If the records really are gone, acknowledge it once to re-create them (%[5]d per cycle): "+
		`POST /api/v1/dns/repair/ack {"provider":%[1]q,"zone":%[2]q} (API from T20), or without the API set the kv key %[6]s to the current UTC time in RFC3339 `+
		`(sqlite3 <database> "INSERT OR REPLACE INTO kv(key,value) VALUES('%[6]s',strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ','now'))"); `+
		"the acknowledgement lasts %[7]s and is cleared once the zone has recovered",
		rp.provider, rp.zone, rp.missing, rp.wanted, RepairCapPerZone, key, "24h")
}

// driftSkip reports an owned record whose value was changed out of band.
func (p *planner) driftSkip(z *zoneInfo, o *store.DNSRecord, key string, s *model.Service, listed []dns.Record) Action {
	vals := make([]string, 0, len(listed))
	for _, r := range listed {
		vals = append(vals, r.Value)
	}
	name := normName(o.Name)
	rec := dns.Record{ID: o.ProviderRecordID, Name: name, Type: normType(o.Type), Value: o.Value}
	return Action{Kind: Skip, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider, Record: &rec,
		Owner: o.OwnerKey, Reason: fmt.Sprintf("owned record %s %s changed out of band (the provider has %s, doorwarden stored %s); not overwriting it",
			name, rec.Type, strings.Join(vals, ", "), o.Value)}
}

// owned returns the ownership row for (provider, zone, name, type), if any.
func (p *planner) owned(z *zoneInfo, name, typ string) *store.DNSRecord {
	for i := range p.obs.Owned {
		o := &p.obs.Owned[i]
		if o.Provider == z.provider && normName(o.Zone) == z.name && normName(o.Name) == name && normType(o.Type) == typ {
			return o
		}
	}
	return nil
}

// covered reports whether every name is covered by some cert row that has not
// expired. Status is ignored (its vocabulary belongs to the ACME manager);
// renewal timing is the ACME manager's job, not the plan's.
func (p *planner) covered(names ...string) bool {
	for _, n := range names {
		ok := false
		for _, c := range p.obs.Certs {
			if c.NotAfter.After(p.now) && certCovers(c, n) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func certCovers(c store.Cert, name string) bool {
	var domains []string
	if err := json.Unmarshal([]byte(c.DomainsJSON), &domains); err != nil {
		return false
	}
	for _, d := range domains {
		d = normName(d)
		if d == name {
			return true
		}
		if rest, ok := strings.CutPrefix(d, "*."); ok && !strings.HasPrefix(name, "*.") {
			if i := strings.IndexByte(name, '.'); i > 0 && name[i+1:] == rest {
				return true
			}
		}
	}
	return false
}

// planRemovals handles the routes of known services absent from desired.
// Their DNS records are handled by planOrphans, like every other record.
func (p *planner) planRemovals(present map[string]bool, losers map[string]loss) {
	for _, k := range sortedKnown(p.obs.Known) {
		if present[k.Key] || p.unavailable(k) {
			continue // present, or unknown state: never schedule or remove
		}
		zn, host := normName(k.Zone), normName(k.Hostname)
		if l, lost := losers[k.Key]; lost && p.takesOver(k.Key, k.Source, l.winner) {
			// a present Published, routable service of the same or a higher
			// source rank takes over its hostname now: remove its route
			// without waiting for the grace period (its owned DNS record is
			// an orphan, removed after the grace period by planOrphans).
			p.emit(Action{Kind: RouteRemove, Zone: zn, Host: host, Key: k.Key, Cause: CauseTakeover,
				Reason: "service no longer discovered and hostname " + host + " now belongs to published " + l.winner.key})
			continue
		}
		if k.RemovedAfter == nil {
			ra := p.now.Add(p.grace)
			p.emit(Action{Kind: ScheduleRemoval, Zone: zn, Host: host, Key: k.Key, RemovedAfter: &ra,
				Reason: "service no longer discovered"})
			continue
		}
		if !p.now.After(*k.RemovedAfter) {
			continue // still within grace
		}
		ra := *k.RemovedAfter
		p.emit(Action{Kind: RouteRemove, Zone: zn, Host: host, Key: k.Key, Cause: CauseRemovalGrace, RemovedAfter: &ra,
			Reason: "grace period expired"})
	}
}

// routeBackend returns the backend a RouteWrite for s would carry: its own
// when authoritative, else its last-known one; ok is false when neither.
func (p *planner) routeBackend(s model.Service) (model.Backend, bool) {
	if authoritative(s.Backend) {
		return s.Backend, true
	}
	if lk, ok := p.obs.LastKnown[s.Key]; ok && authoritative(lk) {
		return lk, true
	}
	return model.Backend{}, false
}

// mayRemoveLoserRoute reports whether a hostname loser's existing route may be
// removed: only when the winner really takes over the name in this same plan
// (published, gets a RouteWrite, not a phantom, at least the loser's source
// rank) and the loser's source is available (an outage never removes).
func (p *planner) mayRemoveLoserRoute(loser model.Service, w claimant) bool {
	return p.takesOver(loser.Key, loser.Source, w)
}

// takesOver is the single rule for removing a hostname loser's route (a
// present loser or an absent known service): the loser's source is
// available and the winner is Published, routable, not a phantom, and of the
// same or a higher source rank.
func (p *planner) takesOver(key, source string, w claimant) bool {
	if source == "" || p.obs.Unavailable[source] {
		return false
	}
	return !w.phantom && w.published && w.routable && w.rank() <= model.SourceRank(key, source)
}

func sortedKnown(m map[string]KnownService) []KnownService {
	out := make([]KnownService, 0, len(m))
	for key, k := range m {
		if k.Key == "" {
			k.Key = key
		}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// authoritative reports whether b is routable. It is model.ValidateBackend,
// the same predicate the route store enforces, so a RouteWrite the plan
// emits is never rejected by the store for its backend.
func authoritative(b model.Backend) bool { return model.ValidateBackend(b) == nil }

func sameValue(a, b string) bool {
	if a == b {
		return true
	}
	x, err1 := netip.ParseAddr(strings.TrimSpace(a))
	y, err2 := netip.ParseAddr(strings.TrimSpace(b))
	return err1 == nil && err2 == nil && x.Unmap() == y.Unmap()
}

func copySvc(s model.Service) *model.Service {
	s.Options.Middlewares = append([]string(nil), s.Options.Middlewares...)
	return &s
}

func copySvcPtr(s *model.Service) *model.Service {
	if s == nil {
		return nil
	}
	return copySvc(*s)
}

func sortActions(as []Action) {
	rank := map[ActionKind]int{}
	for i, k := range KindOrder {
		rank[k] = i
	}
	key := func(a Action) []string {
		r := []string{a.Zone, a.Host, a.Key, a.Provider}
		if a.Record != nil {
			r = append(r, a.Record.Name, a.Record.Type, a.Record.Value)
		} else {
			r = append(r, "", "", "")
		}
		return append(r, a.Reason)
	}
	sort.SliceStable(as, func(i, j int) bool {
		if ri, rj := rank[as[i].Kind], rank[as[j].Kind]; ri != rj {
			return ri < rj
		}
		ki, kj := key(as[i]), key(as[j])
		for n := range ki {
			if ki[n] != kj[n] {
				return ki[n] < kj[n]
			}
		}
		return false
	})
}

func backendProblem(b model.Backend) string {
	if err := model.ValidateBackend(b); err != nil {
		return err.Error()
	}
	return "ok"
}
