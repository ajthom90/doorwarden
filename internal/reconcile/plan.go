package reconcile

import (
	"encoding/json"
	"errors"
	"fmt"
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

	sortActions(p.out)
	return p.out, winners
}

func newPlanner(obs Observed, cfg *config.Config, now time.Time) *planner {
	p := &planner{obs: obs, now: now, grace: cfg.Settings.GracePeriod, zones: map[string]*zoneInfo{},
		foreign: map[string][]dns.Record{}}
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
// the service key ("" for the wildcard record).
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
		p.emit(Action{Kind: DNSEnsure, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
			Record: &want, Owner: owner, Reason: "owned record has a different value"})
		return
	}
	listing, listed := p.foreign[z.provider+"/"+z.name]
	if !listed {
		p.emit(Action{Kind: Skip, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
			Reason: fmt.Sprintf("foreign records for %s/%s unknown; not creating %s", z.provider, z.name, name)})
		return
	}
	for _, f := range listing {
		ft := normType(f.Type)
		if normName(f.Name) != name || (ft != z.recType && ft != "CNAME") || p.owned(z, name, ft) != nil {
			continue
		}
		fr := dns.Record{ID: f.ID, Name: normName(f.Name), Type: ft, Value: f.Value, TTL: f.TTL}
		p.emit(Action{Kind: Conflict, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
			Record: &fr, Owner: owner,
			Reason: fmt.Sprintf("foreign record exists: %s %s %s (adopt or skip it)", fr.Name, fr.Type, fr.Value)})
		return
	}
	p.emit(Action{Kind: DNSEnsure, Zone: z.name, Host: name, Key: key, Svc: copySvcPtr(s), Provider: z.provider,
		Record: &want, Owner: owner})
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
