package reconcile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// keyPrefixSources are the key prefixes whose source can be inferred when a
// row's owner is neither in desired nor Known (see ownerSourceUnknown).
var keyPrefixSources = map[string]bool{"static": true, "truenas": true, "docker": true}

// rowKey identifies one record slot: provider, normalized zone, name, type.
func rowKey(provider, zone, name, typ string) string {
	return provider + "|" + normName(zone) + "|" + normName(name) + "|" + normType(typ)
}

// ownerWants is what one present owner key needs from the ownership table.
type ownerWants struct {
	svc model.Service
	// protected: the owner is present but not cleanly Published (or its
	// wanted set cannot be computed): none of its rows is an orphan, and a
	// scheduled removal stays as it is (neither cancelled nor executed).
	protected bool
	wants     map[string]bool // rowKey set
}

// presentOwners classifies every present (deduplicated) desired service for
// the orphan rule. A Published service whose labels resolve, whose source is
// available and that has a route backend wants exactly the per-host record
// planService would ensure for it (winner or hostname loser alike); every
// other present service is protected.
func (p *planner) presentOwners(entries []entry) map[string]*ownerWants {
	out := map[string]*ownerWants{}
	for _, e := range entries {
		o := &ownerWants{svc: e.svc, wants: map[string]bool{}}
		out[e.svc.Key] = o
		_, routable := p.routeBackend(e.svc)
		switch {
		case e.svc.Source == "" || p.obs.Unavailable[e.svc.Source],
			e.svc.State != model.StatePublished, e.err != nil, e.heldInvalid, !routable:
			o.protected = true
			continue
		}
		z := p.zones[e.zone]
		if z == nil || z.mode != "per-host" {
			continue // wants no per-host record
		}
		if z.recType == "" {
			o.protected = true // target_ip unusable: the wanted type is unknown
			continue
		}
		o.wants[rowKey(z.provider, z.name, e.host, z.recType)] = true
	}
	return out
}

// sourceEvidence maps a key prefix to the source names seen on this cycle's
// desired services and Known entries with that prefix.
func (p *planner) sourceEvidence(entries []entry) map[string]map[string]bool {
	ev := map[string]map[string]bool{}
	add := func(key, src string) {
		i := strings.IndexByte(key, ':')
		if i <= 0 || src == "" {
			return
		}
		pre := key[:i]
		if ev[pre] == nil {
			ev[pre] = map[string]bool{}
		}
		ev[pre][src] = true
	}
	for _, e := range entries {
		add(e.svc.Key, e.svc.Source)
	}
	for _, k := range sortedKnown(p.obs.Known) {
		add(k.Key, k.Source)
	}
	return ev
}

// ownerSourceUnknown reports, for an owner key absent from desired, whether
// its source's state is unknown this cycle (then its rows are never
// scheduled or deleted). With a Known entry its recorded source decides
// (planner.unavailable). Otherwise the key prefix must be static, truenas or
// docker; the source is unknown when any candidate name for that prefix
// (the prefix itself, compared case-insensitively, and every source name
// carried by a desired or Known key with that prefix) is Unavailable, or
// when an Unavailable source name maps to no prefix at all (it could be the
// owner's renamed source).
func (p *planner) ownerSourceUnknown(owner string, ev map[string]map[string]bool) bool {
	if k, ok := p.obs.Known[owner]; ok {
		if k.Key == "" {
			k.Key = owner
		}
		return p.unavailable(k)
	}
	i := strings.IndexByte(owner, ':')
	if i <= 0 || !keyPrefixSources[owner[:i]] {
		return true
	}
	pre := owner[:i]
	for name, down := range p.obs.Unavailable {
		if !down {
			continue
		}
		ln := strings.ToLower(name)
		if ln == pre || ev[pre][name] {
			return true
		}
		mapped := keyPrefixSources[ln]
		for _, names := range ev {
			mapped = mapped || names[name]
		}
		if !mapped {
			return true
		}
	}
	return false
}

// reassignTarget returns the present owner an orphan row (owner no longer
// wants it) is handed over to, or nil: the hostname's winner, when it is a
// present, cleanly Published service other than owner that wants exactly
// this row (same provider, zone, name and type) and the stored value equals
// the zone's desired value. A loser that also wants the row never gets it.
func reassignTarget(owners map[string]*ownerWants, winners map[string]claimant, owner, name, rk, value string, z *zoneInfo) *ownerWants {
	w, ok := winners[name]
	if !ok || w.key == owner || w.phantom || !w.published || !w.routable {
		return nil
	}
	to := owners[w.key]
	if to == nil || to.protected || !to.wants[rk] || to.svc.State != model.StatePublished || !sameValue(value, z.value) {
		return nil
	}
	return to
}

// planOrphans is the single DNS deletion path: it schedules, cancels and
// executes the removal of owned per-host records whose owner no longer
// wants them (see the package documentation, "Orphan DNS records").
func (p *planner) planOrphans(entries []entry, winners map[string]claimant) {
	owners := p.presentOwners(entries)
	ev := p.sourceEvidence(entries)
	ensured := map[string]bool{}
	for _, a := range p.out {
		if a.Kind == DNSEnsure && a.Record != nil {
			ensured[rowKey(a.Provider, a.Zone, a.Record.Name, a.Record.Type)] = true
		}
	}
	wildcardOwned := map[string]bool{} // zone -> its "*.zone" row is owned
	for _, o := range p.obs.Owned {
		zn := normName(o.Zone)
		if z := p.zones[zn]; z != nil && o.Provider == z.provider && normName(o.Name) == "*."+zn &&
			o.OwnerKey == WildcardOwnerKey(zn) {
			wildcardOwned[zn] = true
		}
	}
	rows := append([]store.DNSRecord(nil), p.obs.Owned...)
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if ka, kb := rowKey(a.Provider, a.Zone, a.Name, a.Type), rowKey(b.Provider, b.Zone, b.Name, b.Type); ka != kb {
			return ka < kb
		}
		return a.OwnerKey < b.OwnerKey
	})
	for _, o := range rows {
		zn, name, typ, owner := normName(o.Zone), normName(o.Name), normType(o.Type), o.OwnerKey
		if owner == "" || strings.HasPrefix(strings.ToLower(owner), "zone:") || strings.HasPrefix(name, "*.") {
			continue // (c) the wildcard record, and rows without an owner, are never removed automatically
		}
		rec := dns.Record{ID: o.ProviderRecordID, Name: name, Type: typ, Value: o.Value}
		base := Action{Zone: zn, Host: name, Key: owner, Provider: o.Provider, Record: &rec, Owner: owner}
		z := p.zones[zn]
		if z == nil {
			base.Kind, base.Reason = Skip, fmt.Sprintf("zone %s is not configured; owned record %s %s (owner %s) is left alone: it cannot be verified", zn, name, typ, owner)
			p.emit(base)
			continue // (e)
		}
		if z.mode != "per-host" && z.mode != "wildcard" {
			continue // (d) records mode off: never touch anything
		}
		if o.Provider != z.provider {
			base.Kind, base.Reason = Skip, fmt.Sprintf("zone %s now uses records provider %s; owned record %s %s at provider %s (owner %s) is left alone: it cannot be verified",
				zn, z.provider, name, typ, o.Provider, owner)
			p.emit(base)
			continue // (e)
		}
		rk := rowKey(o.Provider, zn, name, typ)
		ow, present := owners[owner]
		if present && ow.wants[rk] {
			if o.RemovedAfter != nil {
				base.Kind, base.Svc, base.Reason = DNSCancelRemoval, copySvc(ow.svc), "record is wanted again"
				p.emit(base)
			}
			continue
		}
		if ensured[rk] {
			continue // never remove what this plan ensures
		}
		if present && ow.protected {
			continue // (a) present but not cleanly Published: keeps its records
		}
		if !present && p.ownerSourceUnknown(owner, ev) {
			continue // (b) a source outage means unknown, never gone
		}
		if z.mode == "wildcard" && !wildcardOwned[zn] {
			continue // (d) leftover per-host rows wait until the wildcard record exists
		}
		if to := reassignTarget(owners, winners, owner, name, rk, o.Value, z); to != nil {
			// the hostname's winner wants exactly this record: hand it over
			// instead of deleting and re-creating it (no DNS gap)
			base.Kind, base.Key, base.Svc, base.NewOwner = DNSReassign, to.svc.Key, copySvc(to.svc), to.svc.Key
			base.Reason = fmt.Sprintf("%s no longer wants this record and %s serves %s with the same value", owner, to.svc.Key, name)
			p.emit(base)
			continue
		}
		var reason string
		deadline := p.now.Add(p.grace)
		if present {
			base.Svc = copySvc(ow.svc)
			reason = "service no longer wants this record (renamed, moved, or the zone's records mode changed)"
		} else {
			reason = "service no longer discovered"
			if k, ok := p.obs.Known[owner]; ok && k.RemovedAfter != nil {
				deadline = *k.RemovedAfter // remove the record together with the route
			}
		}
		switch {
		case o.RemovedAfter == nil:
			base.Kind, base.Reason, base.RemovedAfter = DNSScheduleRemoval, reason, &deadline
			p.emit(base)
		case p.now.After(*o.RemovedAfter):
			// the delete names the schedule it was planned for: the executor
			// refuses unless the stored row still has it
			ra := *o.RemovedAfter
			base.Kind, base.Reason, base.RemovedAfter = DNSDelete, reason+"; grace period expired", &ra
			p.emit(base)
		}
	}
}
