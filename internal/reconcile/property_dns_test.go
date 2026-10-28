package reconcile

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// dnsPropSeeds is the number of deterministic cases
// TestPropertyDNSOrphanInvariants checks (pure Plan, no store).
const dnsPropSeeds = 3000

type dnsPropCase struct {
	cfg         *config.Config
	desired     []model.Service
	obs         Observed
	modes       map[string]string // zone -> records mode
	desc        []string
	unavailable map[string]bool
	alias       map[string]string // key prefix -> its source's name
}

// srcOf is the source name key's service really has: its prefix's alias, or
// the prefix itself for prefixes without one.
func (c dnsPropCase) srcOf(key string) string {
	if a, ok := c.alias[sourceOf(key)]; ok {
		return a
	}
	return sourceOf(key)
}

// dnsPropAliases are source naming schemes: the identity (Source equals the
// key prefix) and names unrelated to, or swapped with, the prefixes (a
// TrueNAS source named "docker").
var dnsPropAliases = []map[string]string{
	{"static": "static", "truenas": "truenas", "docker": "docker"},
	{"static": "files", "truenas": "docker", "docker": "dock1"},
	{"static": "static", "truenas": "docker", "docker": "truenas"},
	{"static": "static", "truenas": "nas", "docker": "docker"},
}

var dnsPropOwners = []string{"static:a", "truenas:a", "docker:a", "docker:b", "other:a", "", "zone:example.test"}

func genDNSProp(r *rand.Rand) dnsPropCase {
	c := dnsPropCase{modes: map[string]string{}, unavailable: map[string]bool{}, alias: dnsPropAliases[0]}
	if r.Intn(3) == 0 {
		c.alias = dnsPropAliases[1+r.Intn(len(dnsPropAliases)-1)]
	}
	modes := []string{"per-host", "per-host", "wildcard", "off"}
	zA, zB := zone("example.test", "per-host", "wildcard"), zone("other.test", modes[r.Intn(len(modes))], "wildcard")
	if r.Intn(5) == 0 {
		zA.Records.Mode = modes[r.Intn(len(modes))]
	}
	if r.Intn(8) == 0 {
		zA.TargetIP = "2001:db8::10"
	}
	c.cfg = cfgOf(zA, zB)
	c.modes["example.test"], c.modes["other.test"] = zA.Records.Mode, zB.Records.Mode
	for _, src := range []string{"static", "truenas", "docker"} {
		if r.Intn(5) == 0 {
			c.unavailable[c.alias[src]] = true
		}
	}
	zones := []string{"example.test", "other.test", "gone.test"}
	names := []string{"app", "web", "api"}
	ras := []*time.Time{nil, nil, tp(t0.Add(-time.Hour)), tp(t0), tp(t0.Add(time.Hour))}
	c.obs = Observed{Foreign: listed("example.test", "other.test"), Known: map[string]KnownService{},
		Unavailable: c.unavailable}
	for _, k := range propKeys {
		role := r.Intn(8)
		name, zn := names[r.Intn(len(names))], zones[r.Intn(2)]
		var s model.Service
		switch role {
		case 2, 3:
			s = pub(k, name, zn, 2000)
		case 4:
			s = pub(k, name, zn, 0) // no backend
		case 5:
			s = svc(k, name, zn, []string{model.StateStopped, model.StatePending, model.StateError}[r.Intn(3)], "198.51.100.5", 3000)
		case 6:
			s = pub(k, name, "missing.test", 2000) // invalid labels
		case 7:
			s = pub(k, name, zn, 2000)
			s.Options.Middlewares = []string{"undefined@file"}
		} // 0, 1: absent
		s.Source = c.srcOf(k)
		if s.Key != "" && !c.unavailable[s.Source] {
			c.desired = append(c.desired, s)
		}
		if r.Intn(2) == 0 {
			kn := known(k, zn, names[r.Intn(len(names))]+"."+zn, ras[r.Intn(len(ras))])
			kn.Source = c.srcOf(k)
			c.obs.Known[k] = kn
			c.obs.LastKnown = map[string]model.Backend{}
		}
		c.desc = append(c.desc, fmt.Sprintf("%s (source %q) role=%d %s.%s", k, c.srcOf(k), role, name, zn))
	}
	seen := map[string]bool{}
	for i := 0; i < 2+r.Intn(8); i++ {
		owner := dnsPropOwners[r.Intn(len(dnsPropOwners))]
		zn := zones[r.Intn(len(zones))]
		name := names[r.Intn(len(names))] + "." + zn
		if r.Intn(10) == 0 {
			name = "*." + zn
		}
		typ := []string{"A", "A", "AAAA"}[r.Intn(3)]
		if seen[zn+name+typ] {
			continue
		}
		seen[zn+name+typ] = true
		o := ownedRA(zn, name, typ, target, owner, ras[r.Intn(len(ras))])
		if r.Intn(15) == 0 {
			o.Provider = "oldp"
		}
		c.obs.Owned = append(c.obs.Owned, o)
		c.desc = append(c.desc, fmt.Sprintf("row %s %s %s owner=%q ra=%v", o.Provider, name, typ, owner, o.RemovedAfter))
	}
	return c
}

// propWanted is the test's own statement of "the owner wants this row".
func propWanted(c dnsPropCase, s model.Service, o store.DNSRecord) bool {
	if s.State != model.StatePublished || s.Backend.Port == 0 || len(s.Options.Middlewares) > 0 || s.Zone == "missing.test" {
		return false
	}
	typ := "A"
	if c.cfg.Zones[0].TargetIP != target && s.Zone == "example.test" {
		typ = "AAAA"
	}
	return c.modes[s.Zone] == "per-host" && o.Provider == "dnsp" && o.Zone == s.Zone && o.Name == s.Name+"."+s.Zone && o.Type == typ
}

// propProtected is the test's own statement of "present but not cleanly
// Published": such an owner keeps its rows, and a schedule is cancelled.
func propProtected(c dnsPropCase, s model.Service) bool {
	return s.State != model.StatePublished || s.Backend.Port == 0 || len(s.Options.Middlewares) > 0 ||
		s.Zone == "missing.test" || c.unavailable[s.Source]
}

func TestPropertyDNSOrphanInvariants(t *testing.T) {
	var scheduled, deleted, cancelled, reassigned, completeChecked int
	for seed := int64(0); seed < dnsPropSeeds; seed++ {
		r := rand.New(rand.NewSource(seed))
		c := genDNSProp(r)
		acts := Plan(c.desired, c.obs, c.cfg, t0)
		fail := func(f string, a ...any) {
			t.Helper()
			t.Fatalf("seed %d: %s\ncase %v\nunavailable %v\nacts %v", seed, fmt.Sprintf(f, a...), c.desc, c.unavailable, sums(acts))
		}
		present := map[string]model.Service{}
		for _, s := range c.desired {
			present[s.Key] = s
		}
		rowOf := func(a Action) store.DNSRecord {
			for _, o := range c.obs.Owned {
				if o.Provider == a.Provider && o.Zone == a.Zone && o.Name == a.Record.Name && o.Type == a.Record.Type {
					return o
				}
			}
			fail("%s for a row that is not owned: %s", a.Kind, sum(a))
			return store.DNSRecord{}
		}
		checkNoEnsureAndRemoval(t, acts)
		got := map[string]ActionKind{}
		for _, a := range acts {
			if a.Kind != DNSScheduleRemoval && a.Kind != DNSDelete && a.Kind != DNSCancelRemoval && a.Kind != DNSReassign {
				continue
			}
			o := rowOf(a)
			if prev, dup := got[o.Zone+" "+o.Name+" "+o.Type]; dup {
				fail("two lifecycle actions for one row: %s and %s", prev, sum(a))
			}
			got[o.Zone+" "+o.Name+" "+o.Type] = a.Kind
			if a.Owner != o.OwnerKey || a.Record.ID != o.ProviderRecordID || a.Record.Value != o.Value {
				fail("%s does not carry the stored row: %s", a.Kind, sum(a))
			}
			if strings.HasPrefix(o.OwnerKey, "zone:") || o.OwnerKey == "" || strings.HasPrefix(o.Name, "*.") {
				fail("%s for a wildcard/ownerless row", a.Kind)
			}
			if c.modes[o.Zone] != "per-host" && c.modes[o.Zone] != "wildcard" || o.Provider != "dnsp" {
				fail("%s in an unmanaged zone or under another provider", a.Kind)
			}
			s, isPresent := present[o.OwnerKey]
			wanted := isPresent && propWanted(c, s, o)
			if a.Kind == DNSCancelRemoval {
				cancelled++
				if !(wanted || isPresent && propProtected(c, s)) || o.RemovedAfter == nil {
					fail("cancel for an unwanted or unscheduled row of a non-protected owner")
				}
				continue
			}
			if wanted {
				fail("%s for a wanted row", a.Kind)
			}
			if a.Kind == DNSReassign {
				reassigned++
				ns, ok := present[a.NewOwner]
				if !ok || a.NewOwner == o.OwnerKey || a.Key != a.NewOwner || a.Svc == nil || a.Svc.Key != a.NewOwner {
					fail("reassign to an absent or inconsistent new owner: %s", sum(a))
				}
				if !propWanted(c, ns, o) || ns.State != model.StatePublished || c.unavailable[ns.Source] {
					fail("reassign to a new owner that does not want the row: %s", sum(a))
				}
				if ns.Zone == "example.test" && c.cfg.Zones[0].TargetIP != o.Value {
					fail("reassign with a value the new owner does not want: %s", sum(a))
				}
			}
			if isPresent && (s.State != model.StatePublished || s.Backend.Port == 0 || len(s.Options.Middlewares) > 0 || s.Zone == "missing.test") {
				fail("%s for a present non-Published or invalid owner", a.Kind)
			}
			// an absent owner's source: its Known entry's, else the source
			// its key prefix really belongs to (the planner sees only the
			// prefix), which must be static, truenas or docker
			pre := sourceOf(o.OwnerKey)
			src, inferred := c.srcOf(o.OwnerKey), true
			if k, ok := c.obs.Known[o.OwnerKey]; ok {
				src, inferred = k.Source, false
			}
			if !isPresent && (c.unavailable[src] || inferred && pre != "static" && pre != "truenas" && pre != "docker") {
				fail("%s for an owner whose source is unavailable or unknown", a.Kind)
			}
			switch a.Kind {
			case DNSScheduleRemoval:
				scheduled++
				if o.RemovedAfter != nil {
					fail("schedule for an already scheduled row")
				}
				want := t0.Add(24 * time.Hour)
				if k, ok := c.obs.Known[o.OwnerKey]; ok && !isPresent && k.RemovedAfter != nil {
					want = *k.RemovedAfter
				}
				if a.RemovedAfter == nil || !a.RemovedAfter.Equal(want) {
					fail("schedule deadline %v, want %v", a.RemovedAfter, want)
				}
			case DNSDelete:
				deleted++
				if o.RemovedAfter == nil || !t0.After(*o.RemovedAfter) {
					fail("delete before the deadline")
				}
			}
		}
		// Completeness: every wanted scheduled row is cancelled, and a plain
		// orphan (absent owner, no outage at all, per-host zone, our
		// provider) is scheduled or deleted on time, or reassigned when a
		// present service wants exactly that row.
		for _, o := range c.obs.Owned {
			k := o.Zone + " " + o.Name + " " + o.Type
			s, isPresent := present[o.OwnerKey]
			if isPresent && propWanted(c, s, o) && o.RemovedAfter != nil && got[k] != DNSCancelRemoval {
				fail("wanted scheduled row %s not cancelled", k)
			}
			if isPresent && propProtected(c, s) && o.RemovedAfter != nil && got[k] != DNSCancelRemoval &&
				!strings.HasPrefix(o.Name, "*.") && c.modes[o.Zone] != "off" && c.modes[o.Zone] != "" && o.Provider == "dnsp" && o.Zone != "gone.test" {
				fail("scheduled row %s of a present protected owner not cancelled", k)
			}
			pre := sourceOf(o.OwnerKey)
			if isPresent || len(c.unavailable) > 0 || c.modes[o.Zone] != "per-host" || o.Provider != "dnsp" ||
				strings.HasPrefix(o.Name, "*.") || (pre != "static" && pre != "truenas" && pre != "docker") {
				continue
			}
			completeChecked++
			if got[k] == DNSReassign {
				continue // checked above: the new owner wants the row
			}
			switch {
			case o.RemovedAfter == nil && got[k] != DNSScheduleRemoval:
				fail("orphan %s not scheduled", k)
			case o.RemovedAfter != nil && t0.After(*o.RemovedAfter) && got[k] != DNSDelete:
				fail("orphan %s past its deadline not deleted", k)
			case o.RemovedAfter != nil && !t0.After(*o.RemovedAfter) && got[k] != "":
				fail("orphan %s within grace got %s", k, got[k])
			}
		}
		// Determinism under input order of desired and Owned.
		if seed%10 == 0 {
			for i := 0; i < 5; i++ {
				d := append([]model.Service(nil), c.desired...)
				ow := append([]store.DNSRecord(nil), c.obs.Owned...)
				r.Shuffle(len(d), func(a, b int) { d[a], d[b] = d[b], d[a] })
				r.Shuffle(len(ow), func(a, b int) { ow[a], ow[b] = ow[b], ow[a] })
				obs := c.obs
				obs.Owned = ow
				if again := Plan(d, obs, c.cfg, t0); !reflect.DeepEqual(again, acts) {
					fail("plan depends on input order")
				}
			}
		}
	}
	t.Logf("scheduled %d, deleted %d, cancelled %d, reassigned %d, complete-checked %d", scheduled, deleted, cancelled, reassigned, completeChecked)
	for n, v := range map[string]int{"scheduled": scheduled, "deleted": deleted, "cancelled": cancelled, "reassigned": reassigned, "complete-checked": completeChecked} {
		if v == 0 {
			t.Errorf("%s is 0: the check never ran", n)
		}
	}
}

// genDriftProp extends a genDNSProp case with drift: rows of listed zones
// are randomly missing at the provider or changed out of band, and foreign
// records (a CNAME, or a record of the row's type) randomly sit at owned
// names. It draws from r only after genDNSProp, so the base cases are the
// same as TestPropertyDNSOrphanInvariants'.
func genDriftProp(r *rand.Rand) dnsPropCase {
	c := genDNSProp(r)
	c.obs.OwnedMissing, c.obs.OwnedDrifted = map[string]bool{}, map[string][]dns.Record{}
	for _, o := range c.obs.Owned {
		if _, ok := c.obs.Foreign[o.Provider+"/"+o.Zone]; !ok {
			continue // not listed: unknown
		}
		k := OwnedRowKey(o.Provider, o.Zone, o.Name, o.Type)
		switch r.Intn(6) {
		case 0, 1, 2:
			c.obs.OwnedMissing[k] = true
			c.desc = append(c.desc, "missing "+k)
		case 3:
			c.obs.OwnedDrifted[k] = []dns.Record{{ID: "x", Name: o.Name, Type: o.Type, Value: ipFX}}
			c.desc = append(c.desc, "drifted "+k)
		}
		if r.Intn(6) == 0 {
			typ := []string{"CNAME", "AAAA", "A", "TXT"}[r.Intn(4)]
			if typ == o.Type {
				continue // a record at an owned name+type is never foreign
			}
			f := dns.Record{ID: "f", Name: o.Name, Type: typ, Value: "foreign.test"}
			c.obs.Foreign["dnsp/"+o.Zone] = append(c.obs.Foreign["dnsp/"+o.Zone], f)
			c.desc = append(c.desc, "foreign "+o.Name+" "+typ)
		}
	}
	return c
}

func TestPropertyDNSRepairInvariants(t *testing.T) {
	var repaired, completeChecked, drifted int
	for seed := int64(0); seed < dnsPropSeeds; seed++ {
		r := rand.New(rand.NewSource(seed))
		c := genDriftProp(r)
		acts := Plan(c.desired, c.obs, c.cfg, t0)
		fail := func(f string, a ...any) {
			t.Helper()
			t.Fatalf("seed %d: %s\ncase %v\nunavailable %v\nacts %v", seed, fmt.Sprintf(f, a...), c.desc, c.unavailable, sums(acts))
		}
		checkNoEnsureAndRemoval(t, acts)
		present := map[string]model.Service{}
		for _, s := range c.desired {
			present[s.Key] = s
		}
		zoneVal := func(zn string) string {
			if zn == "example.test" {
				return c.cfg.Zones[0].TargetIP
			}
			return target
		}
		blocked := func(o store.DNSRecord) bool {
			for _, f := range c.obs.Foreign["dnsp/"+o.Zone] {
				if f.Name == o.Name && (f.Type == o.Type || f.Type == "CNAME") {
					return true
				}
			}
			return false
		}
		ensuredSlot := map[string]int{}
		perPair, tripped := map[string]int{}, map[string]bool{}
		for _, a := range ofKind(acts, DNSEnsure) {
			ensuredSlot[OwnedRowKey(a.Provider, a.Zone, a.Record.Name, a.Record.Type)]++
			if a.Repair {
				perPair[a.Provider+"/"+a.Zone]++
			}
		}
		for _, a := range breakerSkips(acts) {
			tripped[a.Provider+"/"+a.Zone] = true
		}
		for pk, n := range perPair {
			if n > RepairCapPerZone || tripped[pk] {
				fail("%d repairs at %s (breaker tripped: %v)", n, pk, tripped[pk])
			}
		}
		got := map[string]int{}
		for _, a := range acts {
			if !a.Repair {
				continue
			}
			if a.Kind != DNSEnsure {
				fail("Repair on %s", sum(a))
			}
			var o *store.DNSRecord
			for i := range c.obs.Owned {
				x := &c.obs.Owned[i]
				if x.Provider == a.Provider && x.Zone == a.Zone && x.Name == a.Record.Name && x.Type == a.Record.Type {
					o = x
				}
			}
			if o == nil {
				fail("repair of a row that is not owned: %s", sum(a))
			}
			k := OwnedRowKey(o.Provider, o.Zone, o.Name, o.Type)
			got[k]++
			repaired++
			if got[k] > 1 || ensuredSlot[k] > 1 {
				fail("two ensures for one row: %s", sum(a))
			}
			if !c.obs.OwnedMissing[k] || c.obs.OwnedDrifted[k] != nil {
				fail("repair of a row that is not missing: %s", sum(a))
			}
			if a.Owner != o.OwnerKey || a.Record.ID != o.ProviderRecordID || a.Record.Value != o.Value || a.Record.Value != zoneVal(o.Zone) {
				fail("repair does not carry the stored row: %s", sum(a))
			}
			if blocked(*o) {
				fail("repair over a foreign record: %s", sum(a))
			}
			if strings.HasPrefix(o.Name, "*.") {
				if o.OwnerKey != WildcardOwnerKey(o.Zone) || c.modes[o.Zone] != "wildcard" {
					fail("repair of a wildcard row outside wildcard mode or not zone-owned: %s", sum(a))
				}
				continue
			}
			s, isPresent := present[o.OwnerKey]
			if !isPresent || !propWanted(c, s, *o) || propProtected(c, s) || c.unavailable[s.Source] {
				fail("repair for an orphan, protected or unavailable owner: %s", sum(a))
			}
		}
		for _, o := range c.obs.Owned {
			k := OwnedRowKey(o.Provider, o.Zone, o.Name, o.Type)
			if c.obs.OwnedDrifted[k] != nil {
				drifted++
				if ensuredSlot[k] > 0 {
					fail("ensure over a record changed out of band: %s", k)
				}
				continue
			}
			s, isPresent := present[o.OwnerKey]
			if !c.obs.OwnedMissing[k] || !isPresent || !propWanted(c, s, o) || propProtected(c, s) ||
				o.Value != zoneVal(o.Zone) || blocked(o) {
				continue
			}
			if tripped[o.Provider+"/"+o.Zone] {
				continue
			}
			completeChecked++
			if got[k] != 1 {
				fail("wanted missing row %s not repaired", k)
			}
		}
	}
	t.Logf("repaired %d, complete-checked %d, drifted %d", repaired, completeChecked, drifted)
	if repaired == 0 || completeChecked == 0 || drifted == 0 {
		t.Error("a check never ran")
	}
}

// TestPropertyDNSRepairBreaker checks the mass-repair breaker and the
// per-zone cap against the test's own statement of them, on one per-host zone
// with many owners: some absent (orphans), some stopped (protected), some from
// an unavailable source, rows randomly missing, drifted or blocked by a
// foreign CNAME.
func TestPropertyDNSRepairBreaker(t *testing.T) {
	var trips, capped, under int
	for seed := int64(0); seed < 2000; seed++ {
		r := rand.New(rand.NewSource(seed))
		obs := Observed{Foreign: listed("example.test"), OwnedMissing: map[string]bool{}, OwnedDrifted: map[string][]dns.Record{}}
		if r.Intn(3) == 0 {
			obs.Unavailable = map[string]bool{"truenas": true}
		}
		var desired []model.Service
		var eligibleMissing []string // names of unblocked eligible missing rows
		wanted, miss := 0, 0
		total, pMiss := 1+r.Intn(40), r.Float64()
		for i := 0; i < total; i++ {
			name := fmt.Sprintf("h%02d", i)
			prefix := []string{"docker", "docker", "docker", "truenas"}[r.Intn(4)]
			key := prefix + ":" + name
			role := r.Intn(6) // 0: absent, 1: stopped, else Published
			switch role {
			case 0:
			case 1:
				desired = append(desired, svc(key, name, "example.test", model.StateStopped, "198.51.100.5", 80))
			default:
				desired = append(desired, pub(key, name, "example.test", 80))
			}
			o := owned("example.test", name+".example.test", "A", target, key)
			obs.Owned = append(obs.Owned, o)
			k := OwnedRowKey(o.Provider, o.Zone, o.Name, o.Type)
			isMissing, blocked := r.Float64() < pMiss, false
			if isMissing {
				obs.OwnedMissing[k] = true
				if r.Intn(8) == 0 {
					blocked = true
					obs.Foreign["dnsp/example.test"] = append(obs.Foreign["dnsp/example.test"],
						dns.Record{ID: "f" + name, Name: o.Name, Type: "CNAME", Value: "x.test"})
				}
			} else if r.Intn(8) == 0 { // drifted: wanted, not missing
				obs.OwnedDrifted[k] = []dns.Record{{ID: "x", Name: o.Name, Type: "A", Value: ipFX}}
			}
			if role >= 2 && !obs.Unavailable[prefix] {
				wanted++
				if isMissing {
					miss++
					if !blocked {
						eligibleMissing = append(eligibleMissing, o.Name)
					}
				}
			}
		}
		r.Shuffle(len(desired), func(i, j int) { desired[i], desired[j] = desired[j], desired[i] })
		r.Shuffle(len(obs.Owned), func(i, j int) { obs.Owned[i], obs.Owned[j] = obs.Owned[j], obs.Owned[i] })
		acts := Plan(desired, obs, phCfg(), t0)
		var got []string
		for _, a := range acts {
			if a.Repair {
				got = append(got, a.Record.Name)
			}
		}
		sk := breakerSkips(acts)
		fail := func(f string, a ...any) {
			t.Helper()
			t.Fatalf("seed %d (wanted %d, missing %d): %s\nacts %v", seed, wanted, miss, fmt.Sprintf(f, a...), sums(acts))
		}
		if miss > 3 && 2*miss > wanted {
			trips++
			want := fmt.Sprintf("(%d of %d)", miss, wanted)
			if len(got) != 0 || len(sk) != 1 || !strings.Contains(sk[0].Reason, want) {
				fail("breaker: repairs %v skips %v", got, sums(sk))
			}
			continue
		}
		if len(sk) != 0 {
			fail("breaker tripped wrongly")
		}
		sort.Strings(eligibleMissing)
		if len(eligibleMissing) > RepairCapPerZone {
			capped++
			eligibleMissing = eligibleMissing[:RepairCapPerZone]
		} else if len(eligibleMissing) > 0 {
			under++
		}
		if !reflect.DeepEqual(got, eligibleMissing) && (len(got) != 0 || len(eligibleMissing) != 0) {
			fail("repairs %v, want %v", got, eligibleMissing)
		}
	}
	t.Logf("tripped %d, capped %d, under the cap %d", trips, capped, under)
	if trips == 0 || capped == 0 || under == 0 {
		t.Error("a branch never ran")
	}
}
