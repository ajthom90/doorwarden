package reconcile

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
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
				if !wanted || o.RemovedAfter == nil {
					fail("cancel for an unwanted or unscheduled row")
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
