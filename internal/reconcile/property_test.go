package reconcile

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
	"gopkg.in/yaml.v3"
)

// propSeeds is the number of deterministic seeds TestPropertyRouteInvariants
// runs; each seed applies Plan over propCycles cycles to a real store.
const propSeeds = 2000

// propCycles: t0, past the "future" RemovedAfter of seeded rows, and past
// the grace period of removals scheduled in the first cycle.
var propCycles = []time.Duration{0, 2 * time.Hour, 25 * time.Hour}

var propKeys = []string{"static:a", "static:b", "truenas:a", "docker:a", "docker:b", "other:a"}

type propCase struct {
	rows        []store.Route
	desired     []model.Service
	unavailable map[string]bool
	desc        []string
	// role8 maps each role-8 key to its variant: "typo" (labels name an
	// undefined middleware; any row keeps its last-written, defined
	// middlewares) or "removed" (labels name a middleware whose definition
	// was deleted from the config; any row was written with it).
	role8 map[string]string
}

// role8Typo and role8Removed are the middlewares the role-8 variants
// reference. Neither is defined in e2eMiddlewares.
const (
	role8Typo    = "authh@file"
	role8Removed = "gone@file"
)

// genProp builds one case. Each key optionally has a persisted row (at most
// one row per hostname, removal unset, in grace or past grace) and a role:
// absent, Published (often renamed away from its row), Published with an
// invalid backend, Stopped, Pending, Published with invalid labels (held
// Invalid when it has a row), Error, or Published with an undefined
// middleware (Invalid; held when it has a row). Some sources are unavailable (their
// services are then not in desired, and their rows are phantoms).
func genProp(r *rand.Rand) propCase {
	c := propCase{unavailable: map[string]bool{}, role8: map[string]string{}}
	hosts := []string{"app", "web", "api", "db"}
	used := map[string]bool{}
	for _, src := range []string{"static", "truenas", "docker", "other"} {
		if r.Intn(6) == 0 {
			c.unavailable[src] = true
		}
	}
	for _, k := range propKeys {
		hasRow := r.Intn(3) > 0
		rowHost := hosts[r.Intn(len(hosts))]
		if used[rowHost] {
			hasRow = false
		}
		raDesc := "-"
		if hasRow {
			used[rowHost] = true
			var ra *time.Time
			switch r.Intn(3) {
			case 1:
				ra, raDesc = tp(t0.Add(time.Hour)), "grace"
			case 2:
				ra, raDesc = tp(t0.Add(-time.Hour)), "past"
			}
			c.rows = append(c.rows, store.Route{Key: k, Source: sourceOf(k), Zone: "example.test",
				Hostname: rowHost + ".example.test", Scheme: "http", Host: "198.51.100.9",
				Port: 1000 + r.Intn(100), RemovedAfter: ra})
			if r.Intn(2) == 0 {
				c.rows[len(c.rows)-1].Middlewares = []string{"auth@file"} // defined
			}
		}
		role := r.Intn(9)
		cur := hosts[r.Intn(3)]
		if hasRow && r.Intn(2) == 0 {
			cur = rowHost
		}
		var s model.Service
		switch role {
		case 2:
			s = pub(k, cur, "example.test", 2000+r.Intn(100))
		case 3:
			s = pub(k, cur, "example.test", 0) // invalid backend
		case 4:
			s = svc(k, cur, "example.test", model.StateStopped, "198.51.100.5", 3000)
		case 5:
			s = svc(k, cur, "example.test", model.StatePending, "198.51.100.5", 3000)
		case 6:
			s = pub(k, cur, "missing.test", 2000) // invalid labels
		case 7:
			s = svc(k, cur, "example.test", model.StateError, "", 0)
		case 8: // undefined middleware: fails closed, Invalid
			s = pub(k, cur, "example.test", 2000)
			if r.Intn(2) == 0 {
				c.role8[k] = "typo"
				s.Options.Middlewares = []string{"auth@file", role8Typo}
			} else {
				c.role8[k] = "removed"
				s.Options.Middlewares = []string{role8Removed}
				if hasRow { // the row was written while the definition existed
					c.rows[len(c.rows)-1].Middlewares = []string{role8Removed}
				}
			}
		} // 0, 1: absent
		if s.Key != "" && !c.unavailable[s.Source] {
			c.desired = append(c.desired, s)
		}
		c.desc = append(c.desc, fmt.Sprintf("%s row=%v(%s,%s) role=%d cur=%s", k, hasRow, rowHost, raDesc, role, cur))
	}
	return c
}

func rowSource(k string) string { return sourceOf(k) }

// propShards splits the seeds over parallel subtests, each with its own
// store, so the run stays short under -race (the pure-Go SQLite driver is
// slow under the race detector).
const propShards = 8

func TestPropertyRouteInvariants(t *testing.T) {
	var cnt propCounters
	t.Run("shards", func(t *testing.T) {
		for sh := int64(0); sh < propShards; sh++ {
			t.Run(fmt.Sprintf("shard%d", sh), func(t *testing.T) {
				t.Parallel()
				propRun(t, sh, &cnt)
			})
		}
	}) // returns once every parallel shard is done
	if t.Failed() {
		return
	}
	// The role-8 checks must not be vacuous.
	for name, n := range map[string]int64{
		"role-8 services generated":                      cnt.role8.Load(),
		"role-8 typo services":                           cnt.role8Typo.Load(),
		"role-8 removed-definition rows":                 cnt.role8RemovedRows.Load(),
		"role-8 services outranking a row holder":        cnt.role8Outranks.Load(),
		"of those, Invalid and evicting nobody":          cnt.role8HeldOff.Load(),
		"routable winners checked against Render":        cnt.servedChecked.Load(),
		"removed-definition rows checked dark in Render": cnt.darkChecked.Load(),
	} {
		t.Logf("%s: %d", name, n)
		if n == 0 {
			t.Errorf("counter %q is 0: the check never ran", name)
		}
	}
	if cnt.role8HeldOff.Load() != cnt.role8Outranks.Load() {
		t.Errorf("%d role-8 services outrank a row holder but only %d were Invalid and evicted nobody",
			cnt.role8Outranks.Load(), cnt.role8HeldOff.Load())
	}
}

// propCounters counts how often the role-8 and served-by-Render checks
// actually ran, across all shards.
type propCounters struct {
	role8, role8Typo, role8RemovedRows atomic.Int64
	role8Outranks, role8HeldOff        atomic.Int64
	servedChecked, darkChecked         atomic.Int64
}

// propServed renders rows with the REAL renderer and the config's
// middleware definitions and allowlist (exactly what the orchestrator must
// pass), and returns hostname -> key of the router actually served.
func propServed(t *testing.T, rows []store.Route, cfg *config.Config) map[string]string {
	t.Helper()
	f, _, err := traefik.Render(rows, traefik.MiddlewareDefs(cfg.MiddlewareDefs()), nil,
		traefik.Options{ExternalMiddlewares: cfg.Traefik.ExternalMiddlewares})
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		HTTP struct {
			Routers map[string]struct {
				Rule string `yaml:"rule"`
			} `yaml:"routers"`
		} `yaml:"http"`
	}
	if err := yaml.Unmarshal(f[traefik.RoutesFile], &d); err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, r := range rows {
		byName[traefik.Name(r.Key)] = r.Key
	}
	out := map[string]string{}
	for n, r := range d.HTTP.Routers {
		out[strings.TrimSuffix(strings.TrimPrefix(r.Rule, "Host(`"), "`)")] = byName[n]
	}
	return out
}

// propRun checks the seeds shard, shard+propShards, ... below propSeeds.
func propRun(t *testing.T, shard int64, cnt *propCounters) {
	ctx := context.Background()
	e := newE2E(t)
	e.crashWindow = true               // checked here, with the documented carve-out
	mem, err := store.Open(":memory:") // a real store, kept in memory for speed
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mem.Close() })
	e.st = mem
	re := NewRouteExecutor(mem, func() time.Time { return e.now })
	e.ex = NewMultiExecutor(nil).Handle(RouteWrite, re).Handle(RouteRemove, re).
		Handle(ScheduleRemoval, re).Handle(CancelRemoval, re)
	for seed := shard; seed < propSeeds; seed += propShards {
		r := rand.New(rand.NewSource(seed))
		c := genProp(r)
		for _, old := range listRoutes(t, e.st) { // reuse one store
			if err := e.st.DeleteRoute(ctx, old.Key); err != nil {
				t.Fatal(err)
			}
		}
		for _, row := range c.rows {
			ra := row.RemovedAfter
			row.RemovedAfter = nil
			if err := e.st.UpsertRoute(ctx, row); err != nil {
				t.Fatal(err)
			}
			if ra != nil {
				if err := e.st.SetRouteRemoval(ctx, row.Key, ra); err != nil {
					t.Fatal(err)
				}
			}
		}
		present := map[string]model.Service{}
		for _, s := range c.desired {
			present[s.Key] = s
			switch c.role8[s.Key] {
			case "typo":
				cnt.role8.Add(1)
				cnt.role8Typo.Add(1)
			case "removed":
				cnt.role8.Add(1)
			}
		}
		seededMW := map[string][]string{}
		for _, row := range c.rows {
			seededMW[row.Key] = row.Middlewares
			if c.role8[row.Key] == "removed" {
				cnt.role8RemovedRows.Add(1)
			}
		}
		mwValid, _ := model.ValidateMiddlewareDefs(e.cfg.MiddlewareDefs(), e.cfg.Traefik.ExternalMiddlewares)
		resolves := func(ref string) bool {
			return model.CheckMiddlewareRef(ref, func(n string) bool { return mwValid[n] }, e.cfg.Traefik.ExternalMiddlewares) == nil
		}
		written := map[string]bool{} // keys Plan wrote in any cycle so far
		for ci, off := range propCycles {
			now := t0.Add(off)
			e.now = now
			before := listRoutes(t, e.st)
			bw, _ := renderWinners(before)
			known, lk := ObservedFromRoutes(before)
			obs := Observed{Known: known, LastKnown: lk, Unavailable: c.unavailable}
			acts, wins := planWithWinners(c.desired, obs, e.cfg, now)
			e.winners = wins
			if err := e.ex.Apply(ctx, acts, false); err != nil {
				t.Fatal(err)
			}
			after := listRoutes(t, e.st)
			aw, an := renderWinners(after)
			fail := func(f string, a ...any) {
				t.Helper()
				t.Fatalf("seed %d cycle %d: %s\ncase %v\nunavailable %v\nacts %v\nbefore %v\nafter %v",
					seed, ci, fmt.Sprintf(f, a...), c.desc, c.unavailable, sums(acts), bw, aw)
			}

			writes := map[string]bool{} // hosts with a Published RouteWrite
			for _, a := range ofKind(acts, RouteWrite) {
				if a.Svc.State == model.StatePublished {
					writes[a.Host] = true
				}
			}
			renamed := map[string]bool{} // keys whose actions name a host other than their row's
			for _, a := range acts {
				if k, ok := known[a.Key]; ok && a.Host != "" && a.Host != k.Hostname {
					renamed[a.Key] = true
				}
			}

			// Every RouteRemove is past grace, a real takeover, or the old
			// row of a Published loser that renamed away; never for an
			// unavailable source, never twice.
			removed := map[string]bool{}
			for _, a := range ofKind(acts, RouteRemove) {
				if removed[a.Key] {
					fail("double RouteRemove %s", a.Key)
				}
				removed[a.Key] = true
				k := known[a.Key]
				if c.unavailable[k.Source] {
					fail("RouteRemove for unavailable source %s", a.Key)
				}
				s, isPresent := present[a.Key]
				if !isPresent && k.RemovedAfter != nil && now.After(*k.RemovedAfter) {
					continue // past grace
				}
				claimed := k.Hostname
				for _, cf := range ofKind(forKey(acts, a.Key), Conflict) {
					claimed = cf.Host
				}
				w, ok := wins[claimed]
				if !ok || w.key == a.Key {
					fail("RouteRemove %s without a winner", a.Key)
				}
				if isPresent && s.State == model.StatePublished && claimed != k.Hostname {
					continue // renamed-away loser: its old hostname is unclaimed by it
				}
				if !w.published || !w.routable || w.phantom || w.rank() > model.SourceRank(a.Key, k.Source) {
					fail("RouteRemove %s by a winner that does not take over: %+v", a.Key, w)
				}
				if !writes[claimed] {
					fail("RouteRemove %s but winner %s gets no Published RouteWrite at %s", a.Key, w.key, claimed)
				}
			}

			// The served rank per hostname never gets worse, except when the
			// previous server's grace period ended or the previous server
			// itself now acts at a different hostname (a rename: it moved its
			// row, or lost its new hostname and its old row was removed).
			for h, bk := range bw {
				if ak, ok := aw[h]; ok && model.SourceRank(ak, rowSource(ak)) <= model.SourceRank(bk, rowSource(bk)) {
					continue
				}
				k := known[bk]
				if _, p := present[bk]; !p && k.RemovedAfter != nil && now.After(*k.RemovedAfter) {
					continue
				}
				if renamed[bk] {
					continue
				}
				fail("hostname %s served by %s before, %q after", h, bk, aw[h])
			}

			// Every routable present winner gets its write (no dark name).
			for h, w := range wins {
				if !w.absent && !w.phantom && w.published && w.routable && !writes[h] {
					fail("winner %s at %s is routable but gets no RouteWrite", w.key, h)
				}
			}

			// One row per hostname. Remaining window: a row of an
			// unavailable source (a phantom) that a higher-ranked Published
			// winner shares; its source is down, so it cannot be removed.
			for h, n := range an {
				if n == 1 {
					continue
				}
				phantom := false
				for _, row := range after {
					if row.Hostname == h && c.unavailable[row.Source] {
						phantom = true
					}
				}
				if !phantom {
					fail("hostname %s has %d rows", h, n)
				}
			}

			// The renderer agrees with Plan for every claimed hostname whose
			// winner has a row there.
			byKey := map[string]store.Route{}
			for _, row := range after {
				byKey[row.Key] = row
			}
			for h, pw := range wins {
				if row, ok := byKey[pw.key]; ok && row.Hostname == h && aw[h] != pw.key {
					fail("renderer picks %s, Plan %s at %s", aw[h], pw.key, h)
				}
			}
			assertNone(t, acts, DNSDelete) // no records mode configured

			// Middlewares fail closed, checked against the REAL renderer.
			served := propServed(t, after, e.cfg)
			for _, a := range ofKind(acts, RouteWrite) {
				written[a.Key] = true
				for _, ref := range a.Svc.Options.Middlewares {
					if !resolves(ref) {
						fail("RouteWrite %s carries unresolvable middleware %q", a.Key, ref)
					}
				}
			}
			// (a) every routable Published winner with a row at its hostname
			// is actually served there by Render.
			for h, w := range wins {
				if w.absent || w.phantom || !w.published || !w.routable {
					continue
				}
				if row, ok := byKey[w.key]; ok && row.Hostname == h {
					cnt.servedChecked.Add(1)
					if served[h] != w.key {
						fail("winner %s at %s is routable with a row but Render serves %q", w.key, h, served[h])
					}
				}
			}
			// (b) a persisted row only carries an unresolvable middleware
			// when it is a "removed"-variant row left as last written; that
			// row is dark by design. A typo never darkens a row.
			for _, row := range after {
				for _, ref := range row.Middlewares {
					if resolves(ref) {
						continue
					}
					if c.role8[row.Key] != "removed" || written[row.Key] ||
						!reflect.DeepEqual(row.Middlewares, seededMW[row.Key]) {
						fail("row %s carries unresolvable middleware %q", row.Key, ref)
					}
					cnt.darkChecked.Add(1)
					if served[row.Hostname] == row.Key {
						fail("row %s with removed definition %q is still served", row.Key, ref)
					}
				}
			}
			// (c) a role-8 service that outranks the holder of a row at its
			// hostname is Invalid and evicts nobody.
			if ci == 0 {
				for _, s := range c.desired {
					if c.role8[s.Key] == "" {
						continue
					}
					h := s.Name + ".example.test"
					for _, row := range before {
						if row.Hostname != h || row.Key == s.Key {
							continue
						}
						sr, hr := model.SourceRank(s.Key, s.Source), model.SourceRank(row.Key, row.Source)
						if sr > hr || sr == hr && s.Key > row.Key {
							continue
						}
						cnt.role8Outranks.Add(1)
						if len(ofKind(forKey(acts, s.Key), Invalid)) != 1 {
							fail("role-8 %s outranks %s at %s but is not Invalid", s.Key, row.Key, h)
						}
						if w, ok := wins[h]; ok && w.key == s.Key && w.routable {
							fail("role-8 %s is a routable winner at %s", s.Key, h)
						}
						for _, a := range acts {
							if a.Kind == RouteWrite && a.Key == s.Key {
								fail("role-8 %s gets a RouteWrite", s.Key)
							}
							if a.Kind != RouteRemove {
								continue
							}
							// the eviction's winner (as in the RouteRemove check
							// above) must never be the role-8 service
							claimed := known[a.Key].Hostname
							for _, cf := range ofKind(forKey(acts, a.Key), Conflict) {
								claimed = cf.Host
							}
							if ps, ok := present[a.Key]; ok && ps.State == model.StatePublished && claimed != known[a.Key].Hostname {
								continue // a renamed-away loser removes its own old row
							}
							if w, ok := wins[claimed]; ok && w.key == s.Key {
								fail("role-8 %s evicted %s at %s", s.Key, a.Key, claimed)
							}
						}
						cnt.role8HeldOff.Add(1)
					}
				}
			}

			// Determinism under input order.
			if ci == 0 && seed%10 == 0 {
				for i := 0; i < 20; i++ {
					d := append([]model.Service(nil), c.desired...)
					r.Shuffle(len(d), func(a, b int) { d[a], d[b] = d[b], d[a] })
					if got := Plan(d, obs, e.cfg, now); !reflect.DeepEqual(got, acts) {
						fail("plan depends on input order")
					}
				}
			}
		}
	}
}
