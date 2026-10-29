package reconcile

import (
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
)

// A Published service that renames onto a hostname held by a winner that
// does not take over (absent in grace, Pending, Stopped) must not leave its
// old row behind: nothing would claim the old hostname, so a newcomer there
// would share it with the stale row and the renderer would serve the stale
// one.
func TestE2ERenamedLoserOldRowRemoved(t *testing.T) {
	for _, variant := range []string{"absent-static-in-grace", "pending-truenas", "stopped-static-same-rank"} {
		t.Run(variant, func(t *testing.T) {
			e := newE2E(t) // one row per hostname is asserted every cycle
			movKey, newKey, holderKey := "docker:a", "docker:b", "static:s"
			switch variant {
			case "pending-truenas":
				holderKey = "truenas:t"
			case "stopped-static-same-rank":
				movKey, newKey, holderKey = "static:m", "docker:b", "static:a"
			}
			holder := pub(holderKey, "web", "example.test", 7000)
			e.cycle([]model.Service{pub(movKey, "app", "example.test", 8080), holder})

			e.now = t0.Add(time.Hour)
			var others []model.Service
			switch variant {
			case "pending-truenas":
				h := holder
				h.State = model.StatePending
				others = append(others, h)
			case "stopped-static-same-rank":
				h := holder
				h.State = model.StateStopped
				others = append(others, h)
			} // absent: the holder is simply missing
			mov := pub(movKey, "web", "example.test", 8080)
			acts := e.cycle(append([]model.Service{mov}, others...))
			{
				// (stopped-static-same-rank: the Stopped holder is the
				// incumbent of web since final-review H1, so the mover loses
				// like in the other variants)
				ma := forKey(acts, movKey)
				assertSums(t, ma, "Conflict example.test web.example.test "+movKey,
					"RouteRemove example.test app.example.test "+movKey)
				if !strings.Contains(ma[1].Reason, "app.example.test") || !strings.Contains(ma[1].Reason, holderKey) {
					t.Fatalf("old-row RouteRemove reason %q", ma[1].Reason)
				}
				if _, ok := e.route(movKey); ok {
					t.Fatalf("old row of %s still persisted", movKey)
				}
				if r := e.mustRoute(holderKey); r.Hostname != "web.example.test" {
					t.Fatalf("holder row changed: %+v", r)
				}
			}

			e.now = t0.Add(2 * time.Hour)
			acts = e.cycle(append([]model.Service{mov, pub(newKey, "app", "example.test", 9090)}, others...))
			if w := ofKind(forKey(acts, newKey), RouteWrite); len(w) != 1 {
				t.Fatalf("newcomer gets no route: %v", sums(acts))
			}
			w, n := renderWinners(listRoutes(t, e.st))
			if n["app.example.test"] != 1 || w["app.example.test"] != newKey {
				t.Fatalf("app.example.test: renderer %s (%d rows), want %s alone", w["app.example.test"], n["app.example.test"], newKey)
			}
		})
	}
}

func TestPlanRenamedLoserOldRowGuards(t *testing.T) {
	cfg := cfgOf(zone("example.test", "", ""))
	holder := known("static:s", "example.test", "web.example.test", tp(t0.Add(time.Hour))) // absent, in grace

	t.Run("unavailable source keeps old row", func(t *testing.T) {
		obs := Observed{Known: knownMap(holder, known("docker:a", "example.test", "app.example.test", nil)),
			Unavailable: map[string]bool{"docker": true}}
		got := Plan([]model.Service{pub("docker:a", "web", "example.test", 1)}, obs, cfg, t0)
		assertSums(t, forKey(got, "docker:a"), "Conflict example.test web.example.test docker:a")
	})

	t.Run("same hostname loser keeps its row", func(t *testing.T) {
		// rows already share web; the higher-ranked absent holder keeps the
		// name through grace and the loser keeps its row (it still declares
		// that hostname)
		obs := Observed{Known: knownMap(holder, known("docker:a", "example.test", "web.example.test", nil))}
		got := Plan([]model.Service{pub("docker:a", "web", "example.test", 1)}, obs, cfg, t0)
		assertSums(t, forKey(got, "docker:a"), "Conflict example.test web.example.test docker:a")
	})

	t.Run("held invalid unaffected", func(t *testing.T) {
		obs := Observed{Known: knownMap(known("static:s", "example.test", "app.example.test", tp(t0.Add(time.Hour))),
			known("docker:a", "example.test", "app.example.test", nil))}
		got := Plan([]model.Service{pub("docker:a", "web", "missing.test", 1)}, obs, cfg, t0)
		da := forKey(got, "docker:a")
		if len(ofKind(da, Invalid)) != 1 || len(ofKind(da, Conflict)) != 1 {
			t.Fatalf("want Invalid + Conflict, got %v", sums(da))
		}
		assertNone(t, da, RouteRemove, RouteWrite)
	})

	t.Run("non-published loser unaffected", func(t *testing.T) {
		// a Stopped service claims its stored hostname, so it never renames
		obs := Observed{Known: knownMap(holder, known("docker:a", "example.test", "web.example.test", nil))}
		got := Plan([]model.Service{svc("docker:a", "other", "example.test", model.StateStopped, "198.51.100.5", 1)}, obs, cfg, t0)
		assertSums(t, forKey(got, "docker:a"), "Conflict example.test web.example.test docker:a")
	})
}
