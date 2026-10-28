package reconcile

import (
	"fmt"
	"sort"
	"strings"
)

// claimant is a service that holds or wants a hostname this cycle.
type claimant struct {
	key, source, host string
	// published: the service's current state in desired is Published.
	published bool
	// routable: a published claimant that will receive a RouteWrite in this
	// Plan call (authoritative backend or a last-known one).
	routable bool
	// serving: within its source rank, this claimant is in the upper tier:
	// it is routable, or it is a phantom that still has a Known route.
	serving bool
	// phantom marks a known service of an unavailable source: it is not in
	// desired, but its route may still exist, so it keeps its hostname.
	phantom bool
	// absent marks a known service of an available source that is no longer
	// in desired (removal scheduled or due): its route still exists until
	// RouteRemove, so it holds its hostname, but only while no present
	// service claims it (it ranks below every present claimant).
	absent bool
}

// loss describes why a claimant lost its hostname.
type loss struct {
	winner claimant
	reason string
}

// sourceRank orders hostname precedence: static > truenas > docker > other
// (lower is stronger). The stable key prefix decides first (source names are
// configurable, key prefixes are not); the source name is only a fallback.
func sourceRank(key, source string) int {
	ranks := map[string]int{"static": 0, "truenas": 1, "docker": 2}
	if i := strings.IndexByte(key, ':'); i > 0 {
		if r, ok := ranks[key[:i]]; ok {
			return r
		}
	}
	if r, ok := ranks[strings.ToLower(source)]; ok {
		return r
	}
	return len(ranks)
}

func (c claimant) rank() int { return sourceRank(c.key, c.source) }

// outranks is source-first: a lower-trust source never takes a hostname from
// a higher-trust one, whatever their states. Exception: an absent claimant
// (no longer in desired, route not yet removed) yields to every present one. Within one source rank, the
// serving tier wins, then the smaller key.
func outranks(a, b claimant) bool {
	if a.absent != b.absent {
		return b.absent // a service that is gone yields to any present claimant
	}
	if ra, rb := a.rank(), b.rank(); ra != rb {
		return ra < rb
	}
	if a.serving != b.serving {
		return a.serving
	}
	return a.key < b.key
}

// resolveHostnames picks one winner per (case-insensitive) hostname using
// outranks. It returns winners by host and, for each losing non-phantom key,
// the loss naming the winner.
func resolveHostnames(cs []claimant) (winners map[string]claimant, losers map[string]loss) {
	byHost := map[string][]claimant{}
	for _, c := range cs {
		h := normName(c.host)
		byHost[h] = append(byHost[h], c)
	}
	winners, losers = map[string]claimant{}, map[string]loss{}
	for h, group := range byHost {
		sort.Slice(group, func(i, j int) bool { return outranks(group[i], group[j]) })
		w := group[0]
		winners[h] = w
		for _, l := range group[1:] {
			if l.phantom {
				continue
			}
			why := ""
			switch {
			case w.phantom:
				why = "; its source is unavailable, so it keeps the name"
			case w.absent:
				why = "; it is no longer discovered and its route is removed after the grace period"
			case !w.routable:
				why = "; the winner is not published/routable, fix or approve it (or remove it)"
			}
			losers[l.key] = loss{winner: w, reason: fmt.Sprintf(
				"hostname %s is claimed by %s (precedence: static > truenas > docker, then serving, then key)%s", h, w.key, why)}
		}
	}
	return winners, losers
}
