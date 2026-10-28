package reconcile

import (
	"fmt"
	"sort"
	"strings"
)

// claimant is a service that holds or wants a hostname this cycle.
type claimant struct {
	key, source, host string
	// published: the service's current state in desired is Published. A
	// published claimant always beats every other claimant.
	published bool
	// phantom marks a known service of an unavailable source: it is not in
	// desired, but its route may still exist, so it keeps its hostname.
	phantom bool
}

// sourceRank orders hostname precedence: static > truenas > docker > other.
// The stable key prefix decides first (source names are configurable, key
// prefixes are not); the source name is only a fallback.
// loss describes why a claimant lost its hostname.
type loss struct {
	winner claimant
	reason string
}

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

func outranks(a, b claimant) bool {
	if a.published != b.published {
		return a.published
	}
	ra, rb := sourceRank(a.key, a.source), sourceRank(b.key, b.source)
	if ra != rb {
		return ra < rb
	}
	return a.key < b.key
}

// resolveHostnames picks one winner per (case-insensitive) hostname: a
// Published claimant first, then source rank, then key. It returns winners by
// host and, for each losing non-phantom key, the reason naming the winner.
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
			if w.phantom {
				why = "; its source is unavailable, so it keeps the name"
			}
			losers[l.key] = loss{winner: w, reason: fmt.Sprintf("hostname %s is claimed by %s (precedence: published first, then static > truenas > docker, then key)%s", h, w.key, why)}
		}
	}
	return winners, losers
}
