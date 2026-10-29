package reconcile

import (
	"fmt"
	"sort"

	"github.com/ajthom90/doorwarden/internal/model"
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
	// RouteRemove, so it holds its hostname until its grace period ends
	// against lower source ranks; within its own rank it yields to present
	// claimants. Absent services past their grace period do not claim.
	absent bool
	// incumbent: the claimant's persisted route (Observed.Known) already
	// serves this hostname. Within one source rank an incumbent keeps its
	// hostname against every challenger, whatever its state, until its
	// route is removed (removal grace over, or an operator change): a
	// lexicographically smaller key of the same source cannot take it over.
	incumbent bool
}

// loss describes why a claimant lost its hostname.
type loss struct {
	winner claimant
	reason string
}

// rank is model.SourceRank, shared with the Traefik renderer.
func (c claimant) rank() int { return model.SourceRank(c.key, c.source) }

// outranks is source-first: a lower-trust source never takes a hostname from
// a higher-trust one, whatever their states, even while the higher-trust one
// is absent within its grace period. Within one source rank the incumbent
// (the key whose persisted route serves the hostname) keeps it against
// challengers; first-time claims and ties between incumbents (shared rows of
// a crash window) fall through: an absent claimant (no longer in desired,
// route not yet removed) yields to a present one; then the serving tier
// wins, then the smaller key.
func outranks(a, b claimant) bool {
	if ra, rb := a.rank(), b.rank(); ra != rb {
		return ra < rb
	}
	if a.incumbent != b.incumbent {
		return a.incumbent
	}
	if a.absent != b.absent {
		return b.absent // within one rank, a service that is gone yields to a present one
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
			case w.incumbent && !l.incumbent && w.rank() == l.rank():
				why = "; it is the incumbent (its route already serves the name), so it keeps it until its route is removed (grace period over) or an operator renames/skips one of them"
			case w.phantom:
				why = "; its source is unavailable, so it keeps the name"
			case w.absent:
				why = "; it is no longer discovered but outranks this service, so its route keeps the name until its grace period ends"
			case !w.routable:
				why = "; the winner is not published/routable, fix or approve it (or remove it)"
			}
			losers[l.key] = loss{winner: w, reason: fmt.Sprintf(
				"hostname %s is claimed by %s (precedence: static > truenas > docker, then the incumbent, then serving, then key)%s", h, w.key, why)}
		}
	}
	return winners, losers
}
