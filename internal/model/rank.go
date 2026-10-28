package model

import "strings"

// SourceRank orders hostname precedence: static > truenas > docker > other
// (lower is stronger). The stable key prefix decides first (source names are
// configurable, key prefixes are not); the source name is only a fallback.
// The reconcile planner and the Traefik renderer both use it, so the
// renderer's per-hostname pick among persisted rows (rank, then smaller key)
// cannot drift from Plan's source-first ranking.
func SourceRank(key, source string) int {
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
