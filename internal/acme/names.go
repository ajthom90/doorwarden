package acme

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Strategies (config zones[].certificate.strategy; unset means wildcard).
const (
	StrategyWildcard = "wildcard"
	StrategyPerHost  = "per-host"
	StrategySAN      = "san"
)

// Challenges (config zones[].certificate.challenge; unset means dns-01).
const (
	ChallengeDNS01  = "dns-01"
	ChallengeHTTP01 = "http-01"
)

// maxSANNames is the ACME (Let's Encrypt) limit of names per certificate.
const maxSANNames = 100

// ErrWildcardNeedsDNS01 rejects a wildcard name with any challenge but dns-01.
var ErrWildcardNeedsDNS01 = errors.New("acme: wildcard names require the dns-01 challenge")

func normName(n string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(n)), ".") }

// checkName validates one certificate name against its zone. A wildcard is
// only allowed as the whole leftmost label.
func checkName(zone, name string) error {
	if name == "" {
		return errors.New("acme: empty certificate name")
	}
	base := name
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		base = rest
	}
	if strings.Contains(base, "*") {
		return fmt.Errorf("acme: invalid wildcard name %q", name)
	}
	if strings.ContainsAny(base, " /\\:@") || strings.Contains(base, "..") || len(base) > 253 {
		return fmt.Errorf("acme: invalid certificate name %q", name)
	}
	if base != zone && !strings.HasSuffix(base, "."+zone) {
		return fmt.Errorf("acme: name %q is outside zone %q", name, zone)
	}
	return nil
}

func hasWildcard(names []string) bool {
	for _, n := range names {
		if strings.HasPrefix(n, "*.") {
			return true
		}
	}
	return false
}

// planSets turns a request into the name sets to order, one order per set:
// wildcard => [*.zone, zone]; per-host => one set per name; san => all names
// in sets of at most 100. Names are normalized, deduplicated and checked to
// lie inside the zone; with http-01 a wildcard name is rejected.
func planSets(zone string, names []string, strategy, challenge string) ([][]string, error) {
	zone = normName(zone)
	if zone == "" {
		return nil, errors.New("acme: zone is required")
	}
	if strategy == "" {
		strategy = StrategyWildcard
	}
	if challenge == "" {
		challenge = ChallengeDNS01
	}
	seen := map[string]bool{}
	var ns []string
	for _, n := range names {
		n = normName(n)
		if err := checkName(zone, n); err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			ns = append(ns, n)
		}
	}
	sort.Strings(ns)
	var sets [][]string
	switch strategy {
	case StrategyWildcard:
		sets = [][]string{{"*." + zone, zone}}
	case StrategyPerHost:
		if len(ns) == 0 {
			return nil, errors.New("acme: per-host strategy needs at least one name")
		}
		for _, n := range ns {
			sets = append(sets, []string{n})
		}
	case StrategySAN:
		if len(ns) == 0 {
			return nil, errors.New("acme: san strategy needs at least one name")
		}
		for len(ns) > 0 {
			k := min(len(ns), maxSANNames)
			sets = append(sets, append([]string(nil), ns[:k]...))
			ns = ns[k:]
		}
	default:
		return nil, fmt.Errorf("acme: unknown strategy %q", strategy)
	}
	for _, s := range sets {
		if challenge != ChallengeDNS01 && hasWildcard(s) {
			return nil, ErrWildcardNeedsDNS01
		}
	}
	return sets, nil
}

// certID is the stable id of a managed certificate: the zone plus a hash of
// its sorted names. Renewals and re-issues of the same set reuse the id, so
// the files never move.
func certID(zone string, names []string) string {
	s := append([]string(nil), names...)
	sort.Strings(s)
	sum := sha256.Sum256([]byte(normName(zone) + "\n" + strings.Join(s, "\n")))
	return safeLabel(zone) + "-" + hex.EncodeToString(sum[:6])
}

func safeLabel(s string) string {
	var b strings.Builder
	for _, r := range normName(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "cert"
	}
	return b.String()
}

// validID reports whether id is safe as a single path element.
func validID(id string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 200 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
