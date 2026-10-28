package acme

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/idna"
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

// maxNameLen and maxLabelLen are the DNS limits (RFC 1035) for a name in
// presentation form without the trailing dot, and for one label.
const (
	maxNameLen  = 253
	maxLabelLen = 63
)

// canonHost returns the canonical ASCII form of a host name (no wildcard):
// lowercase LDH labels of 1-63 letters, digits or hyphens, no leading or
// trailing hyphen, at most 253 characters. A single trailing dot is
// removed. A name with non-ASCII characters or an "xn--" label goes
// through IDNA (idna.Lookup.ToASCII) and is rejected if that fails.
// Whitespace, control characters (NUL, newline), underscores and anything
// else outside LDH are rejected, never trimmed.
func canonHost(n string) (string, error) {
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return "", errors.New("empty name")
	}
	ascii := true
	for i := 0; i < len(n); i++ {
		if n[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if !ascii || strings.Contains(strings.ToLower(n), "xn--") {
		a, err := idna.Lookup.ToASCII(n)
		if err != nil {
			return "", errors.New("not a valid internationalized name")
		}
		n = a
	}
	n = strings.ToLower(n)
	if len(n) > maxNameLen {
		return "", fmt.Errorf("longer than %d characters", maxNameLen)
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > maxLabelLen {
			return "", fmt.Errorf("label length must be 1-%d", maxLabelLen)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("label starts or ends with a hyphen")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("only letters, digits and hyphens are allowed")
			}
		}
	}
	return n, nil
}

// canonName is canonHost allowing "*" as the whole leftmost label.
func canonName(n string) (string, error) {
	if rest, ok := strings.CutPrefix(n, "*."); ok {
		h, err := canonHost(rest)
		if err != nil {
			return "", err
		}
		if len(h)+2 > maxNameLen {
			return "", fmt.Errorf("longer than %d characters", maxNameLen)
		}
		return "*." + h, nil
	}
	return canonHost(n)
}

// nameError is an invalid certificate name. The name is quoted with %q, so
// control characters are escaped in messages and logs.
type nameError struct {
	name, why string
}

func (e *nameError) Error() string {
	return fmt.Sprintf("acme: invalid certificate name %q: %s", e.name, e.why)
}

// checkName validates one certificate name against its zone and returns its
// canonical form. A wildcard is only allowed as the whole leftmost label.
// An invalid name gives a *nameError; a valid name outside the zone a
// plain error.
func checkName(zone, name string) (string, error) {
	c, err := canonName(name)
	if err != nil {
		return "", &nameError{name: name, why: err.Error()}
	}
	base := strings.TrimPrefix(c, "*.")
	if base != zone && !strings.HasSuffix(base, "."+zone) {
		return "", fmt.Errorf("acme: name %q is outside zone %q", c, zone)
	}
	return c, nil
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
// in sets of at most 100. Names are canonicalized (see canonName) and
// deduplicated; a syntactically invalid name is dropped and returned in
// dropped (the rest of the request proceeds), a valid name outside the zone
// is an error. With http-01 a wildcard name is rejected.
func planSets(zone string, names []string, strategy, challenge string) (sets [][]string, dropped []string, err error) {
	if zone == "" {
		return nil, nil, errors.New("acme: zone is required")
	}
	zone, err = canonHost(strings.ToLower(strings.TrimSpace(zone)))
	if err != nil {
		return nil, nil, fmt.Errorf("acme: invalid zone name: %w", err)
	}
	if strategy == "" {
		strategy = StrategyWildcard
	}
	if challenge == "" {
		challenge = ChallengeDNS01
	}
	seen := map[string]bool{}
	var ns []string
	for _, raw := range names {
		n, err := checkName(zone, raw)
		if err != nil {
			var ne *nameError
			if errors.As(err, &ne) {
				dropped = append(dropped, raw)
				continue
			}
			return nil, nil, err
		}
		if !seen[n] {
			seen[n] = true
			ns = append(ns, n)
		}
	}
	sort.Strings(ns)
	switch strategy {
	case StrategyWildcard:
		sets = [][]string{{"*." + zone, zone}}
	case StrategyPerHost:
		if len(ns) == 0 {
			return nil, dropped, errors.New("acme: per-host strategy needs at least one valid name")
		}
		for _, n := range ns {
			sets = append(sets, []string{n})
		}
	case StrategySAN:
		if len(ns) == 0 {
			return nil, dropped, errors.New("acme: san strategy needs at least one valid name")
		}
		for len(ns) > 0 {
			k := min(len(ns), maxSANNames)
			sets = append(sets, append([]string(nil), ns[:k]...))
			ns = ns[k:]
		}
	default:
		return nil, dropped, fmt.Errorf("acme: unknown strategy %q", strategy)
	}
	for _, s := range sets {
		if challenge != ChallengeDNS01 && hasWildcard(s) {
			return nil, dropped, ErrWildcardNeedsDNS01
		}
	}
	return sets, dropped, nil
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
