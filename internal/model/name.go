package model

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

const maxLabel = 63

// Slug converts s into a lowercase DNS label: [a-z0-9-], at most 63 chars,
// no leading/trailing hyphen. Runs of other characters become one hyphen.
func Slug(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 'a' - 'A')
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > maxLabel {
		out = strings.TrimRight(out[:maxLabel], "-")
	}
	if out == "" {
		return "", fmt.Errorf("name %q has no characters valid in a DNS label", s)
	}
	return out, nil
}

func normZone(z string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(z), "."))
}

// Hostname returns "<slug(name)>.<zone>", lowercase, or the zone itself for
// an apex service (Options.Apex; Rename is then ignored: config validation
// and UIOverrides.Validate refuse it, so only a stale stored UI rename can
// reach here, and it must not unpublish the apex; the zone
// must be a valid LDH host name: ASCII, punycode for IDN, no IP literal, no
// wildcard). The zone is svc.Zone or
// defaultZone when empty, and must be one of zones (case-insensitive,
// trailing dot ignored).
func Hostname(svc Service, zones []string, defaultZone string) (string, error) {
	zone := normZone(svc.Zone)
	if zone == "" {
		zone = normZone(defaultZone)
	}
	if zone == "" {
		return "", errors.New("no zone specified and no default zone")
	}
	found := false
	for _, z := range zones {
		if normZone(z) == zone {
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("unknown zone %q", zone)
	}
	if svc.Options.Apex {
		if !ValidLDHName(zone) {
			return "", fmt.Errorf("zone %q is not a valid host name for an apex service (letters, digits and hyphens; punycode for internationalized names)", zone)
		}
		return zone, nil
	}
	name := svc.Name
	if svc.Options.Rename != "" {
		name = svc.Options.Rename
	}
	label, err := Slug(name)
	if err != nil {
		return "", err
	}
	return label + "." + zone, nil
}

// ValidLDHName reports whether n is a DNS host name of lowercase LDH labels
// (1-63 characters, no leading or trailing hyphen, at most 253 characters,
// at least two labels) that is not an IP literal.
func ValidLDHName(n string) bool {
	if n == "" || len(n) > 253 || !strings.Contains(n, ".") || net.ParseIP(n) != nil {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > maxLabel || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
