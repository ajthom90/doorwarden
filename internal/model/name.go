package model

import (
	"errors"
	"fmt"
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

// Hostname returns "<slug(name)>.<zone>", lowercase. The zone is svc.Zone or
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
