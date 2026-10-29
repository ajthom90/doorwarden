package model

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrInvalidBackend is wrapped by ValidateBackend errors.
var ErrInvalidBackend = errors.New("invalid backend")

// ValidateBackend reports whether b can be routed: scheme exactly "http" or
// "https" (lowercase), port 1..65535 and a host accepted by ValidHost. It is
// the single routability predicate shared by the reconcile plan and the
// route store, so "the plan thinks it is routable" equals "the store will
// accept it".
func ValidateBackend(b Backend) error {
	var probs []string
	if b.Scheme != "http" && b.Scheme != "https" {
		probs = append(probs, fmt.Sprintf("scheme %q must be http or https", b.Scheme))
	}
	if !ValidHost(b.Host) {
		probs = append(probs, fmt.Sprintf("host %q must be a bare hostname or IP", b.Host))
	}
	if b.Port < 1 || b.Port > 65535 {
		probs = append(probs, fmt.Sprintf("port %d out of range 1..65535", b.Port))
	}
	if len(probs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidBackend, strings.Join(probs, "; "))
	}
	return nil
}

// ValidHost accepts an IP literal (IPv6 bare or bracketed as "[2001:db8::1]";
// a bracketed IPv4 is rejected) or a hostname made of [A-Za-z0-9._-] with
// non-empty labels of at most 63 chars that neither start nor end with '-',
// and at most 253 chars in total. Whitespace, '/', '@', ":port" suffixes and
// everything else are rejected: the host flows into proxy configuration.
// Callers storing a host should strip the brackets (UnbracketHost); URL
// builders must then use net.JoinHostPort.
func ValidHost(h string) bool {
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		ip := net.ParseIP(h[1 : len(h)-1])
		return ip != nil && ip.To4() == nil
	}
	if net.ParseIP(h) != nil {
		return true
	}
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// UnbracketHost returns h without the brackets of a bracketed IP literal.
func UnbracketHost(h string) string {
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1]
	}
	return h
}
