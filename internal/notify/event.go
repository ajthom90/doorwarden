// Package notify delivers alerts (webhook, ntfy, SMTP) and fans them out
// through a Dispatcher with dedupe, rate limiting and bounded retries.
//
// Secrets (URLs with tokens, HMAC keys, passwords, auth headers) live in
// secrets.Secret config fields and are revealed only at send time; no error
// returned by this package contains them.
package notify

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Severity orders how urgent an Event is.
type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Rank is 0 (info), 1 (warning), 2 (critical). Unknown values rank as info.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 2
	case Warning:
		return 1
	}
	return 0
}

// ParseSeverity maps a config string ("" means info) to a Severity.
func ParseSeverity(s string) (Severity, bool) {
	switch Severity(strings.ToLower(s)) {
	case "", Info:
		return Info, true
	case Warning:
		return Warning, true
	case Critical:
		return Critical, true
	}
	return Info, false
}

// Event is one alert. Kind is free-form, e.g. "cert.renewal_failed",
// "cert.expiring", "dns.conflict", "source.unavailable", "reconcile.error".
type Event struct {
	Kind     string
	Severity Severity
	Subject  string
	Message  string
	// Fields carries small key/value context. Never put secrets here.
	Fields map[string]string
	At     time.Time
	// DedupeKey, when set, suppresses repeats within the dispatcher's window.
	DedupeKey string
}

// Notifier is what producers (reconcile, ACME, ...) accept.
type Notifier interface {
	Notify(ctx context.Context, e Event) error
}

// Size limits applied to every outgoing event.
const (
	MaxSubjectBytes    = 200
	MaxMessageBytes    = 4096
	MaxFields          = 20
	MaxFieldKeyBytes   = 64
	MaxFieldValueBytes = 256
	maxKindBytes       = 100
)

// truncate cuts s to at most n bytes on a rune boundary, marking the cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func stripNUL(s string) string {
	if strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// normalized returns a copy of e that is safe to send: bounded sizes, valid
// UTF-8, known severity, at most MaxFields fields (the lexically first).
func (e Event) normalized() Event {
	out := e
	out.Kind = truncate(strings.ToValidUTF8(stripNUL(e.Kind), "?"), maxKindBytes)
	out.Subject = truncate(strings.ToValidUTF8(stripNUL(e.Subject), "?"), MaxSubjectBytes)
	out.Message = truncate(strings.ToValidUTF8(stripNUL(e.Message), "?"), MaxMessageBytes)
	if _, ok := ParseSeverity(string(e.Severity)); !ok || e.Severity == "" {
		out.Severity = Info
	}
	out.Fields = nil
	if len(e.Fields) > 0 {
		keys := make([]string, 0, len(e.Fields))
		for k := range e.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > MaxFields {
			keys = keys[:MaxFields]
		}
		out.Fields = make(map[string]string, len(keys))
		for _, k := range keys {
			nk := truncate(strings.ToValidUTF8(stripNUL(k), "?"), MaxFieldKeyBytes)
			out.Fields[nk] = truncate(strings.ToValidUTF8(stripNUL(e.Fields[k]), "?"), MaxFieldValueBytes)
		}
	}
	if out.At.IsZero() {
		out.At = time.Now()
	}
	out.At = out.At.UTC()
	return out
}

// sortedFields returns the field keys in order.
func sortedFields(f map[string]string) []string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
