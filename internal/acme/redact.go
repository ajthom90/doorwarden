package acme

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Redaction: every string that leaves the Manager (cert rows, logs,
// notifier events, returned error text) passes through redactor.redact,
// which (1) rewrites URLs (userinfo, query and fragment removed), (2)
// replaces every secret value known to the Manager, (3) scrubs generic
// credential patterns. Truncation happens only after redaction. The raw
// error is kept in memory only, as the Unwrap target of the returned
// error, so errors.Is/As keep working.

// minSecretLen is the shortest secret that is redacted by value; shorter
// ones would destroy unrelated text and are reported at construction.
const minSecretLen = 4

const redacted = "[redacted]"

type redactor struct {
	// parent, when set, receives every value added here too (the
	// process-wide redactor used for lego's global logger).
	parent  *redactor
	mu      sync.RWMutex
	set     map[string]bool
	ordered []string // longest first
}

func newRedactor() *redactor { return &redactor{set: map[string]bool{}} }

// globalRedactor knows the secrets of every Manager in the process; it
// guards lego's package-level logger.
var globalRedactor = newRedactor()

// add registers secret values. It returns false for a non-empty value too
// short to redact.
func (r *redactor) add(vals ...string) bool {
	if r.parent != nil {
		r.parent.add(vals...)
	}
	ok := true
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if len(v) < minSecretLen {
			ok = false
			continue
		}
		if !r.set[v] {
			r.set[v] = true
			changed = true
		}
	}
	if changed {
		r.ordered = r.ordered[:0]
		for v := range r.set {
			r.ordered = append(r.ordered, v)
		}
		sort.Slice(r.ordered, func(i, j int) bool {
			if len(r.ordered[i]) != len(r.ordered[j]) {
				return len(r.ordered[i]) > len(r.ordered[j])
			}
			return r.ordered[i] < r.ordered[j]
		})
	}
	return ok
}

// addPEM registers a PEM block, its base64 body and each body line.
func (r *redactor) addPEM(p []byte) {
	b, _ := pem.Decode(p)
	if b == nil {
		r.add(string(p))
		return
	}
	body := base64.StdEncoding.EncodeToString(b.Bytes)
	vals := []string{string(p), body}
	for i := 0; i < len(body); i += 64 {
		vals = append(vals, body[i:min(i+64, len(body))])
	}
	r.add(vals...)
}

var (
	urlRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>` + "`" + `]+`)
	// Generic credential shapes, applied after URL and value redaction.
	scrubRes = []struct {
		re   *regexp.Regexp
		repl string
	}{
		{regexp.MustCompile(`(?i)\bBearer\s+\S+`), "Bearer " + redacted},
		{regexp.MustCompile(`(?i)\bAuthorization:\s*\S+(\s+\S+)?`), "Authorization: " + redacted},
		{regexp.MustCompile(`(?i)(token|secret|key|password|hmac)=[^&\s]+`), "${1}=" + redacted},
		{regexp.MustCompile(`(?i)("(?:[a-z_]*token|[a-z_]*secret|password|[a-z_]*key|hmac)"\s*:\s*")[^"]*"`), "${1}" + redacted + `"`},
		{regexp.MustCompile(`(?i)((?:key|token|secret)[a-z_-]*["']?\s*[:=]?\s*["']?)[A-Za-z0-9+/_=-]{32,}`), "${1}" + redacted},
	}
)

// sanitizeURL keeps scheme, host and path; drops userinfo, query and
// fragment ("?[redacted]" marks a removed query).
func sanitizeURL(raw string) string {
	trail := ""
	for strings.HasSuffix(raw, ".") || strings.HasSuffix(raw, ",") || strings.HasSuffix(raw, ")") || strings.HasSuffix(raw, ";") {
		trail = raw[len(raw)-1:] + trail
		raw = raw[:len(raw)-1]
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" && u.Opaque != "" {
		// Unparseable: cut everything after '?' or '#', and userinfo.
		s := raw
		if i := strings.IndexAny(s, "?#"); i >= 0 {
			q := s[i] == '?'
			s = s[:i]
			if q {
				s += "?" + redacted
			}
		}
		if i := strings.Index(s, "://"); i >= 0 {
			rest := s[i+3:]
			end := strings.IndexAny(rest, "/")
			if end < 0 {
				end = len(rest)
			}
			if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
				s = s[:i+3] + redacted + "@" + rest[at+1:]
			}
		}
		return s + trail
	}
	hadQuery := u.RawQuery != "" || u.ForceQuery
	out := u.Scheme + "://"
	if u.User != nil {
		out += redacted + "@"
	}
	out += u.Host + u.EscapedPath()
	if hadQuery {
		out += "?" + redacted
	}
	return out + trail
}

// redact applies the URL, known-secret and pattern layers to s.
func (r *redactor) redact(s string) string {
	if s == "" {
		return s
	}
	s = strings.ToValidUTF8(s, "?")
	s = r.knownSecrets(s)
	s = urlRe.ReplaceAllStringFunc(s, sanitizeURL)
	for _, p := range scrubRes {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}

func (r *redactor) knownSecrets(s string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, v := range r.ordered {
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, redacted)
		}
	}
	return s
}

// errText is the redacted, then truncated, text of err. URLs carried by
// *url.Error values in the chain are sanitized even when their text would
// not match the URL pattern (e.g. unescaped spaces).
func (r *redactor) errText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	walkErr(err, func(e error) {
		var ue *url.Error
		if errors.As(e, &ue) && ue.URL != "" {
			s = strings.ReplaceAll(s, ue.URL, sanitizeURL(ue.URL))
		}
	})
	return truncate(r.redact(s))
}

func walkErr(err error, f func(error)) {
	for depth := 0; err != nil && depth < 64; depth++ {
		f(err)
		switch u := err.(type) {
		case interface{ Unwrap() []error }:
			for _, e := range u.Unwrap() {
				walkErr(e, f)
			}
			return
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		default:
			return
		}
	}
}

func truncate(s string) string {
	if len(s) > maxErrorLen {
		s = strings.ToValidUTF8(s[:maxErrorLen], "") + "..."
	}
	return s
}

// redactedError carries redacted text; the raw cause stays reachable only
// through Unwrap (for errors.Is/As), never through Error().
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// safeErr returns err with redacted text. Sentinels and errors whose text
// needs no redaction are returned as is.
func (r *redactor) safeErr(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*redactedError); ok {
		return err
	}
	if t := r.errText(err); t != err.Error() {
		return &redactedError{msg: t, cause: err}
	}
	return err
}

// redactHandler redacts the message and every string, error and
// Stringer attribute value before handing the record on.
type redactHandler struct {
	inner slog.Handler
	r     *redactor
}

func (h redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h redactHandler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.r.redact(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.attr(a))
		return true
	})
	return h.inner.Handle(ctx, out)
}

func (h redactHandler) attr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.r.redact(v.String()))
	case slog.KindGroup:
		as := v.Group()
		out := make([]any, len(as))
		for i, g := range as {
			out[i] = h.attr(g)
		}
		return slog.Group(a.Key, out...)
	case slog.KindAny:
		switch x := v.Any().(type) {
		case error:
			return slog.String(a.Key, h.r.errText(x))
		case []byte:
			return slog.String(a.Key, redacted)
		default:
			return slog.String(a.Key, h.r.redact(v.String()))
		}
	}
	return slog.Attr{Key: a.Key, Value: v}
}

func (h redactHandler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = h.attr(a)
	}
	return redactHandler{inner: h.inner.WithAttrs(out), r: h.r}
}

func (h redactHandler) WithGroup(name string) slog.Handler {
	return redactHandler{inner: h.inner.WithGroup(name), r: h.r}
}

// redactNotifier redacts event text before delivery.
type redactNotifier struct {
	inner Notifier
	r     *redactor
}

func (n redactNotifier) Notify(ctx context.Context, ev Event) {
	ev.Message = truncate(n.r.redact(ev.Message))
	n.inner.Notify(ctx, ev)
}

// secretKeyRe matches setting names that hold credentials.
var secretKeyRe = regexp.MustCompile(`(?i)(token|secret|key|pass|hmac|credential|auth|private)`)

// registerConfigSecrets registers every credential the configuration
// holds: provider settings whose name looks like a credential or that map
// to a lego environment variable (all of which are set in the process
// environment for lego), and EAB values. Values shorter than minSecretLen
// cannot be redacted and are reported.
func (m *Manager) registerConfigSecrets() {
	names := make([]string, 0, len(m.cfg.Providers))
	for n := range m.cfg.Providers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		pc := m.cfg.Providers[n]
		var mapped map[string]bool
		if cat, ok := LookupChallengeProvider(pc.Type); ok {
			mapped = map[string]bool{}
			for k := range pc.Extra {
				env, _ := envForSettings(cat, map[string]string{k: "x"})
				if len(env) > 0 {
					mapped[k] = true
				}
			}
		}
		keys := make([]string, 0, len(pc.Extra))
		for k := range pc.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !mapped[k] && !secretKeyRe.MatchString(k) {
				continue
			}
			v, err := m.settingValue(pc.Extra[k])
			if err != nil || v == "" {
				continue
			}
			if !m.red.add(v) {
				m.log.Warn("acme: credential is too short to be redacted from errors and logs", "provider", n, "setting", k)
			}
		}
	}
	inames := make([]string, 0, len(m.cfg.Issuers))
	for n := range m.cfg.Issuers {
		inames = append(inames, n)
	}
	sort.Strings(inames)
	for _, n := range inames {
		is := m.cfg.Issuers[n]
		if !m.red.add(is.EABKid) {
			m.log.Warn("acme: credential is too short to be redacted from errors and logs", "issuer", n, "setting", "eab_kid")
		}
		if !m.red.add(is.EABHMAC) {
			m.log.Warn("acme: credential is too short to be redacted from errors and logs", "issuer", n, "setting", "eab_hmac")
		}
	}
}
