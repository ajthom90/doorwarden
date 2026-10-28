package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Redaction: every string that leaves the Manager (cert rows, logs,
// notifier events, returned error text) passes through redactor.redact,
// which (1) rewrites URLs (userinfo, query and fragment removed), (2)
// replaces every secret value known to the Manager, (3) scrubs generic
// credential patterns. Truncation happens only after redaction. The raw
// error is kept in memory only: a returned error never unwraps to it;
// errors.Is is answered through it (sentinels, context errors) and
// errors.As only for allowlisted types (*DeferredError).

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
	// hex holds lowercase hexadecimal secrets, matched case-insensitively.
	hex []string
}

func newRedactor() *redactor { return &redactor{set: map[string]bool{}} }

// encodedForms returns v and the forms it commonly takes inside error text
// and logs: URL path and query escaping, JSON/Go string escaping and, for
// values of 8 or more bytes, standard and URL base64 (padded and raw).
func encodedForms(v string) []string {
	out := []string{v, url.PathEscape(v), url.QueryEscape(v)}
	if q := strconv.Quote(v); len(q) >= 2 {
		out = append(out, q[1:len(q)-1])
	}
	if js, err := json.Marshal(v); err == nil && len(js) >= 2 {
		out = append(out, string(js[1:len(js)-1]))
	}
	if len(v) >= 8 {
		b := []byte(v)
		out = append(out, base64.StdEncoding.EncodeToString(b), base64.URLEncoding.EncodeToString(b),
			base64.RawStdEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b))
	}
	return out
}

func isHex(v string) bool {
	if len(v) < minSecretLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

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
		for _, f := range encodedForms(v) {
			if len(f) >= minSecretLen && !r.set[f] {
				r.set[f] = true
				changed = true
			}
		}
		if isHex(v) {
			lv := strings.ToLower(v)
			if !slices.Contains(r.hex, lv) {
				r.hex = append(r.hex, lv)
			}
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
	}
	// kvKeyRe finds "<credential word>[quote]<sep>" before a value; the
	// value itself is delimited by scrubKV (quote-aware), not by a regexp.
	kvKeyRe = regexp.MustCompile(`(?i)(?:token|secret|key|password|hmac|authorization)["']?\s*[:=]\s*`)
	// longRunRe: long key-like runs after a credential word, separator
	// optional (applied last).
	longRunRe = regexp.MustCompile(`(?i)((?:key|token|secret)[a-z_-]*["']?\s*[:=]?\s*["']?)[A-Za-z0-9+/_=-]{32,}`)
)

// scrubKV redacts the value after every "<credential word><sep>" in s. A
// value starting with a quote runs to the matching unescaped quote of the
// same kind (across lines; without one, to the end of the line) and its
// body is replaced, quotes kept. An unquoted value runs to whitespace or
// '&' (commas and quotes inside are part of it); for an authorization
// value of the form "<Scheme> <credentials>" both words are consumed.
func scrubKV(s string) string {
	var b strings.Builder
	pos := 0
	for pos < len(s) {
		loc := kvKeyRe.FindStringIndex(s[pos:])
		if loc == nil {
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		b.WriteString(s[pos:end])
		rest := s[end:]
		if rest == "" {
			pos = end
			break
		}
		if q := rest[0]; q == '"' || q == '\'' {
			i, closed := 1, false
			for i < len(rest) {
				if rest[i] == '\\' {
					i += 2
					continue
				}
				if rest[i] == q {
					closed = true
					break
				}
				i++
			}
			if closed {
				b.WriteString(string(q) + redacted + string(q))
				pos = end + i + 1
			} else {
				n := strings.IndexByte(rest, '\n')
				if n < 0 {
					n = len(rest)
				}
				b.WriteString(string(q) + redacted)
				pos = end + n
			}
			continue
		}
		n := strings.IndexAny(rest, "& \t\r\n")
		if n < 0 {
			n = len(rest)
		}
		if n == 0 {
			pos = end
			continue
		}
		if strings.HasPrefix(strings.ToLower(s[start:end]), "authorization") && isSchemeWord(rest[:n]) {
			// "<Scheme> <credentials>": consume the credentials word too.
			j := n
			for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
				j++
			}
			if k := strings.IndexAny(rest[j:], "& \t\r\n"); k != 0 && j < len(rest) {
				if k < 0 {
					k = len(rest) - j
				}
				n = j + k
			}
		}
		b.WriteString(redacted)
		pos = end + n
	}
	b.WriteString(s[pos:])
	return b.String()
}

func isSchemeWord(w string) bool {
	switch strings.ToLower(w) {
	case "basic", "bearer", "digest", "token", "negotiate", "hmac", "apikey":
		return true
	}
	return false
}

// sanitizeURL keeps scheme, host and path; drops userinfo, query and
// fragment ("?[redacted]" marks a removed query). Userinfo is everything
// between "://" and the LAST '@' before any '?' or '#', so a password
// containing '@' or '/' is removed entirely, parseable or not.
func sanitizeURL(raw string) string {
	trail := ""
	for strings.HasSuffix(raw, ".") || strings.HasSuffix(raw, ",") || strings.HasSuffix(raw, ")") || strings.HasSuffix(raw, ";") {
		trail = raw[len(raw)-1:] + trail
		raw = raw[:len(raw)-1]
	}
	user := ""
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		end := len(rest)
		if j := strings.IndexAny(rest, "?#"); j >= 0 {
			end = j
		}
		if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
			raw = raw[:i+3] + rest[at+1:]
			user = redacted + "@"
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" && u.Opaque != "" || u.User != nil {
		// Unparseable: cut everything after '?' or '#'.
		s := raw
		if i := strings.IndexAny(s, "?#"); i >= 0 {
			q := s[i] == '?'
			s = s[:i]
			if q {
				s += "?" + redacted
			}
		}
		if i := strings.Index(s, "://"); i >= 0 && user != "" {
			s = s[:i+3] + user + s[i+3:]
		}
		return s + trail
	}
	hadQuery := u.RawQuery != "" || u.ForceQuery
	out := u.Scheme + "://" + user + u.Host + u.EscapedPath()
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
	s = scrubKV(s)
	s = longRunRe.ReplaceAllString(s, "${1}"+redacted)
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
	for _, h := range r.hex {
		s = replaceFoldASCII(s, h)
	}
	return s
}

// replaceFoldASCII replaces every ASCII-case-insensitive occurrence of the
// lowercase needle in s.
func replaceFoldASCII(s, needle string) string {
	low := asciiLower(s)
	if !strings.Contains(low, needle) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(low, needle)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(redacted)
		s, low = s[i+len(needle):], low[i+len(needle):]
	}
}

// asciiLower lowercases ASCII letters only, so byte offsets are preserved.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
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

// redactedError carries redacted text. It deliberately has no Unwrap: the
// raw cause (whose text or fields may hold secrets) is never handed out.
// errors.Is is answered through the cause (sentinels, context errors);
// errors.As only for allowlisted types whose content is already redacted.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }

// Is reports whether the cause matches target (errors.Is semantics).
func (e *redactedError) Is(target error) bool { return errors.Is(e.cause, target) }

// As fills target from the cause only for *DeferredError (its texts come
// from the redacted store); every other type is refused.
func (e *redactedError) As(target any) bool {
	switch target.(type) {
	case **DeferredError:
		return errors.As(e.cause, target)
	}
	return false
}

// safeErr returns err wrapped as a *redactedError with redacted text (an
// already wrapped error is returned as is).
func (r *redactor) safeErr(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*redactedError); ok {
		return err
	}
	return &redactedError{msg: r.errText(err), cause: err}
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

// defaultHandler forwards to slog.Default()'s handler as it is at log
// time, so a default logger installed after the first Manager (lego's
// logger is a process global set once) still receives lego's output.
// WithAttrs/WithGroup are recorded and replayed on each record.
type defaultHandler struct {
	ops []func(slog.Handler) slog.Handler
}

func (h defaultHandler) current() slog.Handler {
	out := slog.Default().Handler()
	for _, op := range h.ops {
		out = op(out)
	}
	return out
}

func (h defaultHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return slog.Default().Handler().Enabled(ctx, l)
}

func (h defaultHandler) Handle(ctx context.Context, rec slog.Record) error {
	return h.current().Handle(ctx, rec)
}

func (h defaultHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return defaultHandler{ops: append(slices.Clip(h.ops), func(x slog.Handler) slog.Handler { return x.WithAttrs(as) })}
}

func (h defaultHandler) WithGroup(name string) slog.Handler {
	return defaultHandler{ops: append(slices.Clip(h.ops), func(x slog.Handler) slog.Handler { return x.WithGroup(name) })}
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

// fileSettingRe matches lego settings whose value names a file holding
// credentials (<VAR>_FILE, TSIG key files, keytabs, private key and
// service-account files).
var fileSettingRe = regexp.MustCompile(`(_FILE|_PATH)$`)

// maxSecretFile bounds a credential file read for redaction.
const maxSecretFile = 1 << 20

// secretFileValues reads a credential file (regular, at most 1 MiB) and
// returns its trimmed contents and each trimmed line. The path itself is
// not a secret and is never returned.
func secretFileValues(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecretFile {
		return nil, errors.New("file too large")
	}
	vals := []string{strings.TrimSpace(string(b))}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			vals = append(vals, l)
		}
	}
	// Key-like tokens inside config-style files (a TSIG file's
	// secret "...";, JSON service-account fields).
	vals = append(vals, keyTokenRe.FindAllString(string(b), -1)...)
	return vals, nil
}

// keyTokenRe matches base64/hex-like tokens long enough to be key material.
var keyTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)

// isCredentialSetting reports whether a provider setting holds a secret:
// it maps to one of the provider's documented Credentials (or its _FILE
// form), or its name (setting key or lego variable) looks like one.
// Additional settings (TTLs, timeouts, base URLs) are not secrets.
func isCredentialSetting(cat ChallengeProvider, key, envName string) bool {
	if a, ok := settingAliases[cat.Name][settingKey(key)]; ok && a.Credential {
		return true
	}
	if envName != "" {
		for _, c := range cat.Credentials {
			if envName == c || envName == c+"_FILE" {
				return true
			}
		}
	}
	return secretKeyRe.MatchString(key) || (envName != "" && secretKeyRe.MatchString(envName))
}

// registerSetting registers one provider setting's secret value(s): for a
// file setting the file's contents, otherwise, for a credential setting,
// the value and (for a URL) its secret-bearing parts. It returns false when
// a value is too short to redact.
func (m *Manager) registerSetting(cat ChallengeProvider, key, envName, value string) bool {
	if value == "" {
		return true
	}
	if envName != "" && fileSettingRe.MatchString(envName) {
		vals, err := secretFileValues(value)
		if err != nil {
			m.log.Warn("acme: credential file cannot be read for redaction", "setting", key, "err", err.Error())
			return true
		}
		m.red.add(vals...)
		return true
	}
	if !isCredentialSetting(cat, key, envName) {
		return true // Additional settings (TTLs, base URLs) are not secrets
	}
	ok := m.red.add(value)
	m.red.add(urlParts(value)...)
	return ok
}

// urlParts returns the secret-bearing components of a URL-shaped credential
// (userinfo, its user and password, each path segment of 4 or more bytes,
// each query value), so a provider echoing only part of it is redacted.
func urlParts(v string) []string {
	if !strings.Contains(v, "://") {
		return nil
	}
	i := strings.Index(v, "://")
	rest := v[i+3:]
	var out []string
	end := len(rest)
	if j := strings.IndexAny(rest, "?#"); j >= 0 {
		end = j
	}
	if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
		ui := rest[:at]
		out = append(out, ui)
		if u, p, ok := strings.Cut(ui, ":"); ok {
			out = append(out, u, p)
		}
		rest = rest[at+1:]
	}
	u, err := url.Parse(v[:i+3] + rest)
	if err != nil {
		return out
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if len(seg) >= minSecretLen {
			out = append(out, seg)
			if d, err := url.PathUnescape(seg); err == nil {
				out = append(out, d)
			}
		}
	}
	for _, vals := range u.Query() {
		out = append(out, vals...)
	}
	if u.Fragment != "" {
		out = append(out, u.Fragment)
	}
	return out
}

// registerConfigSecrets registers every credential the configuration
// holds (see registerSetting) and EAB values. Values shorter than
// minSecretLen cannot be redacted and are reported.
func (m *Manager) registerConfigSecrets() {
	names := make([]string, 0, len(m.cfg.Providers))
	for n := range m.cfg.Providers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		pc := m.cfg.Providers[n]
		cat, _ := LookupChallengeProvider(pc.Type)
		keys := make([]string, 0, len(pc.Extra))
		for k := range pc.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v, err := m.settingValue(pc.Extra[k])
			if err != nil || v == "" {
				continue
			}
			if !m.registerSetting(cat, k, settingEnvName(cat, k), v) {
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

// settingEnvName is the lego variable a setting key maps to ("" if none).
func settingEnvName(cat ChallengeProvider, key string) string {
	env, _ := envForSettings(cat, map[string]string{key: "x"})
	for k := range env {
		return k
	}
	return ""
}
