package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Notifications configures outbound alerts (webhook, ntfy, SMTP).
//
// Secret-bearing fields (tokens, passwords, HMAC secrets, header values) are
// secrets.Secret, which redacts itself under every fmt verb, unlike the older
// provider settings that stay plain strings until wrapped at use. YAML decodes
// them from ordinary strings, and ${VAR} substitution works. The top-level
// notifications: key substitutes as plain strings (see stringOnlyTopKeys), so
// numeric and boolean options (rate_per_minute, port, queue_size,
// allow_insecure_http, ...) must be written literally, not as placeholders.
type Notifications struct {
	// DedupeWindow suppresses repeat events sharing a DedupeKey. 0 means the
	// default (1h); a negative value disables suppression.
	DedupeWindow time.Duration `yaml:"dedupe_window"`
	// Timeout bounds one delivery attempt per sender (default 10s).
	Timeout time.Duration `yaml:"timeout"`
	// QueueSize bounds the dispatcher's pending events (default 64).
	QueueSize int `yaml:"queue_size"`

	Webhooks []WebhookCfg `yaml:"webhooks"`
	Ntfy     []NtfyCfg    `yaml:"ntfy"`
	SMTP     []SMTPCfg    `yaml:"smtp"`
}

// NotifyCommon holds the options shared by every sender.
type NotifyCommon struct {
	Name string `yaml:"name"`
	// MinSeverity drops events below it: info|warning|critical (default info).
	MinSeverity string `yaml:"min_severity"`
	// RatePerMinute is the token-bucket rate (default 10).
	RatePerMinute int `yaml:"rate_per_minute"`
}

// WebhookCfg posts a JSON event to URL.
type WebhookCfg struct {
	NotifyCommon      `yaml:",inline"`
	URL               secrets.Secret            `yaml:"url"` // may embed a token, so a Secret
	Secret            secrets.Secret            `yaml:"secret"`
	Headers           map[string]secrets.Secret `yaml:"headers"`
	AllowInsecureHTTP bool                      `yaml:"allow_insecure_http"`
}

// NtfyCfg publishes to <server>/<topic>. Token and username/password are
// mutually exclusive.
type NtfyCfg struct {
	NotifyCommon      `yaml:",inline"`
	Server            string         `yaml:"server"`
	Topic             string         `yaml:"topic"`
	Token             secrets.Secret `yaml:"token"`
	Username          string         `yaml:"username"`
	Password          secrets.Secret `yaml:"password"`
	AllowInsecureHTTP bool           `yaml:"allow_insecure_http"`
}

// SMTPCfg sends plain-text mail.
type SMTPCfg struct {
	NotifyCommon `yaml:",inline"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"` // default 587 (starttls), 465 (tls), 25 (none)
	// TLS is starttls (default), tls (implicit) or none.
	TLS                string         `yaml:"tls"`
	Username           string         `yaml:"username"`
	Password           secrets.Secret `yaml:"password"`
	From               string         `yaml:"from"`
	To                 []string       `yaml:"to"`
	InsecureSkipVerify bool           `yaml:"insecure_skip_verify"`
}

func (n *Notifications) applyDefaults() {
	if n.DedupeWindow == 0 {
		n.DedupeWindow = time.Hour
	}
	if n.Timeout == 0 {
		n.Timeout = 10 * time.Second
	}
	if n.QueueSize == 0 {
		n.QueueSize = 64
	}
	def := func(c *NotifyCommon, prefix string, i int) {
		if c.Name == "" {
			c.Name = fmt.Sprintf("%s-%d", prefix, i)
		}
		if c.MinSeverity == "" {
			c.MinSeverity = "info"
		}
		if c.RatePerMinute == 0 {
			c.RatePerMinute = 10
		}
	}
	for i := range n.Webhooks {
		def(&n.Webhooks[i].NotifyCommon, "webhook", i)
	}
	for i := range n.Ntfy {
		def(&n.Ntfy[i].NotifyCommon, "ntfy", i)
	}
	for i := range n.SMTP {
		def(&n.SMTP[i].NotifyCommon, "smtp", i)
		s := &n.SMTP[i]
		if s.TLS == "" {
			s.TLS = "starttls"
		}
		if s.Port == 0 {
			s.Port = map[string]int{"starttls": 587, "tls": 465, "none": 25}[s.TLS]
		}
	}
}

var topicRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// validate returns every problem found. Messages never contain secret values.
func (n *Notifications) validate() []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if n.Timeout < 0 {
		add("notifications.timeout must not be negative")
	}
	if n.QueueSize < 0 {
		add("notifications.queue_size must not be negative")
	}
	names := map[string]bool{}
	common := func(path string, c NotifyCommon) {
		if names[c.Name] {
			add("%s: duplicate sender name %q", path, c.Name)
		}
		names[c.Name] = true
		switch c.MinSeverity {
		case "", "info", "warning", "critical":
		default:
			add("%s.min_severity %q must be info, warning or critical", path, c.MinSeverity)
		}
		if c.RatePerMinute < 0 {
			add("%s.rate_per_minute must not be negative", path)
		}
	}
	for i, w := range n.Webhooks {
		p := fmt.Sprintf("notifications.webhooks[%d]", i)
		common(p, w.NotifyCommon)
		if err := ValidateNotifyURL(w.URL.Reveal(), w.AllowInsecureHTTP); err != nil {
			add("%s.url: %v", p, err)
		}
		for h, v := range w.Headers {
			if err := CheckHeader(h, v.Reveal()); err != nil {
				add("%s.headers: %v", p, err)
			}
		}
	}
	for i, t := range n.Ntfy {
		p := fmt.Sprintf("notifications.ntfy[%d]", i)
		common(p, t.NotifyCommon)
		if err := ValidateNotifyURL(t.Server, t.AllowInsecureHTTP); err != nil {
			add("%s.server: %v", p, err)
		}
		if !topicRe.MatchString(t.Topic) {
			add("%s.topic must match [A-Za-z0-9_-]{1,64}", p)
		}
		if t.Token != "" && (t.Username != "" || t.Password != "") {
			add("%s: token and username/password are mutually exclusive", p)
		}
		if (t.Username == "") != (t.Password == "") {
			if t.Token == "" {
				add("%s: username and password must be set together", p)
			}
		}
	}
	for i, s := range n.SMTP {
		p := fmt.Sprintf("notifications.smtp[%d]", i)
		common(p, s.NotifyCommon)
		if s.Host == "" || strings.ContainsAny(s.Host, " \r\n/@") {
			add("%s.host is required and must be a bare host name", p)
		}
		if s.Port < 0 || s.Port > 65535 {
			add("%s.port out of range", p)
		}
		switch s.TLS {
		case "", "starttls", "tls", "none":
		default:
			add("%s.tls %q must be starttls, tls or none", p, s.TLS)
		}
		if s.TLS == "none" && (s.Username != "" || s.Password != "") && !isLoopbackHost(s.Host) {
			add("%s: refusing to send credentials without TLS to a non-loopback host", p)
		}
		if (s.Username == "") != (s.Password == "") {
			add("%s: username and password must be set together", p)
		}
		if _, err := mail.ParseAddress(s.From); err != nil || strings.ContainsAny(s.From, "\r\n") {
			add("%s.from is not a valid address", p)
		}
		if len(s.To) == 0 {
			add("%s.to must list at least one recipient", p)
		}
		for _, to := range s.To {
			if _, err := mail.ParseAddress(to); err != nil || strings.ContainsAny(to, "\r\n") {
				add("%s.to contains an invalid address", p)
			}
		}
	}
	return errs
}

// ValidateNotifyURL checks that raw is an absolute http(s) URL without
// userinfo or fragment. Plain http is accepted only for loopback/private
// hosts unless allowInsecure. The returned error never echoes the URL (it
// may embed a token).
func ValidateNotifyURL(raw string, allowInsecure bool) error {
	if raw == "" {
		return errors.New("is required")
	}
	if strings.ContainsAny(raw, "\r\n\t ") {
		return errors.New("must not contain whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme must be http or https")
	}
	if u.Hostname() == "" {
		return errors.New("host is required")
	}
	if u.User != nil {
		return errors.New("must not contain userinfo (use token/username/headers fields)")
	}
	if u.Fragment != "" {
		return errors.New("must not contain a fragment")
	}
	if u.Scheme == "http" && !allowInsecure && !isPrivateHost(u.Hostname()) {
		return errors.New("plain http is only allowed for private/loopback hosts (set allow_insecure_http to override)")
	}
	return nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}

func isPrivateHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()
	}
	if h == "localhost" || !strings.Contains(h, ".") {
		return true // single-label names resolve on the local network
	}
	for _, suf := range []string{".localhost", ".local", ".lan", ".internal", ".home.arpa", ".localdomain"} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

var headerNameRe = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// CheckHeader validates a custom HTTP header: a token name, no CR/LF/NUL in
// the value, and not one of the headers the sender owns. Errors never echo
// the value.
func CheckHeader(name, value string) error {
	if !headerNameRe.MatchString(name) {
		return fmt.Errorf("invalid header name %q", name)
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "content-type", "transfer-encoding", "x-doorwarden-signature":
		return fmt.Errorf("header %q is managed by doorwarden", name)
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("header %q value contains a control character", name)
	}
	return nil
}
