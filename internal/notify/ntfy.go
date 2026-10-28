package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
)

var topicRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Ntfy publishes events to an ntfy topic.
type Ntfy struct {
	name    string
	cfg     config.NtfyCfg
	target  string
	client  *httpDoer
	secrets []string
}

// NewNtfy validates cfg and builds the sender.
func NewNtfy(cfg config.NtfyCfg, timeout time.Duration) (*Ntfy, error) {
	if err := config.ValidateNotifyURL(cfg.Server, cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("ntfy %q: server: %w", cfg.Name, err)
	}
	if !topicRe.MatchString(cfg.Topic.Reveal()) {
		return nil, fmt.Errorf("ntfy %q: invalid topic", cfg.Name)
	}
	if cfg.Token != "" && (cfg.Username != "" || cfg.Password != "") {
		return nil, fmt.Errorf("ntfy %q: token and username/password are mutually exclusive", cfg.Name)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	n := &Ntfy{
		name: cfg.Name, cfg: cfg,
		target: strings.TrimRight(cfg.Server, "/") + "/" + cfg.Topic.Reveal(),
		client: newHTTPClient(timeout),
	}
	n.secrets = append(urlSecrets(n.target), cfg.Token.Reveal(), cfg.Password.Reveal(), cfg.Topic.Reveal())
	n.secrets = append(n.secrets, urlSecrets(cfg.Server)...)
	return n, nil
}

// Name returns the configured sender name.
func (n *Ntfy) Name() string { return n.name }

// Type is the bounded metrics label for this sender kind.
func (n *Ntfy) Type() string { return "ntfy" }

func ntfyPriority(s Severity) string {
	switch s {
	case Critical:
		return "5"
	case Warning:
		return "4"
	}
	return "3"
}

func ntfySeverityTag(s Severity) string {
	switch s {
	case Critical:
		return "rotating_light"
	case Warning:
		return "warning"
	}
	return "information_source"
}

var nonTag = regexp.MustCompile(`[^a-z0-9_]+`)

// checkHeaderValue rejects values that could split or smuggle HTTP/mail headers.
func checkHeaderValue(name, v string) error {
	if strings.ContainsAny(v, "\r\n\x00") {
		return permanent(fmt.Errorf("header %s: value contains a control character (CR/LF/NUL rejected)", name))
	}
	return nil
}

// Send publishes e. Success is any 2xx response.
func (n *Ntfy) Send(ctx context.Context, e Event) error {
	e = e.normalized()
	if err := checkHeaderValue("Title", e.Subject); err != nil {
		return fmt.Errorf("ntfy %q: %w", n.name, err)
	}
	var body bytes.Buffer
	body.WriteString(e.Message)
	if len(e.Fields) > 0 {
		body.WriteString("\n\n")
		for _, k := range sortedFields(e.Fields) {
			fmt.Fprintf(&body, "%s: %s\n", k, e.Fields[k])
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.target, &body)
	if err != nil {
		return permanent(errors.New("ntfy " + fmt.Sprintf("%q", n.name) + ": build request"))
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("User-Agent", "doorwarden")
	req.Header.Set("Title", mime.QEncoding.Encode("UTF-8", e.Subject))
	req.Header.Set("Priority", ntfyPriority(e.Severity))
	tags := ntfySeverityTag(e.Severity)
	if k := nonTag.ReplaceAllString(strings.ToLower(e.Kind), "_"); strings.Trim(k, "_") != "" {
		tags += "," + strings.Trim(k, "_")
	}
	req.Header.Set("Tags", tags)
	switch {
	case n.cfg.Token != "":
		req.Header.Set("Authorization", "Bearer "+n.cfg.Token.Reveal())
	case n.cfg.Username != "":
		req.SetBasicAuth(n.cfg.Username, n.cfg.Password.Reveal())
	}
	return doRequest(ctx, n.client, req, fmt.Sprintf("ntfy %q", n.name), n.secrets...)
}
