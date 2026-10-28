package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
)

// SignatureHeader carries "sha256=<hex>" HMAC-SHA256 of the request body.
const SignatureHeader = "X-Doorwarden-Signature"

// Webhook POSTs events as JSON to a configured URL.
type Webhook struct {
	name    string
	cfg     config.WebhookCfg
	client  *http.Client
	secrets []string
}

// NewWebhook validates cfg (URL, headers) and builds the sender.
func NewWebhook(cfg config.WebhookCfg, timeout time.Duration) (*Webhook, error) {
	if err := config.ValidateNotifyURL(cfg.URL.Reveal(), cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("webhook %q: url: %w", cfg.Name, err)
	}
	for h, v := range cfg.Headers {
		if err := config.CheckHeader(h, v.Reveal()); err != nil {
			return nil, fmt.Errorf("webhook %q: %w", cfg.Name, err)
		}
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	w := &Webhook{name: cfg.Name, cfg: cfg, client: newHTTPClient(timeout)}
	w.secrets = append(w.secrets, cfg.URL.Reveal(), cfg.Secret.Reveal())
	for _, v := range cfg.Headers {
		w.secrets = append(w.secrets, v.Reveal())
	}
	return w, nil
}

// Name returns the configured sender name.
func (w *Webhook) Name() string { return w.name }

// Type is the bounded metrics label for this sender kind.
func (w *Webhook) Type() string { return "webhook" }

type webhookBody struct {
	Kind     string            `json:"kind"`
	Severity Severity          `json:"severity"`
	Subject  string            `json:"subject"`
	Message  string            `json:"message"`
	Fields   map[string]string `json:"fields"`
	At       time.Time         `json:"at"`
}

// Send posts e. Success is any 2xx response.
func (w *Webhook) Send(ctx context.Context, e Event) error {
	e = e.normalized()
	fields := e.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	body, err := json.Marshal(webhookBody{e.Kind, e.Severity, e.Subject, e.Message, fields, e.At})
	if err != nil {
		return permanent(fmt.Errorf("webhook %q: encode: %w", w.name, err))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL.Reveal(), bytes.NewReader(body))
	if err != nil {
		return permanent(fmt.Errorf("webhook %q: build request", w.name))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "doorwarden")
	for h, v := range w.cfg.Headers {
		req.Header.Set(h, v.Reveal())
	}
	if k := w.cfg.Secret.Reveal(); k != "" {
		req.Header.Set(SignatureHeader, Sign([]byte(k), body))
	}
	return doRequest(ctx, w.client, req, fmt.Sprintf("webhook %q", w.name), w.secrets...)
}

// Sign returns the signature header value for body: "sha256=" + hex HMAC.
func Sign(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
