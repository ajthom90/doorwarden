package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
	"time"
)

func TestNotificationsDefaultsAndSecretEnv(t *testing.T) {
	yml := base + `notifications:
  webhooks:
    - url: https://hooks.example.test/x
      secret: ${HMAC}
  ntfy:
    - server: http://10.0.0.5:8080
      topic: alerts
      token: ${TOK}
  smtp:
    - host: mail.example.test
      from: doorwarden@example.test
      to: [admin@example.test]
      password: ${PW}
      username: u
`
	// numeric/bool-looking secrets must stay exact strings
	c, err := loadStr(t, yml, map[string]string{"HMAC": "0123", "TOK": "true", "PW": "1e3"})
	if err != nil {
		t.Fatal(err)
	}
	n := c.Notifications
	if n.Webhooks[0].Secret.Reveal() != "0123" || n.Ntfy[0].Token.Reveal() != "true" || n.SMTP[0].Password.Reveal() != "1e3" {
		t.Fatalf("secrets retyped: %q %q %q", n.Webhooks[0].Secret.Reveal(), n.Ntfy[0].Token.Reveal(), n.SMTP[0].Password.Reveal())
	}
	if n.DedupeWindow != time.Hour || n.Timeout != 10*time.Second || n.QueueSize != 64 {
		t.Fatalf("defaults: %v %v %d", n.DedupeWindow, n.Timeout, n.QueueSize)
	}
	if n.SMTP[0].Port != 587 || n.SMTP[0].TLS != "starttls" || n.Webhooks[0].RatePerMinute != 10 || n.Webhooks[0].Name != "webhook-0" {
		t.Fatalf("sender defaults: %+v", n.SMTP[0])
	}
	if errs := c.Validate(nil); len(errs) != 0 {
		t.Fatalf("unexpected: %v", errs)
	}
	if s := fmt.Sprintf("%+v %v", n, n.Webhooks[0]); strings.Contains(s, "0123") || strings.Contains(s, "1e3") {
		t.Fatalf("secret leaked via fmt: %s", s)
	}
}

func TestNotificationsStrictKeys(t *testing.T) {
	if _, err := loadStr(t, base+"notifications:\n  bogus: 1\n", nil); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := loadStr(t, base+"notifications:\n  webhooks:\n    - url: https://a.example.test\n      bogus: 1\n", nil); err == nil {
		t.Fatal("unknown nested key accepted")
	}
}

func TestNotificationsValidation(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"http public", "webhooks:\n  - url: http://hooks.example.test/x\n", "plain http"},
		{"http public allowed", "webhooks:\n  - url: http://hooks.example.test/x\n    allow_insecure_http: true\n", ""},
		{"http lan ok", "webhooks:\n  - url: http://192.0.2.1/x\n", "plain http"}, // RFC 5737 is not private
		{"http rfc1918 ok", "webhooks:\n  - url: http://10.1.2.3/x\n", ""},
		{"http loopback ok", "webhooks:\n  - url: http://127.0.0.1:9/x\n", ""},
		{"userinfo", "webhooks:\n  - url: https://u:p@hooks.example.test/x\n", "userinfo"},
		{"scheme", "webhooks:\n  - url: ftp://hooks.example.test/x\n", "scheme"},
		{"empty url", "webhooks:\n  - secret: x\n", "required"},
		{"bad severity", "webhooks:\n  - url: https://a.example.test\n    min_severity: loud\n", "min_severity"},
		{"dup names", "webhooks:\n  - {name: a, url: \"https://a.example.test\"}\n  - {name: a, url: \"https://b.example.test\"}\n", "duplicate"},
		{"bad header", "webhooks:\n  - url: https://a.example.test\n    headers:\n      \"X-A\": \"v\\nInjected: 1\"\n", "control character"},
		{"managed header", "webhooks:\n  - url: https://a.example.test\n    headers:\n      Content-Type: x\n", "managed"},
		{"ntfy topic", "ntfy:\n  - server: https://ntfy.example.test\n    topic: a/b\n", "topic"},
		{"ntfy both auth", "ntfy:\n  - server: https://ntfy.example.test\n    topic: a\n    token: t\n    username: u\n    password: p\n", "mutually exclusive"},
		{"smtp bad from", "smtp:\n  - host: m.example.test\n    from: nope\n    to: [a@example.test]\n", "from"},
		{"smtp no to", "smtp:\n  - host: m.example.test\n    from: a@example.test\n", "recipient"},
		{"smtp bad tls", "smtp:\n  - host: m.example.test\n    tls: maybe\n    from: a@example.test\n    to: [b@example.test]\n", "tls"},
		{"smtp creds no tls", "smtp:\n  - host: m.example.test\n    tls: none\n    username: u\n    password: p\n    from: a@example.test\n    to: [b@example.test]\n", "without TLS"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := loadStr(t, base+"notifications:\n"+indent(tc.body), nil)
			if err != nil {
				t.Fatal(err)
			}
			errs := c.Validate(nil)
			if tc.want == "" {
				if len(errs) != 0 {
					t.Fatalf("unexpected %v", errs)
				}
				return
			}
			if !hasErr(errs, tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, errs)
			}
		})
	}
}

func TestNotifyValidationNeverEchoesURL(t *testing.T) {
	err := ValidateNotifyURL("http://hooks.example.test/SECRETTOKEN123", false)
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN123") {
		t.Fatalf("err = %v", err)
	}
}

func indent(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("  " + l + "\n")
	}
	return b.String()
}

// The notifications: subtree substitutes as plain strings, like providers:.
func TestNotificationsSubtreeIsStringOnly(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("notifications:\n  smtp:\n    - password: ${PW}\nother: ${PW}\n"), &root); err != nil {
		t.Fatal(err)
	}
	var missing []string
	substituteNode(&root, func(string) (string, bool) { return "0123", true }, &missing)
	m := root.Content[0]
	pw := m.Content[1].Content[1].Content[0].Content[1] // notifications.smtp[0].password value
	if pw.Tag != "!!str" {
		t.Fatalf("notifications password tag = %s, want !!str", pw.Tag)
	}
	if other := m.Content[3]; other.Tag != "!!int" {
		t.Fatalf("control: top-level placeholder tag = %s, want !!int", other.Tag)
	}
}
