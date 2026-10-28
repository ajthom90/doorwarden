package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/ajthom90/doorwarden/internal/config"
)

// failingProvider's Present returns err (a DNS challenge provider echoing
// credentials in its error, as real provider SDKs sometimes do).
type failingProvider struct{ err error }

func (p failingProvider) Present(string, string, string) error { return p.err }
func (p failingProvider) CleanUp(string, string, string) error { return nil }

// presentingHarness: Issue builds the provider and the order calls its
// Present, returning its error, like lego's DNS-01 solver.
func presentingHarness(t *testing.T, cfg *config.Config, err error) *harness {
	h := newHarness(t, cfg, func(mc *ManagerConfig) {
		mc.ProviderByName = func(string) (challenge.Provider, error) { return failingProvider{err}, nil }
	})
	h.m.obtain = func(_ context.Context, o order) (obtained, error) {
		return obtained{}, fmt.Errorf("acme: error presenting token: %w", o.Provider.Present("example.test", "tok", "keyauth"))
	}
	return h
}

func TestFailureTextRedacted(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		secrets []string
		keep    []string
	}{
		{"known provider token raw",
			errors.New("cloudflare: authentication failed for token cf-secret-token (HTTP 403) at api.example.test/client/v4"),
			[]string{"cf-secret-token"}, []string{"api.example.test/client/v4", "403"}},
		{"token in URL query",
			errors.New(`Get "https://api.example.test/v4/zones?sig=Qx7rTz9Lmn2&x=1#frag": unexpected status 401`),
			[]string{"Qx7rTz9Lmn2", "frag"}, []string{"https://api.example.test/v4/zones?[redacted]", "401"}},
		{"credentials in URL userinfo",
			errors.New(`Post "https://admin:Pw8unknownZ@dns.example.test/api/records": status 500`),
			[]string{"Pw8unknownZ", "admin:"}, []string{"dns.example.test/api/records", "500"}},
		{"authorization header fragment",
			errors.New("request rejected (status 401), sent headers: Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l"),
			[]string{"YWxhZGRpbjpvcGVuc2VzYW1l"}, []string{"401", "Authorization: [redacted]"}},
		{"bearer token",
			errors.New("status 403 for Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig on api.example.test"),
			[]string{"eyJhbGciOiJIUzI1NiJ9"}, []string{"403", "api.example.test"}},
		{"wrapped url.Error",
			fmt.Errorf("rfc2136 update: %w", &url.Error{Op: "Post", URL: "https://u:pw-in-url-1@dns.example.test/update?token=abc123secretvalue",
				Err: errors.New("dial tcp 192.0.2.1:443: connect: connection refused")}),
			[]string{"abc123secretvalue", "pw-in-url-1"}, []string{"dns.example.test/update", "connection refused"}},
		{"key=value pattern",
			errors.New("bad request (400): api_key=unknownKeyValue99 password=hunter2hunter"),
			[]string{"unknownKeyValue99", "hunter2hunter"}, []string{"400", "api_key=[redacted]"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := presentingHarness(t, nil, tc.err)
			_, err := h.m.Issue(ctx, wildcardReq())
			if err == nil {
				t.Fatal("want failure")
			}
			var ue *url.Error
			if strings.Contains(tc.name, "url.Error") && !errors.As(err, &ue) {
				t.Error("errors.As lost the cause")
			}
			// Row read back from the real store.
			rows, lerr := h.st.ListCerts(ctx)
			if lerr != nil || len(rows) != 1 {
				t.Fatal(rows, lerr)
			}
			evs := h.evs.list()
			if len(evs) != 1 {
				t.Fatalf("%d events", len(evs))
			}
			outs := map[string]string{
				"row.LastError": rows[0].LastError, "row.LastResult": rows[0].LastResult,
				"log": h.logs.String(), "event": evs[0].Message, "Result.Err": err.Error(),
			}
			// A second attempt is deferred; its error carries the stored text.
			h.clock.Add(0)
			_, derr := h.m.Issue(ctx, wildcardReq())
			outs["deferred"] = derr.Error()
			for where, s := range outs {
				for _, sec := range tc.secrets {
					if strings.Contains(s, sec) {
						t.Errorf("%s leaks %q: %s", where, sec, s)
					}
				}
			}
			for _, where := range []string{"row.LastError", "event", "Result.Err"} {
				for _, k := range tc.keep {
					if !strings.Contains(outs[where], k) {
						t.Errorf("%s lost context %q: %s", where, k, outs[where])
					}
				}
			}
		})
	}
}

// Redaction happens before truncation: a secret straddling the cut is not
// left half-visible.
func TestRedactBeforeTruncate(t *testing.T) {
	// The order wraps the provider error with this prefix (presentingHarness).
	prefix := "acme: error presenting token: "
	cause := errors.New(strings.Repeat("x", maxErrorLen-5-len(prefix)) + " cf-secret-token trailing")
	h := presentingHarness(t, nil, cause)
	_, err := h.m.Issue(ctx, wildcardReq())
	if err == nil {
		t.Fatal("want failure")
	}
	rows, _ := h.st.ListCerts(ctx)
	for where, s := range map[string]string{"row": rows[0].LastError, "err": err.Error(), "log": h.logs.String()} {
		if strings.Contains(s, "cf-s") {
			t.Errorf("%s leaks a secret prefix: ...%s", where, s[max(0, len(s)-60):])
		}
	}
	if len(rows[0].LastError) > maxErrorLen+3 {
		t.Errorf("not truncated: %d", len(rows[0].LastError))
	}
}

func TestEABAndAccountKeyRedacted(t *testing.T) {
	cfg := testConfig()
	cfg.Issuers["le"] = config.Issuer{Directory: "https://acme.example.test/dir", Email: "admin@example.test", EABKid: "kid-abcdef", EABHMAC: "hmacSecretValue_123"}
	h := presentingHarness(t, cfg, errors.New("eab rejected: kid-abcdef hmacSecretValue_123"))
	k, err := h.m.accountKey(ctx, "le")
	if err != nil || k == nil {
		t.Fatal(err)
	}
	s, _, _ := h.st.GetSetting(ctx, accountKeyKey("le"))
	raw, _ := decodeB64(s)
	plain, _ := h.box.Open(raw)
	body := keyBody(plain)
	text := h.m.red.redact("x " + body + " y " + body[64:128])
	if strings.Contains(text, body[:40]) || strings.Contains(text, body[64:128]) {
		t.Fatalf("account key not redacted: %s", text)
	}
	_, err = h.m.Issue(ctx, wildcardReq())
	if err == nil || strings.Contains(err.Error(), "hmacSecretValue_123") || strings.Contains(err.Error(), "kid-abcdef") {
		t.Fatalf("%v", err)
	}
}

func TestShortCredentialWarnsAtConstruction(t *testing.T) {
	cfg := testConfig()
	cfg.Providers["cf"] = config.ProviderCfg{Type: "cloudflare", Extra: map[string]any{"cf_dns_api_token": "abc"}}
	h := newHarness(t, cfg, nil)
	l := h.logs.String()
	if !strings.Contains(l, "too short to be redacted") || !strings.Contains(l, "cf_dns_api_token") || strings.Contains(l, "abc\"") {
		t.Fatalf("no warning: %s", l)
	}
}

func TestRedactorConcurrent(t *testing.T) {
	r := newRedactor()
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := range 50 {
				r.add(fmt.Sprintf("secret-%d-%d", i, j))
			}
		}()
		go func() {
			defer wg.Done()
			for j := range 50 {
				_ = r.redact(fmt.Sprintf("e secret-%d-%d https://u:p@h.example.test/p?q=1", i, j))
			}
		}()
	}
	wg.Wait()
	if got := r.redact("x secret-3-7 y"); got != "x [redacted] y" {
		t.Fatal(got)
	}
}

func TestSanitizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://u:p@h.example.test/a/b?x=1#f": "https://[redacted]@h.example.test/a/b?[redacted]",
		"https://h.example.test/a":             "https://h.example.test/a",
		"https://h.example.test/a#frag":        "https://h.example.test/a",
		"https://h.example.test/a?q=1.":        "https://h.example.test/a?[redacted].",
	} {
		if got := sanitizeURL(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// Defense in depth: anything logged through the Manager's logger, sent
// through its notifier or returned from its public API is redacted even
// when the caller passed raw text.
func TestManagerOutputsRedactRawText(t *testing.T) {
	h := newHarness(t, nil, nil)
	raw := fmt.Errorf("wrapped: %w", &url.Error{Op: "Get", URL: "https://u:pw-xyz-9@api.example.test/p?token=qqq", Err: errors.New("cf-secret-token rejected")})
	h.m.log.Warn("raw", "err", raw, "text", "Bearer abc.def.ghi cf-secret-token", slog.Group("g", "s", "cf-secret-token"))
	h.m.notifier.Notify(ctx, Event{Kind: EventFailure, Message: "token cf-secret-token at https://api.example.test/x?sig=zzzz"})
	logs, ev := h.logs.String(), h.evs.list()[0].Message
	for _, sec := range []string{"cf-secret-token", "pw-xyz-9", "token=qqq", "abc.def.ghi", "sig=zzzz"} {
		if strings.Contains(logs, sec) || strings.Contains(ev, sec) {
			t.Errorf("%q leaked: log=%s event=%s", sec, logs, ev)
		}
	}
	if !strings.Contains(logs, "api.example.test/p") || !strings.Contains(ev, "api.example.test/x") {
		t.Errorf("context lost: %s %s", logs, ev)
	}
	// Public API error built from caller input.
	_, err := h.m.Issue(ctx, IssueRequest{Zone: "cf-secret-token.example.test"})
	if err == nil || strings.Contains(err.Error(), "cf-secret-token") {
		t.Fatalf("%v", err)
	}
	se := h.m.red.safeErr(raw)
	var ue *url.Error
	if strings.Contains(se.Error(), "cf-secret-token") || !errors.As(se, &ue) {
		t.Fatalf("safeErr: %v", se)
	}
}
