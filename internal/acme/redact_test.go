package acme

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/go-acme/lego/v4/challenge"
	legolog "github.com/go-acme/lego/v4/log"

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
			// The raw cause is never reachable from the returned error: its
			// text would carry the secrets.
			var ue *url.Error
			if errors.As(err, &ue) {
				t.Errorf("errors.As exposes the raw cause: %v", ue)
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
	if strings.Contains(se.Error(), "cf-secret-token") || errors.As(se, &ue) || errors.Unwrap(se) != nil {
		t.Fatalf("safeErr exposes the raw error: %v", se)
	}
}

// safeErr always wraps; errors.Is reaches sentinels and context errors
// through the cause, errors.As only allowlisted types, never raw errors.
func TestSafeErrHidesCauseButKeepsIs(t *testing.T) {
	r := newRedactor()
	plain := errors.New("plain text without secrets")
	if se := r.safeErr(plain); se == plain || errors.Unwrap(se) != nil || se.Error() != plain.Error() {
		t.Fatalf("not wrapped: %#v", se)
	}
	for _, target := range []error{ErrInFlight, context.DeadlineExceeded, context.Canceled, ErrNoIssuer} {
		se := r.safeErr(r.safeErr(fmt.Errorf("x: %w", target)))
		if !errors.Is(se, target) {
			t.Errorf("errors.Is lost %v", target)
		}
	}
	de := &DeferredError{Until: t0, Reason: "r"}
	se := r.safeErr(fmt.Errorf("w: %w", de))
	var got *DeferredError
	if !errors.As(r.safeErr(se), &got) || got != de || !errors.Is(se, ErrDeferred) {
		t.Fatal("DeferredError not reachable")
	}
	var ue *url.Error
	if errors.As(r.safeErr(&url.Error{Op: "Get", URL: "https://h.example.test", Err: plain}), &ue) {
		t.Fatal("url.Error reachable")
	}
}

// Encoded forms of a known secret are redacted too.
func TestRedactEncodedSecretForms(t *testing.T) {
	r := newRedactor()
	sec := "p@ss w/rd+\"q\u00e9"
	r.add(sec)
	hex := "DEADBEEFcafe0123"
	r.add(hex)
	b64 := "s3cr3t-value-xyz"
	r.add(b64)
	for _, enc := range []string{
		url.PathEscape(sec), url.QueryEscape(sec), strings.Trim(strconv.Quote(sec), `"`),
		base64.StdEncoding.EncodeToString([]byte(b64)), base64.URLEncoding.EncodeToString([]byte(b64)),
		base64.RawStdEncoding.EncodeToString([]byte(b64)), base64.RawURLEncoding.EncodeToString([]byte(b64)),
		strings.ToLower(hex), strings.ToUpper(hex),
	} {
		out := r.redact("before " + enc + " after")
		if strings.Contains(out, enc) || !strings.Contains(out, "before") || !strings.Contains(out, "after") {
			t.Errorf("%q: %s", enc, out)
		}
	}
}

func TestSanitizeURLAuthorityWithSlashAndAt(t *testing.T) {
	for in, want := range map[string]string{
		"https://user:p@ss/w@host.example.test/x":   "https://[redacted]@host.example.test/x",
		"https://user:p%2@host.example.test/x?a=1":  "https://[redacted]@host.example.test/x?[redacted]",
		"https://u:a b@host.example.test/x":         "https://[redacted]@host.example.test/x",
		"https://host.example.test/x?mail=a@b.test": "https://host.example.test/x?[redacted]",
	} {
		if got := sanitizeURL(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	r := newRedactor()
	if out := r.redact(`Get "https://user:p@ss/w@host.example.test/x": refused`); strings.Contains(out, "ss/w") || strings.Contains(out, "user") {
		t.Fatal(out)
	}
}

func TestKeyValueScrubPattern(t *testing.T) {
	r := newRedactor()
	for in, leak := range map[string]string{
		"failed: token: abcdef123":       "abcdef123",
		"failed: Secret = zzzyyyxxx,":    "zzzyyyxxx",
		"authorization=QWxhZGRpbjpvcGVu": "QWxhZGRpbjpvcGVu",
		`password:"hunter2x"`:            "hunter2x",
		"api_key=k123456&x=1":            "k123456",
	} {
		if out := r.redact(in); strings.Contains(out, leak) {
			t.Errorf("%q -> %q", in, out)
		}
	}
}

// Only credentials are registered as secrets: a short Additional setting
// (a TTL) causes no warning, and a base URL is not scrubbed from messages.
func TestOnlyCredentialSettingsRegistered(t *testing.T) {
	cfg := testConfig()
	cfg.Providers["cf"] = config.ProviderCfg{Type: "cloudflare", Extra: map[string]any{
		"cf_dns_api_token": "cf-secret-token", "cloudflare_ttl": 120, "cloudflare_propagation_timeout": "300",
	}}
	cfg.Providers["pd"] = config.ProviderCfg{Type: "pdns", Extra: map[string]any{
		"pdns_api_url": "https://pdns.example.test:8081", "pdns_api_key": "pdns-key-value",
	}}
	cfg.Zones = append(cfg.Zones, config.Zone{Name: "pd.example.test", TargetIP: "192.0.2.10",
		Certificate: config.Certificate{Issuer: "le", Strategy: "wildcard", Challenge: "dns-01", DNSProvider: "pd"}})
	h := newHarness(t, cfg, nil)
	if l := h.logs.String(); strings.Contains(l, "too short") {
		t.Fatalf("spurious warning: %s", l)
	}
	if _, err := h.m.dnsChallengeProvider("pd"); err != nil {
		t.Fatal(err)
	}
	out := h.m.red.redact("dial https://pdns.example.test:8081/api failed; key pdns-key-value 300")
	if !strings.Contains(out, "pdns.example.test:8081") || strings.Contains(out, "pdns-key-value") || !strings.Contains(out, "300") {
		t.Fatalf("%s", out)
	}
}

// <VAR>_FILE settings: the file's contents (and each line) are secrets, the
// path is not a substitute.
func TestFileSettingContentsRegistered(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "token")
	must(t, os.WriteFile(f, []byte("file-token-line1\nfile-token-line2\n"), 0o600))
	tsig := filepath.Join(dir, "tsig.key")
	must(t, os.WriteFile(tsig, []byte("key \"k\" { algorithm hmac-sha256; secret \"dHNpZ3NlY3JldHZhbHVl\"; };\n"), 0o600))
	cfg := testConfig()
	cfg.Providers["cf"] = config.ProviderCfg{Type: "cloudflare", Extra: map[string]any{"cf_dns_api_token_file": f}}
	cfg.Providers["du"] = config.ProviderCfg{Type: "rfc2136", Extra: map[string]any{"dnsupdate_tsig_file": tsig, "dnsupdate_nameserver": "192.0.2.53"}}
	h := newHarness(t, cfg, nil)
	if _, err := h.m.dnsChallengeProvider("cf"); err != nil {
		t.Fatal(err)
	}
	out := h.m.red.redact("x file-token-line1 y file-token-line2 z dHNpZ3NlY3JldHZhbHVl " + f)
	for _, sec := range []string{"file-token-line1", "file-token-line2", "dHNpZ3NlY3JldHZhbHVl"} {
		if strings.Contains(out, sec) {
			t.Errorf("%s leaked: %s", sec, out)
		}
	}
	if !strings.Contains(out, f) {
		t.Errorf("path should stay visible: %s", out)
	}
}

// lego's global logger resolves slog.Default() at log time, so a default
// installed after the first Manager still receives (redacted) lego logs.
func TestLegoLoggerFollowsSlogDefault(t *testing.T) {
	h := newHarness(t, nil, nil)
	_ = h
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	var buf syncBuffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	legolog.Logger.Printf("lego says cf-secret-token")
	if out := buf.String(); !strings.Contains(out, "lego says") || strings.Contains(out, "cf-secret-token") {
		t.Fatalf("%q", out)
	}
}
