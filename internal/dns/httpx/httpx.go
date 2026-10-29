// Package httpx is the small HTTP client shared by the hand-written DNS
// providers: context-aware, bounded response size, no proxy from the
// environment (LAN targets), configurable TLS verification, and error text
// scrubbed of secrets.
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const (
	// DefaultTimeout bounds one request when the caller's context has no deadline.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxBody is the response size limit.
	DefaultMaxBody = 4 << 20
)

// ErrTooLarge is returned when a response exceeds the size limit.
var ErrTooLarge = errors.New("response exceeds size limit")

// StatusError is a non-2xx HTTP response. Msg is a short, secret-free summary.
type StatusError struct {
	Status int
	Msg    string
}

func (e *StatusError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("http status %d", e.Status)
	}
	return fmt.Sprintf("http status %d: %s", e.Status, e.Msg)
}

// ErrNotSent marks a failure that happened before the request reached the
// server: building the request (path, body encoding), a context already done, a
// dial or TLS failure. Such a request cannot have been applied.
var ErrNotSent = errors.New("request not sent")

// IsDefinitiveRejection reports whether err is a 4xx answer: the server
// ANSWERED and refused the request, so it was not applied. A 5xx answer is NOT
// definitive: a gateway (502/504) or an overloaded backend (500/503) may answer
// after the write was applied.
func IsDefinitiveRejection(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status >= 400 && se.Status < 500
}

// NotApplied reports whether err proves that a request was NOT applied: it was
// never sent (ErrNotSent) or the server refused it with a 4xx status. Every
// other failure of a write is ambiguous (timeout, cancellation or connection
// loss after the request was written, a 5xx status, a truncated, oversized or
// unparseable answer): the write may have been applied, and providers return
// the attempted Record with an error built by Ambiguous.
func NotApplied(err error) bool {
	return err != nil && (errors.Is(err, ErrNotSent) || IsDefinitiveRejection(err))
}

// Ambiguous builds the error for a write whose outcome is unknown: it wraps
// dns.ErrUnconfirmed (the caller still gets the Record that was attempted) and
// its text is scrubbed of this client's secrets.
func (c *Client) Ambiguous(op string, cause error) error {
	return fmt.Errorf("%s: the request may have been applied but the outcome is unknown (%s): %w", op, c.Scrub(cause.Error()), dns.ErrUnconfirmed)
}

// IsAuth reports 401/403.
func (e *StatusError) IsAuth() bool { return e.Status == 401 || e.Status == 403 }

// RawJSON is a request body sent byte for byte. json.Marshal would re-compact
// it and HTML-escape "<", ">" and "&", which matters when a server stores and
// later compares the exact text.
type RawJSON []byte

// Client talks to one base URL. The secrets it scrubs from error text are held
// only inside closures (see dns.Scrubber), never in a field, so formatting a
// Client by reflection cannot reveal them.
type Client struct {
	Base    *url.URL
	HC      *http.Client
	MaxBody int64

	addSecret func(secrets.Secret)
	scrub     func(string) string
}

// New builds a client for base (scheme://host[:port][/prefix]).
func New(base string, insecureSkipVerify bool, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("config field \"url\" must be an http(s) URL such as https://host[:port]")
	}
	if u.User != nil {
		return nil, errors.New("config field \"url\" must not embed credentials")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	tr := &http.Transport{
		Proxy:                 nil,                                                                               // never honour HTTP(S)_PROXY for DNS-server targets
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureSkipVerify, MinVersion: tls.VersionTLS12}, //nolint:gosec // operator opt-in
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
	}
	hc := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: refuseCrossHost}
	add, scrub := dns.Scrubber()
	return &Client{Base: u, HC: hc, MaxBody: DefaultMaxBody, addSecret: add, scrub: scrub}, nil
}

// refuseCrossHost stops redirects that leave the original host, so credential
// headers (X-API-KEY, tokens, cookies) are never forwarded elsewhere.
func refuseCrossHost(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) || req.URL.Scheme != via[0].URL.Scheme {
		return errors.New("refusing redirect to a different host or scheme")
	}
	return nil
}

// CheckURL validates the user-supplied base URL of a self-hosted provider:
// http(s), host present, no userinfo. Plain http is allowed only for
// loopback/private/link-local IPs, dot-less hostnames or "localhost", unless
// allowInsecureHTTP is set (config "allow_insecure_http").
func CheckURL(raw string, allowInsecureHTTP bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("config field \"url\" must be an http(s) URL such as https://host[:port]")
	}
	if u.User != nil {
		return errors.New("config field \"url\" must not embed credentials")
	}
	if u.Scheme == "http" && !allowInsecureHTTP && !privateHost(u.Hostname()) {
		return errors.New("config field \"url\": plain http to a non-private host would send credentials in clear text; use https or set allow_insecure_http: true")
	}
	return nil
}

func privateHost(h string) bool {
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return h == "localhost" || !strings.Contains(h, ".")
}

// Close drops idle connections.
func (c *Client) Close() { c.HC.CloseIdleConnections() }

// AddSecret registers values to scrub from every error string this client
// returns (credentials, session tokens).
func (c *Client) AddSecret(ss ...secrets.Secret) {
	for _, s := range ss {
		c.addSecret(s)
	}
}

// Scrub replaces every registered secret in s.
func (c *Client) Scrub(s string) string { return c.scrub(s) }

type scrubbed struct {
	msg string
	err error
}

func (e *scrubbed) Error() string { return e.msg }

// There is deliberately no Unwrap: the wrapped error (a *url.Error, a syscall
// error) carries unscrubbed text and could be unwrapped and printed by a caller.
// Is delegates identity checks (context.DeadlineExceeded, net errors by
// sentinel), and As exposes only the allowlisted types callers branch on.
func (e *scrubbed) Is(target error) bool { return errors.Is(e.err, target) }

func (e *scrubbed) As(target any) bool {
	switch target.(type) {
	case **StatusError, *net.Error:
		return errors.As(e.err, target)
	}
	return false
}

func (c *Client) wrap(err error) error {
	if err == nil {
		return nil
	}
	var se *StatusError
	if errors.As(err, &se) {
		return err
	}
	return &scrubbed{msg: c.Scrub(err.Error()), err: err}
}

// Do sends a request. body (if non-nil) is JSON-encoded; out (if non-nil) is
// JSON-decoded from the response. A url.Values body is sent form-encoded and a
// RawJSON body verbatim. query may be nil. The response status is returned even
// on error when a response was received. A failure before any request byte was
// written wraps ErrNotSent (see NotApplied).
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, hdr http.Header, body, out any) (int, error) {
	u := *c.Base
	// path is already escaped by the caller (url.PathEscape on variable parts)
	u.RawPath = strings.TrimRight(u.EscapedPath(), "/") + path
	if up, err := url.PathUnescape(u.RawPath); err == nil {
		u.Path = up
	} else {
		return 0, fmt.Errorf("invalid request path: %w: %w", ErrNotSent, err)
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var rd io.Reader
	ctype := "application/json"
	if form, ok := body.(url.Values); ok {
		rd, ctype = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
	} else if raw, ok := body.(RawJSON); ok {
		rd = bytes.NewReader(raw)
	} else if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("encode request body: %w: %w", ErrNotSent, err)
		}
		rd = bytes.NewReader(b)
	}
	// written turns true once the request headers were handed to the
	// connection: from then on the server may have received (and applied) it.
	// A failure before that (dial, TLS, a context already done) means nothing
	// was sent. Callbacks can run on transport goroutines, hence the atomic.
	var written atomic.Bool
	tctx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteHeaders: func() { written.Store(true) },
		WroteRequest: func(httptrace.WroteRequestInfo) { written.Store(true) },
	})
	req, err := http.NewRequestWithContext(tctx, method, u.String(), rd)
	if err != nil {
		return 0, c.wrap(fmt.Errorf("%w: %w", ErrNotSent, err))
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := c.HC.Do(req)
	if err != nil {
		cause := unwrapURLErr(err)
		if ctx.Err() != nil {
			cause = ctx.Err()
		}
		if !written.Load() {
			return 0, c.wrap(fmt.Errorf("%s %s: %w: %w", method, path, ErrNotSent, cause))
		}
		return 0, c.wrap(fmt.Errorf("%s %s: %w", method, path, cause))
	}
	defer resp.Body.Close()
	max := c.MaxBody
	if max <= 0 {
		max = DefaultMaxBody
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return resp.StatusCode, c.wrap(fmt.Errorf("%s %s: read response: %w", method, path, err))
	}
	if int64(len(data)) > max {
		return resp.StatusCode, fmt.Errorf("%s %s: %w (%d bytes)", method, path, ErrTooLarge, max)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("%s %s: %w", method, path, &StatusError{Status: resp.StatusCode, Msg: trunc(c.Scrub(summarize(data)))})
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: decode response: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

func unwrapURLErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// summarize extracts the message of an error body (JSON message/error
// fields), complete: the caller redacts it and only then normalizes and
// truncates it (trunc), so no fragment of a secret survives the cut.
func summarize(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		if arr, ok := m["errors"].([]any); ok && len(arr) > 0 {
			if first, ok := arr[0].(map[string]any); ok {
				if s, ok := first["message"].(string); ok && s != "" {
					return s
				}
			}
		}
		for _, k := range []string{"message", "errorMessage", "error", "detail", "msg"} {
			if s, ok := m[k].(string); ok && s != "" {
				return s
			}
			if em, ok := m[k].(map[string]any); ok {
				if s, ok := em["message"].(string); ok && s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// trunc normalizes whitespace and cuts s to 200 bytes; apply it only to
// redacted text.
func trunc(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// BoolOption reads an optional bool config key. Booleans under `providers:`
// can arrive as the strings "true"/"false" (environment substitution), so those
// are accepted case-insensitively as well as real bools; anything else is an
// error.
func BoolOption(cfg map[string]any, key string) (bool, error) {
	v, ok := cfg[key]
	if !ok || v == nil {
		return false, nil
	}
	switch b := v.(type) {
	case bool:
		return b, nil
	case string:
		switch strings.ToLower(b) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("config field %q must be true or false", key)
}
