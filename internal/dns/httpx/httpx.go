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
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
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

// IsAuth reports 401/403.
func (e *StatusError) IsAuth() bool { return e.Status == 401 || e.Status == 403 }

// Client talks to one base URL.
type Client struct {
	Base    *url.URL
	HC      *http.Client
	MaxBody int64
	// Secrets are scrubbed from every error string this client returns.
	Secrets []string
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
	return &Client{Base: u, HC: hc, MaxBody: DefaultMaxBody}, nil
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

// Scrub replaces every configured secret in s.
func (c *Client) Scrub(s string) string {
	for _, sec := range c.Secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}

type scrubbed struct {
	msg string
	err error
}

func (e *scrubbed) Error() string { return e.msg }
func (e *scrubbed) Unwrap() error { return e.err }

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
// JSON-decoded from the response. A url.Values body is sent form-encoded. query may be nil. The response status is
// returned even on error when a response was received.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, hdr http.Header, body, out any) (int, error) {
	u := *c.Base
	u.Path = strings.TrimRight(u.Path, "/") + path
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var rd io.Reader
	ctype := "application/json"
	if form, ok := body.(url.Values); ok {
		rd, ctype = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
	} else if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return 0, c.wrap(err)
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
		if ctx.Err() != nil {
			return 0, c.wrap(fmt.Errorf("%s %s: %w", method, path, ctx.Err()))
		}
		return 0, c.wrap(fmt.Errorf("%s %s: %w", method, path, unwrapURLErr(err)))
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
		return resp.StatusCode, fmt.Errorf("%s %s: %w", method, path, &StatusError{Status: resp.StatusCode, Msg: c.Scrub(summarize(data))})
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

// summarize extracts a short message from an error body (JSON message/error
// fields, else a truncated text prefix).
func summarize(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		if arr, ok := m["errors"].([]any); ok && len(arr) > 0 {
			if first, ok := arr[0].(map[string]any); ok {
				if s, ok := first["message"].(string); ok && s != "" {
					return trunc(s)
				}
			}
		}
		for _, k := range []string{"message", "error", "detail", "msg"} {
			if s, ok := m[k].(string); ok && s != "" {
				return trunc(s)
			}
			if em, ok := m[k].(map[string]any); ok {
				if s, ok := em["message"].(string); ok && s != "" {
					return trunc(s)
				}
			}
		}
	}
	return ""
}

func trunc(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
