package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// maxResponseBytes bounds how much of a response body is ever read.
const maxResponseBytes = 4 << 10

// Error kinds. Errors returned by senders expose only these sentinels (plus
// context.DeadlineExceeded/Canceled) through Unwrap, never raw transport or
// server text.
var (
	ErrPermanent = errors.New("permanent failure")
	ErrTemporary = errors.New("temporary failure")
)

// sanitizedError carries an already-redacted message and a kind sentinel.
type sanitizedError struct {
	msg  string
	kind error
}

func (s sanitizedError) Error() string { return s.msg }
func (s sanitizedError) Unwrap() error { return s.kind }

// permanent marks a failure a retry cannot fix (HTTP 4xx except 429/408,
// redirects, invalid configuration, header injection). The message of err is
// kept; callers pass only already-sanitized errors.
func permanent(err error) error {
	return sanitizedError{msg: err.Error(), kind: ErrPermanent}
}

// IsPermanent reports whether retrying err is pointless.
func IsPermanent(err error) bool { return errors.Is(err, ErrPermanent) }

// httpDoer sends single requests without Client redirect handling (which
// would parse and echo Location headers) and with a hard timeout. It ignores
// ambient proxy settings.
type httpDoer struct {
	rt      http.RoundTripper
	timeout time.Duration
}

func newHTTPClient(timeout time.Duration) *httpDoer {
	return &httpDoer{timeout: timeout, rt: &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
	}}
}

// doRequest sends req and maps the outcome to an error that never contains
// the URL, headers, Location or response body. who names the sender.
// Redirects are never followed: a 3xx is a delivery failure.
func doRequest(ctx context.Context, c *httpDoer, req *http.Request, who string, redact ...string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rt.RoundTrip(req.WithContext(ctx))
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s: request failed: %w", who, scrub(err, redact...))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		return nil
	case code >= 300 && code < 400:
		return permanent(fmt.Errorf("%s: unexpected redirect (status %d); redirects are not followed", who, code))
	}
	e := fmt.Errorf("%s: server returned HTTP %d %s", who, code, http.StatusText(code))
	if code >= 400 && code < 500 && code != http.StatusTooManyRequests && code != http.StatusRequestTimeout {
		return permanent(e)
	}
	return sanitizedError{msg: e.Error(), kind: ErrTemporary}
}

var queryPairRe = regexp.MustCompile(`([?&][^=&\s"]+=)[^&\s"]+`)

const minScrubLen = 4

// scrub returns a sanitized error: every secret (longest first, >= 4 bytes)
// and every URL query value is replaced by [redacted]. The result unwraps
// only to a kind sentinel (ErrPermanent, ErrTemporary, or a context error),
// never to the raw cause.
func scrub(err error, secret ...string) error {
	msg := err.Error()
	list := make([]string, 0, len(secret))
	for _, s := range secret {
		if len(s) >= minScrubLen {
			list = append(list, s)
		}
	}
	sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
	for _, s := range list {
		msg = strings.ReplaceAll(msg, s, "[redacted]")
	}
	msg = queryPairRe.ReplaceAllString(msg, "${1}[redacted]")
	kind := ErrTemporary
	switch {
	case errors.Is(err, ErrPermanent):
		kind = ErrPermanent
	case errors.Is(err, context.DeadlineExceeded):
		kind = context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		kind = context.Canceled
	}
	return sanitizedError{msg: msg, kind: kind}
}

// urlSecrets lists the substrings of raw that must never appear in errors:
// the full string, path, query, each query key=value and value, userinfo
// (and its password) and fragment.
func urlSecrets(raw string) []string {
	out := []string{raw}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	if p := u.EscapedPath(); len(p) > 1 {
		out = append(out, p, u.Path)
	}
	if u.RawQuery != "" {
		out = append(out, u.RawQuery)
		for _, pair := range strings.Split(u.RawQuery, "&") {
			out = append(out, pair)
			if _, v, ok := strings.Cut(pair, "="); ok {
				out = append(out, v)
			}
		}
	}
	if u.User != nil {
		out = append(out, u.User.String(), u.User.Username())
		if pw, ok := u.User.Password(); ok {
			out = append(out, pw)
		}
	}
	if u.Fragment != "" {
		out = append(out, u.Fragment)
	}
	return out
}
