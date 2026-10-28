package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes bounds how much of a response body is ever read.
const maxResponseBytes = 4 << 10

// permanentError marks a failure a retry cannot fix (HTTP 4xx except 429,
// invalid configuration, header injection).
type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }
func (p permanentError) Unwrap() error { return p.err }

func permanent(err error) error { return permanentError{err} }

// IsPermanent reports whether retrying err is pointless.
func IsPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

// newHTTPClient builds a client that ignores ambient proxy settings, has a
// hard timeout, and refuses redirects that leave the original scheme/host
// (so tokens and signatures never travel to another origin).
func newHTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			first := via[0].URL
			if len(via) > 3 {
				return errors.New("redirect refused: too many redirects")
			}
			if req.URL.Scheme != first.Scheme || !strings.EqualFold(req.URL.Host, first.Host) {
				return errors.New("redirect refused: target differs from the configured origin")
			}
			return nil
		},
	}
}

// doRequest sends req and maps the outcome to an error that never contains
// the URL, headers or response body. who names the sender (config name).
func doRequest(ctx context.Context, c *http.Client, req *http.Request, who string, redact ...string) error {
	resp, err := c.Do(req.WithContext(ctx))
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s: request failed: %w", who, scrub(err, redact...))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	e := fmt.Errorf("%s: server returned HTTP %d %s", who, resp.StatusCode, http.StatusText(resp.StatusCode))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusRequestTimeout {
		return permanent(e)
	}
	return e
}

type scrubbed struct {
	msg   string
	cause error
}

func (s scrubbed) Error() string { return s.msg }
func (s scrubbed) Unwrap() error { return s.cause }

// scrub returns err with every non-empty secret replaced by [redacted] in its
// message, keeping the chain for errors.Is.
func scrub(err error, secret ...string) error {
	msg := err.Error()
	for _, s := range secret {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	return scrubbed{msg: msg, cause: err}
}
