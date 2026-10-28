// Package truenas discovers TrueNAS SCALE apps through the middleware's
// JSON-RPC 2.0 websocket API (wss://<host>/api/current), using only the
// read-only app.query method.
package truenas

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ajthom90/doorwarden/internal/secrets"
)

// RPCError is a JSON-RPC error response from the server.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// errAuth marks a rejected API key; it is never retried.
var errAuth = errors.New("authentication failed")

// Client is a goroutine-safe JSON-RPC 2.0 websocket client. It authenticates
// with auth.login_with_api_key on every new connection and reconnects once
// when a live connection turns out to be dead.
type Client struct {
	wsURL    string
	key      secrets.Secret
	insecure bool

	mu     sync.Mutex
	conn   *websocket.Conn
	nextID int64
	urlErr error
}

// NewClient builds a Client. url may be http(s):// or ws(s)://; when it has no
// path, /api/current is used. Nothing is dialed until the first Call.
func NewClient(rawURL string, apiKey secrets.Secret, insecureTLS bool) *Client {
	c := &Client{key: apiKey, insecure: insecureTLS}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		c.urlErr = errors.New("invalid TrueNAS URL")
		return c
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		u.Scheme = "ws"
	default:
		c.urlErr = fmt.Errorf("unsupported TrueNAS URL scheme %q", u.Scheme)
		return c
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/api/current"
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	c.wsURL = u.String()
	return c
}

// Close closes the current connection, if any.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropLocked()
}

func (c *Client) dropLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// scrub removes the API key from text that may be surfaced in an error.
func (c *Client) scrub(s string) string {
	if k := c.key.Reveal(); k != "" {
		s = strings.ReplaceAll(s, k, "[redacted]")
	}
	return s
}

// Call invokes a JSON-RPC method and returns the raw result. Params are always
// sent as an array (the server rejects null/omitted params).
func (c *Client) Call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.urlErr != nil {
		return nil, c.urlErr
	}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		reused := c.conn != nil
		res, err := c.callLocked(ctx, method, params)
		if err == nil {
			return res, nil
		}
		var re *RPCError
		if errors.As(err, &re) || errors.Is(err, errAuth) {
			return nil, c.scrubErr(err)
		}
		// Transport failure: the connection state is unknown, drop it.
		_ = c.dropLocked()
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		if attempt == 0 && reused {
			continue // stale connection: reconnect, re-auth and retry once
		}
		return nil, c.scrubErr(err)
	}
}

func (c *Client) scrubErr(err error) error {
	var re *RPCError
	if errors.As(err, &re) {
		return &RPCError{Code: re.Code, Message: c.scrub(re.Message)}
	}
	return errors.New(c.scrub(err.Error()))
}

func (c *Client) callLocked(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	if c.conn == nil {
		if err := c.connectLocked(ctx); err != nil {
			return nil, err
		}
	}
	return c.roundTrip(ctx, method, params)
}

func (c *Client) connectLocked(ctx context.Context) error {
	d := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	if c.insecure {
		d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for self-signed NAS certs
	}
	conn, _, err := d.DialContext(ctx, c.wsURL, nil)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	c.conn = conn
	res, err := c.roundTrip(ctx, "auth.login_with_api_key", []any{c.key.Reveal()})
	if err != nil {
		var re *RPCError
		if errors.As(err, &re) {
			_ = c.dropLocked()
			return fmt.Errorf("%w: %v", errAuth, err)
		}
		_ = c.dropLocked()
		return err
	}
	var ok bool
	if json.Unmarshal(res, &ok) != nil || !ok {
		_ = c.dropLocked()
		return errAuth // server answers `false` for a rejected key
	}
	return nil
}

type rpcResponse struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
}

// roundTrip sends one request on c.conn and reads until the matching id.
func (c *Client) roundTrip(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	conn := c.conn
	c.nextID++
	id := c.nextID
	idRaw, _ := json.Marshal(id)

	// Unblock reads/writes when ctx ends.
	stop := context.AfterFunc(ctx, func() { past := time.Unix(1, 0); _ = conn.SetReadDeadline(past); _ = conn.SetWriteDeadline(past) })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
		_ = conn.SetWriteDeadline(dl)
	} else {
		_ = conn.SetReadDeadline(time.Time{})
		_ = conn.SetWriteDeadline(time.Time{})
	}

	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
	if err := conn.WriteJSON(req); err != nil {
		return nil, ctxOr(ctx, fmt.Errorf("write: %w", err))
	}
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return nil, ctxOr(ctx, fmt.Errorf("read: %w", err))
		}
		var r rpcResponse
		if json.Unmarshal(msg, &r) != nil || len(r.ID) == 0 || !bytes.Equal(bytes.TrimSpace(r.ID), idRaw) {
			continue // notification or response to something else
		}
		if r.Error != nil {
			return nil, r.Error
		}
		return r.Result, nil
	}
}

func ctxOr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return err
}
