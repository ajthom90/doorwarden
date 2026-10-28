package truenas

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ajthom90/doorwarden/internal/secrets"
)

func TestClientAuthFirstWithKey(t *testing.T) {
	f := newFake(t, `[]`)
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	got, err := c.Call(context.Background(), "core.ping")
	if err != nil || string(got) != `"pong"` {
		t.Fatalf("got %s, %v", got, err)
	}
	m := f.seen()
	if len(m) != 2 || m[0] != "auth.login_with_api_key" || m[1] != "core.ping" {
		t.Fatalf("methods = %v", m)
	}
}

func TestClientAuthFailure(t *testing.T) {
	f := newFake(t, `[]`)
	c := NewClient(f.url(), secrets.Secret("wrong"), false)
	defer c.Close()
	_, err := c.Call(context.Background(), "core.ping")
	if err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatal("key leaked")
	}
}

func TestClientRPCError(t *testing.T) {
	f := newFake(t, `[]`)
	f.rpcError = true
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	_, err := c.Call(context.Background(), "core.ping")
	var re *RPCError
	if !errors.As(err, &re) || re.Code != -32001 {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatalf("key leaked: %v", err)
	}
}

func TestClientReconnectsAfterDrop(t *testing.T) {
	f := newFake(t, `[]`)
	drop := true
	f.handler = func(c *websocket.Conn, req rpcReq, conn int) bool {
		if conn == 1 && req.Method == "core.ping" && drop {
			c.Close()
			return true
		}
		return false
	}
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	if _, err := c.Call(context.Background(), "system.version"); err != nil {
		t.Fatal(err)
	}
	got, err := c.Call(context.Background(), "core.ping")
	if err != nil || string(got) != `"pong"` {
		t.Fatalf("got %s, %v", got, err)
	}
	if f.conns != 2 {
		t.Fatalf("conns = %d", f.conns)
	}
}

func TestClientMatchesIDsAmidNoise(t *testing.T) {
	f := newFake(t, `[]`)
	f.handler = func(c *websocket.Conn, req rpcReq, _ int) bool {
		if req.Method != "core.ping" {
			return false
		}
		_ = c.WriteJSON(map[string]any{"jsonrpc": "2.0", "method": "collection_update", "params": map[string]any{}})
		_ = c.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": 99999, "result": "stale"})
		_ = c.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": "x", "result": "stale"})
		_ = c.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "right"})
		return true
	}
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	got, err := c.Call(context.Background(), "core.ping")
	if err != nil || string(got) != `"right"` {
		t.Fatalf("got %s, %v", got, err)
	}
}

func TestClientContextCancel(t *testing.T) {
	f := newFake(t, `[]`)
	f.handler = func(c *websocket.Conn, req rpcReq, _ int) bool {
		return req.Method == "core.ping" // never reply
	}
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Call(ctx, "core.ping")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("did not honor deadline")
	}
	// Client is still usable afterwards.
	f.mu.Lock()
	f.handler = nil
	f.mu.Unlock()
	if _, err := c.Call(context.Background(), "core.ping"); err != nil {
		t.Fatal(err)
	}
}

func TestClientParamsAlwaysArray(t *testing.T) {
	f := newFake(t, `[]`)
	var raw []byte
	f.handler = func(c *websocket.Conn, req rpcReq, _ int) bool {
		raw, _ = json.Marshal(req.Params)
		return false
	}
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	if _, err := c.Call(context.Background(), "core.ping"); err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("params = %s", raw)
	}
}

func TestClientConnectionRefused(t *testing.T) {
	f := newFake(t, `[]`)
	u := f.url()
	f.srv.Close()
	c := NewClient(u, secrets.Secret(testKey), false)
	defer c.Close()
	_, err := c.Call(context.Background(), "core.ping")
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Fatalf("err = %v", err)
	}
}
