package truenas

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
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
	f.handler = func(c *websocket.Conn, req rpcReq, conn int) bool {
		if conn == 1 && req.Method == "core.ping" {
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
	if n := f.connCount(); n != 2 {
		t.Fatalf("conns = %d", n)
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
	f.setHandler(nil)
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

func TestClientCancelRacesWithWriteAndRead(t *testing.T) {
	f := newFake(t, `[]`)
	f.handler = func(c *websocket.Conn, req rpcReq, _ int) bool {
		if req.Method == "slow" {
			time.Sleep(2 * time.Millisecond)
			_ = c.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "ok"})
			return true
		}
		return false
	}
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	big := strings.Repeat("x", 256<<10) // large write so cancel can land mid-write
	for i := 0; i < 200; i++ {
		// Cancel while a write/read is in flight.
		ctx, cancel := context.WithCancel(context.Background())
		go func(d time.Duration) { time.Sleep(d); cancel() }(time.Duration(i%7) * 300 * time.Microsecond)
		_, _ = c.Call(ctx, "slow", big)
		cancel()

		// A callback from a finished call fires around the next call's start.
		ctx2, cancel2 := context.WithCancel(context.Background())
		if _, err := c.Call(ctx2, "slow"); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		cancel2() // stale callback
		got, err := c.Call(context.Background(), "slow")
		if err != nil || string(got) != `"ok"` {
			t.Fatalf("iter %d after stale cancel: %s %v", i, got, err)
		}
	}
}

func TestClientDefaultTimeoutOnSilentServer(t *testing.T) {
	f := newFake(t, `[]`)
	f.handler = func(c *websocket.Conn, req rpcReq, _ int) bool { return req.Method == "core.ping" }
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	c.CallTimeout = 200 * time.Millisecond
	defer c.Close()
	start := time.Now()
	_, err := c.Call(context.Background(), "core.ping")
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not honored")
	}
	c.mu.Lock()
	dropped := c.conn == nil
	c.mu.Unlock()
	if !dropped {
		t.Fatal("connection must be dropped after timeout")
	}
	f.setHandler(nil)
	c.CallTimeout = 5 * time.Second
	if got, err := c.Call(context.Background(), "core.ping"); err != nil || string(got) != `"pong"` {
		t.Fatalf("%s %v", got, err)
	}
}

func TestClientNullIDErrorFailsFast(t *testing.T) {
	f := newFake(t, `[]`)
	f.handler = func(c *websocket.Conn, req rpcReq, _ int) bool {
		if req.Method != "core.ping" {
			return false
		}
		_ = c.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": nil,
			"error": map[string]any{"code": -32600, "message": "Invalid Request"}})
		return true
	}
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err := c.Call(ctx, "core.ping")
	var re *RPCError
	if !errors.As(err, &re) || re.Code != -32600 {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("not fast")
	}
}

func TestClientPreservesContextErrors(t *testing.T) {
	f := newFake(t, `[]`)
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Call(ctx, "core.ping"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := c.Call(ctx, "core.ping"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientTLSVerification(t *testing.T) {
	f := newFakeTLS(t, `[]`, true)
	strict := NewClient(f.url(), secrets.Secret(testKey), false)
	defer strict.Close()
	if _, err := strict.Call(context.Background(), "core.ping"); err == nil {
		t.Fatal("self-signed cert must be rejected when insecureTLS=false")
	}
	loose := NewClient(f.url(), secrets.Secret(testKey), true)
	defer loose.Close()
	if got, err := loose.Call(context.Background(), "core.ping"); err != nil || string(got) != `"pong"` {
		t.Fatalf("%s %v", got, err)
	}
}

func TestClientDoubleDropRetriesExactlyOnce(t *testing.T) {
	f := newFake(t, `[]`)
	f.handler = func(c *websocket.Conn, req rpcReq, _ int) bool {
		if req.Method == "core.ping" {
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
	if _, err := c.Call(context.Background(), "core.ping"); err == nil {
		t.Fatal("want error after two drops")
	}
	// conn 1 (initial), conn 2 (the single retry); no third attempt.
	if n := f.connCount(); n != 2 {
		t.Fatalf("conns = %d, want 2", n)
	}
}

func TestClientNoReconnectOnRPCOrAuthError(t *testing.T) {
	f := newFake(t, `[]`)
	f.rpcError = true
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	for i := 0; i < 2; i++ {
		if _, err := c.Call(context.Background(), "core.ping"); err == nil {
			t.Fatal("want rpc error")
		}
	}
	if n := f.connCount(); n != 1 {
		t.Fatalf("rpc error conns = %d, want 1", n)
	}

	g := newFake(t, `[]`)
	bad := NewClient(g.url(), secrets.Secret("nope"), false)
	defer bad.Close()
	if _, err := bad.Call(context.Background(), "core.ping"); err == nil {
		t.Fatal("want auth error")
	}
	if n := g.connCount(); n != 1 {
		t.Fatalf("auth failure conns = %d, want 1", n)
	}
}

func TestClientConcurrentCalls(t *testing.T) {
	f := newFake(t, `[]`)
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	defer c.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				got, err := c.Call(context.Background(), "core.ping")
				if err != nil || string(got) != `"pong"` {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent call failed: %v", err)
	}
	if n := f.connCount(); n != 1 {
		t.Fatalf("conns = %d, want 1", n)
	}
}

func TestClientKeepalivePings(t *testing.T) {
	f := newFake(t, `[]`)
	c := NewClient(f.url(), secrets.Secret(testKey), false)
	c.pingEvery = 20 * time.Millisecond
	defer c.Close()
	if _, err := c.Call(context.Background(), "core.ping"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for f.pingCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.pingCount() == 0 {
		t.Fatal("no keepalive ping received")
	}
}
