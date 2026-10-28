package truenas

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
)

const testKey = "SECRET-KEY-do-not-leak-0123456789"

type rpcReq struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

// fakeServer is a minimal TrueNAS JSON-RPC websocket server.
type fakeServer struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	methods  []string // methods received, in order, across connections
	conns    int
	handler  func(c *websocket.Conn, req rpcReq, conn int) (handled bool) // optional override, after auth
	authOK   bool
	apps     json.RawMessage
	rpcError bool
}

func newFake(t *testing.T, apps string) *fakeServer {
	f := &fakeServer{t: t, authOK: true, apps: json.RawMessage(apps)}
	up := websocket.Upgrader{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/current" {
			http.NotFound(w, r)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		f.mu.Lock()
		f.conns++
		n := f.conns
		f.mu.Unlock()
		for {
			var req rpcReq
			if err := c.ReadJSON(&req); err != nil {
				return
			}
			f.mu.Lock()
			f.methods = append(f.methods, req.Method)
			h := f.handler
			ok, rpcErr := f.authOK, f.rpcError
			apps := f.apps
			f.mu.Unlock()
			reply := func(result any) {
				b, _ := json.Marshal(result)
				_ = c.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": json.RawMessage(b)})
			}
			switch req.Method {
			case "auth.login_with_api_key":
				var k string
				if len(req.Params) == 1 {
					_ = json.Unmarshal(req.Params[0], &k)
				}
				reply(ok && k == testKey)
			default:
				if h != nil && h(c, req, n) {
					continue
				}
				if rpcErr {
					_ = c.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": req.ID,
						"error": map[string]any{"code": -32001, "message": "boom " + testKey}})
					continue
				}
				if req.Method == "app.query" {
					reply(apps)
				} else {
					reply("pong")
				}
			}
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) url() string { return f.srv.URL }

func (f *fakeServer) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.methods...)
}

func appsJSON(items ...string) string { return "[" + strings.Join(items, ",") + "]" }

func appJSON(name, state, portals string) string {
	return `{"name":"` + name + `","state":"` + state + `","portals":` + portals + `}`
}

func extractResult(t *testing.T, b []byte) string {
	t.Helper()
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(b, &env); err != nil || len(env.Result) == 0 {
		t.Fatalf("fixture: %v", err)
	}
	return string(env.Result)
}
