package web

// SSE: GET /api/v1/events streams server-sent events to authenticated
// clients. Events carry identifiers and short messages only (never
// secrets): "cycle" after a reconcile cycle, "activity" for audit entries.
// The server's WriteTimeout would end the stream, so instead every write
// and flush gets its own fresh deadline (sseWriteTimeout): a client that
// stops reading is dropped once the socket buffers fill, rather than
// pinning the handler. A heartbeat comment goes out every heartbeat
// interval and re-validates the principal: a session must still exist and
// be unexpired; a trusted-header stream ends after sseHeaderMaxAge so the
// forward-auth proxy re-checks on reconnect. Clients are capped in all
// (maxSSEClients) and per principal (maxSSEPerPrincipal); slow clients
// drop events.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	maxSSEClients      = 32
	maxSSEPerPrincipal = 4
	sseBuffer          = 32
	sseHeaderMaxAge    = time.Hour
)

var (
	sseHeartbeat    = 25 * time.Second
	sseWriteTimeout = 10 * time.Second
)

type sseEvent struct {
	name string
	data []byte
}

// Broker fans events out to SSE clients.
type Broker struct {
	mu      sync.Mutex
	clients map[chan sseEvent]string // -> principal key
	per     map[string]int
	closed  bool
	done    chan struct{}
}

// NewBroker returns an empty broker.
func NewBroker() *Broker {
	return &Broker{clients: map[chan sseEvent]string{}, per: map[string]int{}, done: make(chan struct{})}
}

// Publish sends an event to every client (dropped for clients that are
// behind). v is JSON-encoded.
func (b *Broker) Publish(name string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for c := range b.clients {
		select {
		case c <- sseEvent{name, data}:
		default:
		}
	}
}

// subscribe adds a client for principal key; status is the refusal code
// (503 when full overall, 429 when the principal has its maximum).
func (b *Broker) subscribe(key string) (chan sseEvent, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || len(b.clients) >= maxSSEClients {
		return nil, http.StatusServiceUnavailable
	}
	if b.per[key] >= maxSSEPerPrincipal {
		return nil, http.StatusTooManyRequests
	}
	c := make(chan sseEvent, sseBuffer)
	b.clients[c] = key
	b.per[key]++
	return c, 0
}

func (b *Broker) unsubscribe(c chan sseEvent) {
	b.mu.Lock()
	if key, ok := b.clients[c]; ok {
		delete(b.clients, c)
		if b.per[key]--; b.per[key] <= 0 {
			delete(b.per, key)
		}
	}
	b.mu.Unlock()
}

// Close ends every stream.
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		close(b.done)
	}
}

func (b *Broker) clientCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.clients)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	rc := http.NewResponseController(w)
	c, refused := s.events.subscribe(p.Actor())
	if refused != 0 {
		writeErr(w, refused, "too many event streams")
		return
	}
	defer s.events.unsubscribe(c)
	started := s.now()
	// The request has no body; the server's read timeout must not end
	// the stream.
	_ = rc.SetReadDeadline(time.Time{})
	// send writes one chunk with a fresh, finite write deadline.
	send := func(format string, a ...any) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		if _, err := fmt.Fprintf(w, format, a...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
	w.WriteHeader(http.StatusOK)
	if !send(": doorwarden events\n\n") {
		return
	}
	t := time.NewTicker(sseHeartbeat)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.events.done:
			return
		case <-t.C:
			if !s.auth.stillValid(r.Context(), p, started) {
				return
			}
			if !send(": ping\n\n") {
				return
			}
		case e := <-c:
			if !send("event: %s\ndata: %s\n\n", e.name, e.data) {
				return
			}
		}
	}
}
