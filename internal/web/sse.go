package web

// SSE: GET /api/v1/events streams server-sent events to authenticated
// clients. Events carry identifiers and short messages only (never
// secrets): "cycle" after a reconcile cycle, "activity" for audit entries.
// The server's WriteTimeout is lifted for the stream (per-response write
// deadline cleared); a heartbeat comment goes out every heartbeat interval
// and re-checks the session, closing the stream once it is logged out or
// expired. Clients are capped (maxSSEClients); slow clients drop events.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	maxSSEClients = 32
	sseBuffer     = 32
)

var sseHeartbeat = 25 * time.Second

type sseEvent struct {
	name string
	data []byte
}

// Broker fans events out to SSE clients.
type Broker struct {
	mu      sync.Mutex
	clients map[chan sseEvent]struct{}
	closed  bool
	done    chan struct{}
}

// NewBroker returns an empty broker.
func NewBroker() *Broker {
	return &Broker{clients: map[chan sseEvent]struct{}{}, done: make(chan struct{})}
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

func (b *Broker) subscribe() (chan sseEvent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || len(b.clients) >= maxSSEClients {
		return nil, false
	}
	c := make(chan sseEvent, sseBuffer)
	b.clients[c] = struct{}{}
	return c, true
}

func (b *Broker) unsubscribe(c chan sseEvent) {
	b.mu.Lock()
	delete(b.clients, c)
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
	c, ok := s.events.subscribe()
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "too many event streams")
		return
	}
	defer s.events.unsubscribe(c)
	_ = rc.SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, ": doorwarden events\n\n"); err != nil {
		return
	}
	if rc.Flush() != nil {
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
			if !s.auth.stillValid(r.Context(), p) {
				return
			}
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		case e := <-c:
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.name, e.data); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}
