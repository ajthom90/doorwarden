package web

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Shutdown with an open UI event stream ends the stream first, so the
// graceful HTTP stop finishes quickly instead of waiting for its timeout.
func TestShutdownWithOpenEventStreamIsQuick(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: e.h}
	go func() { _ = hs.Serve(ln) }()

	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/api/v1/events", nil)
	req.Host = "dw.example.test"
	req.AddCookie(c.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("events: %d", resp.StatusCode)
	}
	if line, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil || !strings.Contains(line, "doorwarden events") {
		t.Fatalf("stream not open: %q %v", line, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := e.srv.Shutdown(ctx, hs); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("shutdown took %v with an open event stream", d)
	}
}

// When the graceful stop times out, the remaining connections are
// force-closed rather than left running into the drain.
func TestShutdownForceClosesOnTimeout(t *testing.T) {
	e := newTestEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{})
	ended := make(chan struct{})
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
		close(ended)
	})}
	go func() { _ = hs.Serve(ln) }()
	go func() {
		if resp, err := http.Get("http://" + ln.Addr().String() + "/"); err == nil {
			<-release // hold the connection open
			resp.Body.Close()
		}
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := e.srv.Shutdown(ctx, hs); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown err = %v", err)
	}
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("the hung connection was not force-closed")
	}
}

// runAsync racing Close never panics (WaitGroup reuse) and refuses jobs
// once closing; run with -race -count=20.
func TestRunAsyncConcurrentWithClose(t *testing.T) {
	e := newTestEnv(t)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.srv.runAsync("k/"+string(rune('a'+i%26))+string(rune('a'+i/26)), "t", "job",
				func(context.Context) error { return nil })
		}()
	}
	e.srv.Close()
	wg.Wait()
	if err := e.srv.runAsync("after", "t", "job", func(context.Context) error {
		t.Error("job ran after Close")
		return nil
	}); !errors.Is(err, errClosing) {
		t.Fatalf("runAsync after Close = %v, want errClosing", err)
	}
}
