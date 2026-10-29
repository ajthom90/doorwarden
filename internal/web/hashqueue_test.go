package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockKDF makes h's key derivation wait on the returned channel (closed to
// release) and counts derivations in progress.
func blockKDF(h *Hasher) (release func(), running *atomic.Int32) {
	gate := make(chan struct{})
	running = &atomic.Int32{}
	orig := h.kdf
	h.kdf = func(pw, salt []byte, p Argon2Params) []byte {
		running.Add(1)
		defer running.Add(-1)
		<-gate
		return orig(pw, salt, p)
	}
	var once sync.Once
	return func() { once.Do(func() { close(gate) }) }, running
}

// The wait queue in front of the hashing slots is bounded: with every slot
// busy, at most maxHashWaiters callers wait and the rest get ErrHasherBusy
// at once; a waiter whose context ends leaves the queue; recheck runs after
// a slot is acquired and can veto the work.
func TestHasherQueueBounded(t *testing.T) {
	h := NewHasher(testParams, 2)
	enc, _ := h.Hash("correct horse battery")
	release, running := blockKDF(h)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var busy, cancelled, other atomic.Int32
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.VerifyContext(ctx, enc, "wrong", nil)
			switch {
			case errors.Is(err, ErrHasherBusy):
				busy.Add(1)
			case errors.Is(err, context.Canceled):
				cancelled.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for busy.Load() < 200-2-maxHashWaiters && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := busy.Load(); got != 200-2-maxHashWaiters {
		t.Fatalf("busy = %d, want %d", got, 200-2-maxHashWaiters)
	}
	if r := running.Load(); r != 2 {
		t.Fatalf("running = %d, want 2", r)
	}
	if w := h.waiting.Load(); w != maxHashWaiters {
		t.Fatalf("waiting = %d, want %d", w, maxHashWaiters)
	}
	cancel() // the waiters leave; the two in the KDF finish once released
	for h.waiting.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if w := h.waiting.Load(); w != 0 {
		t.Fatalf("waiters did not leave on cancel: %d", w)
	}
	release()
	wg.Wait()
	if cancelled.Load() != maxHashWaiters || other.Load() != 2 {
		t.Fatalf("cancelled=%d other=%d", cancelled.Load(), other.Load())
	}

	// recheck vetoes after acquisition, before any KDF work.
	h2 := NewHasher(testParams, 1)
	veto := errors.New("locked meanwhile")
	var kdfRan atomic.Bool
	orig := h2.kdf
	h2.kdf = func(pw, salt []byte, p Argon2Params) []byte { kdfRan.Store(true); return orig(pw, salt, p) }
	if _, err := h2.VerifyContext(context.Background(), enc, "x", func() error { return veto }); !errors.Is(err, veto) {
		t.Fatalf("recheck veto: %v", err)
	}
	if kdfRan.Load() {
		t.Fatal("KDF ran despite the recheck veto")
	}
	if ok, err := h2.VerifyContext(context.Background(), enc, "correct horse battery", nil); !ok || err != nil {
		t.Fatalf("verify = %v %v", ok, err)
	}
}

// A burst of 200 concurrent bad logins (distinct clients) while hashing is
// stalled: only the slots plus a bounded queue are held, the excess is
// refused at once with 503 + Retry-After, and requests whose client goes
// away leave the queue.
func TestLoginBurstBounded(t *testing.T) {
	e := newTestEnv(t)
	e.setupAdmin()
	e.srv.auth.sleep = func(context.Context, time.Duration) {} // limiter delays are not under test here
	release, running := blockKDF(e.srv.auth.hasher)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "http://dw.example.test/api/v1/auth/login",
				strings.NewReader(`{"username":"admin","password":"wrong-password-x"}`)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = fmt.Sprintf("198.51.100.%d:%d", i%250, 1000+i)
			w := httptest.NewRecorder()
			e.h.ServeHTTP(w, r)
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
			if (w.Code == http.StatusServiceUnavailable || w.Code == http.StatusTooManyRequests) && w.Header().Get("Retry-After") == "" {
				t.Error("refusal without Retry-After")
			}
		}()
	}
	// Two run, maxHashWaiters queue; the rest are refused at once: 503
	// (queue full) or 429 (the user's bucket ran dry; no attempt ever runs
	// uncharged).
	h := e.srv.auth.hasher
	deadline := time.Now().Add(10 * time.Second)
	refused := func() int {
		mu.Lock()
		defer mu.Unlock()
		return codes[http.StatusServiceUnavailable] + codes[http.StatusTooManyRequests]
	}
	for refused() < 200-2-maxHashWaiters && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := refused(); n != 200-2-maxHashWaiters {
		mu.Lock()
		t.Fatalf("refused = %d, want %d (codes %v)", n, 200-2-maxHashWaiters, codes)
	}
	if running.Load() != 2 || h.waiting.Load() != maxHashWaiters {
		t.Fatalf("running=%d waiting=%d", running.Load(), h.waiting.Load())
	}
	cancel()
	for h.waiting.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.waiting.Load() != 0 {
		t.Fatal("cancelled requests stayed queued")
	}
	release()
	wg.Wait()
}
