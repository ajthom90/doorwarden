package web

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
)

func newClientIPAuth(t *testing.T, w config.Web, log *slog.Logger) *auth {
	t.Helper()
	old := inContainer
	inContainer = func() bool { return false }
	t.Cleanup(func() { inContainer = old })
	e := newTestEnv(t)
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	a, err := newAuth(context.Background(), e.st, w, NewHasher(testParams, 1), time.Now, log, "tok")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// The throttle/audit client address is the rightmost X-Forwarded-For entry
// that is not a trusted proxy, and only when the TCP peer is one of
// web.trusted_proxies; leftmost (client-supplied) entries never count, and
// trusted_header.proxies alone does not enable it.
func TestClientIPRightmostUntrusted(t *testing.T) {
	a := newClientIPAuth(t, config.Web{
		TrustedProxies: []string{"192.0.2.0/24"},
		TrustedHeader:  config.TrustedHeader{Proxies: []string{"203.0.113.250/32"}, UserHeader: "Remote-User", Role: "viewer"},
	}, nil)
	cases := []struct {
		peer string
		xff  []string
		want string
	}{
		{"192.0.2.10:1", nil, "192.0.2.10"},
		{"192.0.2.10:1", []string{"198.51.100.7"}, "198.51.100.7"},
		// A spoofed leftmost entry is ignored: Traefik appended the real one.
		{"192.0.2.10:1", []string{"203.0.113.9, 198.51.100.7"}, "198.51.100.7"},
		// Trusted hops are skipped from the right.
		{"192.0.2.10:1", []string{"198.51.100.7, 192.0.2.11"}, "198.51.100.7"},
		{"192.0.2.10:1", []string{"203.0.113.9", "198.51.100.8, 192.0.2.12"}, "198.51.100.8"},
		// Junk to the left of the real hop never matters.
		{"192.0.2.10:1", []string{"junk, 198.51.100.7"}, "198.51.100.7"},
		// Every entry trusted: the leftmost of them.
		{"192.0.2.10:1", []string{"192.0.2.13, 192.0.2.11"}, "192.0.2.13"},
		// Entries with a port or brackets are addresses too.
		{"192.0.2.10:1", []string{"198.51.100.7:80"}, "198.51.100.7"},
		{"192.0.2.10:1", []string{"[2001:db8::7]"}, "2001:db8::7"},
		{"192.0.2.10:1", []string{"[2001:db8::7]:443"}, "2001:db8::7"},
		{"192.0.2.10:1", []string{"198.51.100.7:80, 192.0.2.11:1234"}, "198.51.100.7"},
		{"192.0.2.10:1", []string{"198.51.100.7, [::ffff:192.0.2.11]:9"}, "198.51.100.7"},
		// The rightmost entry unparseable: fall back to the peer.
		{"192.0.2.10:1", []string{"198.51.100.7, junk"}, "192.0.2.10"},
		// Peer not a trusted proxy: XFF ignored.
		{"198.51.100.50:1", []string{"198.51.100.7"}, "198.51.100.50"},
		// trusted_header proxy is not a trusted_proxies member.
		{"203.0.113.250:1", []string{"198.51.100.7"}, "203.0.113.250"},
		{"[::ffff:192.0.2.10]:1", []string{"198.51.100.9"}, "198.51.100.9"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := a.clientIP(r).String(); got != c.want {
			t.Errorf("peer %s xff %q: client = %s, want %s", c.peer, c.xff, got, c.want)
		}
	}
}

// With trusted_proxies unset, X-Forwarded-For is ignored, and a warning is
// logged once when it shows up (a reverse proxy in front) or when every
// request comes from one peer.
func TestClientIPUnsetWarns(t *testing.T) {
	var buf syncBuf
	a := newClientIPAuth(t, config.Web{TrustedHeader: config.TrustedHeader{UserHeader: "Remote-User", Role: "viewer"}},
		slog.New(slog.NewTextHandler(&buf, nil)))
	for range 3 {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.10:1"
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		if got := a.clientIP(r).String(); got != "192.0.2.10" {
			t.Fatalf("XFF believed without trusted_proxies: %s", got)
		}
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Fatalf("XFF warning count = %d:\n%s", n, buf.String())
	}

	var buf2 syncBuf
	b := newClientIPAuth(t, config.Web{TrustedHeader: config.TrustedHeader{UserHeader: "Remote-User", Role: "viewer"}},
		slog.New(slog.NewTextHandler(&buf2, nil)))
	for range singlePeerSample + 5 {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.10:1"
		b.clientIP(r)
	}
	if n := strings.Count(buf2.String(), "level=WARN"); n != 1 {
		t.Fatalf("single-peer warning count = %d:\n%s", n, buf2.String())
	}
}
