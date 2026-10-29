package acme

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
)

// A provider's user and password are also redacted in the form an HTTP
// Basic header carries them (base64 of "user:password"), header name or not.
func TestBasicCredentialPairRedacted(t *testing.T) {
	cfg := testConfig()
	cfg.Providers["ad"] = config.ProviderCfg{Type: "autodns", Extra: map[string]any{"autodns_api_user": "dw-user", "autodns_api_password": "pw-secret-1"}}
	h := newHarness(t, cfg, nil)
	pair := "dw-user:pw-secret-1"
	for _, enc := range []string{base64.StdEncoding.EncodeToString([]byte(pair)), base64.RawURLEncoding.EncodeToString([]byte(pair))} {
		if got := h.m.red.redact("request had credentials " + enc + " (rejected)"); strings.Contains(got, enc) {
			t.Errorf("basic pair %s leaked: %q", enc, got)
		}
	}
}

// Basic credentials after the scheme word are scrubbed even when unknown.
func TestBasicSchemeScrubbed(t *testing.T) {
	r := newRedactor()
	got := r.redact("upstream said: Basic dW5rbm93bjpjcmVkZW50aWFscw== was rejected")
	if want := "upstream said: Basic [redacted] was rejected"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A FIFO given as a credential file neither hangs nor is read.
func TestSecretFileFIFODoesNotHang(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := secretFileValues(p); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular") {
			t.Fatalf("want not-a-regular-file error, got %v", err)
		}
	case <-time.After(3 * time.Second):
		// Unblock the open so the goroutine ends.
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			f.Close()
		}
		t.Fatal("secretFileValues hung on a FIFO")
	}
}
