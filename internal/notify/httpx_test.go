package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestScrubRemovesSecretsKeepsChain(t *testing.T) {
	base := errors.New("dial tcp: lookup hooks.example.test/SECRET123: boom SECRET123")
	err := scrub(base, "SECRET123", "")
	if strings.Contains(err.Error(), "SECRET123") || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, base) {
		t.Fatal("raw cause must not be reachable")
	}
	if err := scrub(context.DeadlineExceeded, "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline chain lost")
	}
}
