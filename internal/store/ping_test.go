package store

import (
	"context"
	"testing"
)

func TestPingOKAndLeavesNoTrace(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping on a fresh store: %v", err)
	}
	// The write probe is rolled back: nothing is left in kv.
	keys, err := s.ListSettingKeys(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Ping left kv keys behind: %v", keys)
	}
}

func TestPingFailsWhenClosed(t *testing.T) {
	s, _ := openTemp(t)
	s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("Ping on a closed store succeeded")
	}
}
