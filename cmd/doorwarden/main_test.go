package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMainVersionFlag(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--version"}, &out); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "doorwarden") {
		t.Fatalf("output %q does not contain doorwarden", out.String())
	}
}
