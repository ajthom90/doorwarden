package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Many bad values (a large PUT /config body) are described in linear time
// and the message is bounded: the first problems by key path, then a count.
func TestDecodeErrorManyProblemsIsFastAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		n          int
		gen        func(*strings.Builder, int)
	}{
		{"bad ports", "static[0].port (line 15)", 32000, func(b *strings.Builder, n int) {
			b.WriteString("static:\n")
			for i := range n {
				fmt.Fprintf(b, "  - name: app%d\n    host: 192.0.2.5\n    port: x%d\n", i, i)
			}
		}},
		{"unknown settings keys", "settings.unknown_0 (line 13)", maxMappingKeys, func(b *strings.Builder, n int) {
			b.WriteString("settings:\n")
			for i := range n {
				fmt.Fprintf(b, "  unknown_%d: 1\n", i)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			b.WriteString(base)
			tc.gen(&b, tc.n)
			msg := parseErrFast(t, b.String())
			if len(msg) > maxDecodeMsg+200 {
				t.Fatalf("message is %d bytes", len(msg))
			}
			if !strings.Contains(msg, fmt.Sprintf("and %d more problems", tc.n-maxDecodeProblems)) {
				t.Fatalf("no remaining count: %.300s", msg)
			}
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("first problem not located (%s): %.300s", tc.want, msg)
			}
		})
	}
}

// A mapping too large to decode cheaply (yaml.v3's duplicate-key check is
// quadratic) is refused before decoding, by key path.
func TestHugeMappingIsRefusedFast(t *testing.T) {
	var b strings.Builder
	b.WriteString(base + "settings:\n")
	for i := range 32000 {
		fmt.Fprintf(&b, "  unknown_%d: 1\n", i)
	}
	msg := parseErrFast(t, b.String())
	if !strings.Contains(msg, "settings (line 13): a mapping with 32000 keys (at most 4096)") {
		t.Fatalf("error: %.300s", msg)
	}
}

func parseErrFast(t *testing.T, doc string) string {
	t.Helper()
	start := time.Now()
	_, err := Parse([]byte(doc), func(string) (string, bool) { return "", false })
	if d := time.Since(start); d > time.Second && !raceEnabled {
		t.Fatalf("took %v", d)
	}
	if err == nil {
		t.Fatal("no error")
	}
	return err.Error()
}

// A value with a newline in the part the decoder quotes (its first 7
// bytes) still gets its key path: the decoder's message spans lines.
func TestDecodeErrorMultilineValueKeepsPath(t *testing.T) {
	secret := "Qz7\nWkPjR9vLmTnXb4HsY"
	env := func(k string) (string, bool) { return secret, k == "SECRET" }
	yml := base + "static:\n  - name: app\n    host: 192.0.2.5\n    port: \"${SECRET}\"\n"
	_, err := Parse([]byte(yml), env)
	if err == nil {
		t.Fatal("no error")
	}
	msg := err.Error()
	assertNoSubstring(t, msg, "Qz7")
	assertNoSubstring(t, msg, "WkPj")
	if !strings.Contains(msg, "static[0].port") || !strings.Contains(msg, "invalid value") {
		t.Fatalf("error lost its location: %s", msg)
	}
}

func BenchmarkDecodeErrorManyBadPorts(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(base + "static:\n")
	for i := range 32000 {
		fmt.Fprintf(&sb, "  - name: app%d\n    host: 192.0.2.5\n    port: x%d\n", i, i)
	}
	raw := []byte(sb.String())
	for b.Loop() {
		_, _ = Parse(raw, func(string) (string, bool) { return "", false })
	}
}
