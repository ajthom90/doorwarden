package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizedSeverity(t *testing.T) {
	cases := map[Severity]Severity{
		"WARNING": Warning, " Critical\n": Critical, "Info": Info, "": Info, "bogus": Info, "CRITICAL": Critical,
	}
	for in, want := range cases {
		e := Event{Severity: in}.normalized()
		if e.Severity != want || e.Severity.Rank() != want.Rank() {
			t.Errorf("%q -> %q, want %q", in, e.Severity, want)
		}
	}
	if (Event{Severity: "CRITICAL"}).normalized().Severity.Rank() != 2 {
		t.Fatal("rank")
	}
}

func TestTruncateNeverExceedsBound(t *testing.T) {
	for _, in := range []string{strings.Repeat("a", 300), strings.Repeat("é", 300), strings.Repeat("日", 100)} {
		for _, n := range []int{10, 64, 200} {
			out := truncate(in, n)
			if len(out) > n || !utf8.ValidString(out) {
				t.Fatalf("n=%d len=%d valid=%v", n, len(out), utf8.ValidString(out))
			}
		}
	}
	if truncate("short", 10) != "short" {
		t.Fatal("short altered")
	}
	e := Event{Subject: strings.Repeat("x", 1000), Message: strings.Repeat("y", 10000)}.normalized()
	if len(e.Subject) > MaxSubjectBytes || len(e.Message) > MaxMessageBytes {
		t.Fatalf("%d %d", len(e.Subject), len(e.Message))
	}
}

func TestFieldKeyCollisionAfterTruncation(t *testing.T) {
	long := strings.Repeat("k", MaxFieldKeyBytes+10)
	f := map[string]string{long + "A": "1", long + "B": "2", long + "C": "3"}
	e := Event{Fields: f}.normalized()
	if len(e.Fields) != 3 {
		t.Fatalf("fields silently merged: %v", e.Fields)
	}
	seen := map[string]bool{}
	for k, v := range e.Fields {
		if len(k) > MaxFieldKeyBytes {
			t.Fatalf("key too long: %d", len(k))
		}
		seen[v] = true
	}
	if len(seen) != 3 {
		t.Fatal("values lost")
	}
}
