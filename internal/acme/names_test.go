package acme

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPlanSetsStrategies(t *testing.T) {
	sets, _, err := planSets("Example.Test.", []string{"*.example.test", "example.test"}, "", "")
	if err != nil || !reflect.DeepEqual(sets, [][]string{{"*.example.test", "example.test"}}) {
		t.Fatalf("wildcard default: %v %v", sets, err)
	}
	sets, _, err = planSets("example.test", []string{"b.example.test", "A.example.test", "b.example.test"}, StrategyPerHost, ChallengeHTTP01)
	if err != nil || !reflect.DeepEqual(sets, [][]string{{"a.example.test"}, {"b.example.test"}}) {
		t.Fatalf("per-host: %v %v", sets, err)
	}
	sets, _, err = planSets("example.test", []string{"b.example.test", "a.example.test"}, StrategySAN, "")
	if err != nil || !reflect.DeepEqual(sets, [][]string{{"a.example.test", "b.example.test"}}) {
		t.Fatalf("san: %v %v", sets, err)
	}
}

func TestPlanSetsSANChunksAt100(t *testing.T) {
	var names []string
	for i := range 250 {
		names = append(names, fmt.Sprintf("h%03d.example.test", i))
	}
	sets, _, err := planSets("example.test", names, StrategySAN, ChallengeDNS01)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 3 || len(sets[0]) != 100 || len(sets[1]) != 100 || len(sets[2]) != 50 {
		t.Fatalf("chunks %d", len(sets))
	}
}

func TestWildcardRequiresDNS01Validation(t *testing.T) {
	if _, _, err := planSets("example.test", nil, StrategyWildcard, ChallengeHTTP01); !errors.Is(err, ErrWildcardNeedsDNS01) {
		t.Fatalf("wildcard strategy with http-01: %v", err)
	}
	if _, _, err := planSets("example.test", []string{"*.example.test"}, StrategyPerHost, ChallengeHTTP01); !errors.Is(err, ErrWildcardNeedsDNS01) {
		t.Fatalf("wildcard name with http-01: %v", err)
	}
	if _, _, err := planSets("example.test", []string{"*.example.test"}, StrategyPerHost, ChallengeDNS01); err != nil {
		t.Fatalf("wildcard with dns-01: %v", err)
	}
}

func TestPlanSetsRejectsNamesOutsideZone(t *testing.T) {
	for _, n := range []string{"example.org", "badexample.test", "a.example.org"} {
		if _, _, err := planSets("example.test", []string{n}, StrategyPerHost, ""); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

// Invalid names are dropped (and reported), never ordered, and never stop
// the valid names of the same request.
func TestPlanSetsDropsInvalidNames(t *testing.T) {
	long := strings.Repeat("a", 64)
	bad := []string{
		"", "a..example.test", "a.*.example.test", "**.example.test", "*x.example.test",
		"nul\x00.example.test", "ctl\x07.example.test", "tab\t.example.test", "a b.example.test",
		"under_score.example.test", "a.example.test\n", "\na.example.test", " a.example.test",
		"-lead.example.test", "trail-.example.test", long + ".example.test",
		"xn--zz-.example.test", "a/b.example.test", "a@b.example.test", "a:1.example.test",
		strings.Repeat("abcdefghi.", 25) + "example.test", // > 253
		"bad\u00a0space.example.test",
	}
	sets, dropped, err := planSets("example.test", append([]string{"ok.example.test"}, bad...), StrategySAN, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sets, [][]string{{"ok.example.test"}}) {
		t.Fatalf("sets %q", sets)
	}
	if !reflect.DeepEqual(dropped, bad) {
		t.Fatalf("dropped %q\nwant    %q", dropped, bad)
	}
	if _, d, err := planSets("example.test", bad, StrategyPerHost, ""); err == nil || len(d) != len(bad) {
		t.Fatalf("all-invalid request: %v %d", err, len(d))
	}
}

func TestCanonNameValidForms(t *testing.T) {
	for in, want := range map[string]string{
		"A.Example.Test.":              "a.example.test",
		"*.example.test":               "*.example.test",
		"xn--bcher-kva.example.test":   "xn--bcher-kva.example.test",
		"b\u00fccher.example.test":     "xn--bcher-kva.example.test",
		"B\u00dcCHER.example.test":     "xn--bcher-kva.example.test",
		"a-b.c1.example.test":          "a-b.c1.example.test",
		strings.Repeat("a", 63) + ".t": strings.Repeat("a", 63) + ".t",
	} {
		got, err := canonName(in)
		if err != nil || got != want {
			t.Errorf("canonName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := canonName(strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)); err == nil {
		t.Error("254-char name accepted")
	}
	if _, _, err := planSets("bad_zone.test", []string{"a.bad_zone.test"}, StrategyPerHost, ""); err == nil {
		t.Error("invalid zone accepted")
	}
}

func TestCertIDStableAndSafe(t *testing.T) {
	a := certID("example.test", []string{"b.example.test", "a.example.test"})
	b := certID("example.test", []string{"a.example.test", "b.example.test"})
	if a != b || !validID(a) {
		t.Fatalf("%q %q", a, b)
	}
	if certID("example.test", []string{"a.example.test"}) == a {
		t.Fatal("different sets share an id")
	}
	for _, bad := range []string{"", "..", "a/b", "A", "a b"} {
		if validID(bad) {
			t.Errorf("%q valid", bad)
		}
	}
}
