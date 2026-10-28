package acme

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestPlanSetsStrategies(t *testing.T) {
	sets, err := planSets("Example.Test.", []string{"*.example.test", "example.test"}, "", "")
	if err != nil || !reflect.DeepEqual(sets, [][]string{{"*.example.test", "example.test"}}) {
		t.Fatalf("wildcard default: %v %v", sets, err)
	}
	sets, err = planSets("example.test", []string{"b.example.test", "A.example.test", "b.example.test"}, StrategyPerHost, ChallengeHTTP01)
	if err != nil || !reflect.DeepEqual(sets, [][]string{{"a.example.test"}, {"b.example.test"}}) {
		t.Fatalf("per-host: %v %v", sets, err)
	}
	sets, err = planSets("example.test", []string{"b.example.test", "a.example.test"}, StrategySAN, "")
	if err != nil || !reflect.DeepEqual(sets, [][]string{{"a.example.test", "b.example.test"}}) {
		t.Fatalf("san: %v %v", sets, err)
	}
}

func TestPlanSetsSANChunksAt100(t *testing.T) {
	var names []string
	for i := range 250 {
		names = append(names, fmt.Sprintf("h%03d.example.test", i))
	}
	sets, err := planSets("example.test", names, StrategySAN, ChallengeDNS01)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 3 || len(sets[0]) != 100 || len(sets[1]) != 100 || len(sets[2]) != 50 {
		t.Fatalf("chunks %d", len(sets))
	}
}

func TestWildcardRequiresDNS01Validation(t *testing.T) {
	if _, err := planSets("example.test", nil, StrategyWildcard, ChallengeHTTP01); !errors.Is(err, ErrWildcardNeedsDNS01) {
		t.Fatalf("wildcard strategy with http-01: %v", err)
	}
	if _, err := planSets("example.test", []string{"*.example.test"}, StrategyPerHost, ChallengeHTTP01); !errors.Is(err, ErrWildcardNeedsDNS01) {
		t.Fatalf("wildcard name with http-01: %v", err)
	}
	if _, err := planSets("example.test", []string{"*.example.test"}, StrategyPerHost, ChallengeDNS01); err != nil {
		t.Fatalf("wildcard with dns-01: %v", err)
	}
}

func TestPlanSetsRejectsNamesOutsideZone(t *testing.T) {
	for _, n := range []string{"example.org", "badexample.test", "a.*.example.test", "**.example.test", "", "a..example.test"} {
		if _, err := planSets("example.test", []string{n}, StrategyPerHost, ""); err == nil {
			t.Errorf("%q accepted", n)
		}
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
