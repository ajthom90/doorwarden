package reconcile

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
)

// ---- the cap is spent on due rows only, and its window rotates ----

func dueKey(i int) string {
	return OwnedRowKey("dnsp", "example.test", fmt.Sprintf("s%02d.example.test", i), "A")
}

// repairedNames returns the names of the Repair actions in as.
func repairedNames(as []Action) map[string]bool {
	out := map[string]bool{}
	for _, a := range ofKind(as, DNSEnsure) {
		if a.Repair {
			out[a.Record.Name] = true
		}
	}
	return out
}

func TestPlanRepairDueOnly(t *testing.T) {
	// 7 missing of 20, s00..s02 waiting for their backoff: the 4 due rows are
	// all sent (the waiting ones take no slot); RepairDue true is due
	desired, obs := massCase(20, 7)
	obs.RepairDue = map[string]bool{dueKey(0): false, dueKey(1): false, dueKey(2): false, dueKey(3): true, dueKey(10): false}
	got := repairedNames(Plan(desired, obs, phCfg(), t0))
	if len(got) != 4 || got["s00.example.test"] || got["s01.example.test"] || got["s02.example.test"] {
		t.Fatalf("repairs %v", got)
	}
	// 9 missing of 20, 4 waiting: exactly the 5 due rows, whatever the
	// rotation
	desired, obs = massCase(20, 9)
	obs.RepairDue = map[string]bool{dueKey(1): false, dueKey(3): false, dueKey(5): false, dueKey(7): false}
	for m := 0; m < 30; m++ {
		got = repairedNames(Plan(desired, obs, phCfg(), t0.Add(time.Duration(m)*time.Minute)))
		want := []int{0, 2, 4, 6, 8}
		if len(got) != len(want) {
			t.Fatalf("minute %d: repairs %v", m, got)
		}
		for _, i := range want {
			if !got[fmt.Sprintf("s%02d.example.test", i)] {
				t.Fatalf("minute %d: repairs %v", m, got)
			}
		}
	}
}

// Rows waiting for their backoff still count toward the breaker.
func TestPlanRepairNotDueCountsTowardBreaker(t *testing.T) {
	desired, obs := massCase(10, 6)
	obs.RepairDue = map[string]bool{}
	for i := 0; i < 6; i++ {
		obs.RepairDue[dueKey(i)] = false
	}
	got := Plan(desired, obs, phCfg(), t0)
	sk := breakerSkips(got)
	if len(sk) != 1 || !strings.Contains(sk[0].Reason, "(6 of 10)") || len(repairs(got)) != 0 {
		t.Fatalf("plan %v", sums(got))
	}
	// 5 of 10 (not more than half), all waiting: nothing sent, no Skip
	desired, obs = massCase(10, 5)
	obs.RepairDue = map[string]bool{dueKey(0): false, dueKey(1): false, dueKey(2): false, dueKey(3): false, dueKey(4): false}
	got = Plan(desired, obs, phCfg(), t0)
	if len(breakerSkips(got)) != 0 || len(repairs(got)) != 0 {
		t.Fatalf("plan %v", sums(got))
	}
	// acknowledged: the waiting rows still take no slot
	desired, obs = massCase(10, 8)
	obs.RepairMassOK = map[string]time.Time{"dnsp/example.test": t0}
	obs.RepairDue = map[string]bool{dueKey(0): false, dueKey(1): false, dueKey(2): false, dueKey(3): false, dueKey(4): false}
	if got := repairedNames(Plan(desired, obs, phCfg(), t0)); len(got) != 3 || got["s00.example.test"] {
		t.Fatalf("repairs %v", got)
	}
}

// Rows that never get repaired (no backoff: say update-path re-creates that
// keep failing) cannot hold the cap: over successive cycles the window
// reaches every missing row, whatever the cycle interval.
func TestPlanRepairRotationReachesEveryRow(t *testing.T) {
	desired, obs := massCase(50, 20)
	for _, every := range []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, time.Hour} {
		seen := map[string]bool{}
		cycles := 0
		for ; cycles < 60 && len(seen) < 20; cycles++ {
			now := t0.Add(time.Duration(cycles) * every)
			got := repairedNames(Plan(desired, obs, phCfg(), now))
			if len(got) != RepairCapPerZone {
				t.Fatalf("every %s cycle %d: repairs %v", every, cycles, got)
			}
			for n := range got {
				seen[n] = true
			}
		}
		if len(seen) != 20 {
			t.Fatalf("every %s: %d of 20 rows reached in %d cycles", every, len(seen), cycles)
		}
		t.Logf("every %s: all 20 reached in %d cycles", every, cycles)
	}
	// the same minute gives the same window (deterministic), and the window
	// is contiguous in name order (wrapping)
	a := Plan(desired, obs, phCfg(), t0.Add(30*time.Second))
	b := Plan(desired, obs, phCfg(), t0)
	if !equalSums(a, b) {
		t.Fatal("not deterministic within a minute")
	}
	off := RepairRotation("dnsp/example.test", t0, 20)
	got := repairedNames(b)
	for i := 0; i < RepairCapPerZone; i++ {
		if n := fmt.Sprintf("s%02d.example.test", (off+i)%20); !got[n] {
			t.Fatalf("offset %d: %s not in %v", off, n, got)
		}
	}
	if RepairRotation("dnsp/example.test", t0, RepairCapPerZone) != 0 {
		t.Fatal("rotation when everything fits")
	}
}

func equalSums(a, b []Action) bool {
	return strings.Join(sums(a), "\n") == strings.Join(sums(b), "\n")
}

func TestGatherObservedReadsRepairDue(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := t0
	for i := 0; i < 6; i++ {
		if err := st.AddOwnedRecord(ctx, owned(dz, fmt.Sprintf("s%02d.example.test", i), "A", target, fmt.Sprintf("docker:s%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	set := func(i int, v string) {
		t.Helper()
		if err := st.SetSetting(ctx, repairKey(dzp, dz, fmt.Sprintf("s%02d.example.test", i), "A"), v); err != nil {
			t.Fatal(err)
		}
	}
	state := func(attempts int, next, last time.Time) string {
		return fmt.Sprintf(`{"attempts":%d,"next_at":%d,"last_at":%d}`, attempts, next.Unix(), last.Unix())
	}
	set(0, state(1, now.Add(-time.Second), now.Add(-time.Minute))) // due
	set(1, state(2, now.Add(time.Minute), now.Add(-time.Minute)))  // waiting
	set(2, state(3, now.Add(30*time.Hour), now.Add(-time.Minute))) // clock went back: due, for the executor to clamp
	set(3, state(4, now.Add(time.Minute), now.Add(-3*time.Hour)))  // stale: absent
	set(4, "garbage")                                              // absent
	set(5, state(0, now.Add(time.Hour), now))                      // no attempt: absent
	if err := st.SetSetting(ctx, repairKey(dzp, dz, "gone.example.test", "A"), state(1, now.Add(time.Hour), now)); err != nil {
		t.Fatal(err)
	}
	obs, errs := GatherObservedAt(ctx, map[string]dns.Provider{}, st, nil, 0, now)
	want := map[string]bool{dueKey(0): true, dueKey(1): false, dueKey(2): true}
	if len(errs) != 0 || fmt.Sprint(obs.RepairDue) != fmt.Sprint(want) {
		t.Fatalf("due %v errs %v", obs.RepairDue, errs)
	}
	// reading never writes the clamp (Gather is read-only)
	if v, _, _ := st.GetSetting(ctx, repairKey(dzp, dz, "s02.example.test", "A")); !strings.Contains(v, fmt.Sprint(now.Add(30*time.Hour).Unix())) {
		t.Fatalf("clamp persisted by Gather: %s", v)
	}
	// once the executor has persisted the clamp, it waits (at most 1h)
	set(2, state(3, now.Add(time.Hour), now))
	obs, _ = GatherObservedAt(ctx, map[string]dns.Provider{}, st, nil, 0, now)
	if due, ok := obs.RepairDue[dueKey(2)]; !ok || due {
		t.Fatalf("due %v", obs.RepairDue)
	}
	var o Observed
	obs.Fill(&o)
	if len(o.RepairDue) != len(obs.RepairDue) {
		t.Fatalf("not filled: %v", o.RepairDue)
	}
}
