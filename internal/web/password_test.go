package web

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var testParams = Argon2Params{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

func TestPasswordHashVerify(t *testing.T) {
	h := NewHasher(testParams, 1)
	enc, err := h.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("encoding = %s", enc)
	}
	if strings.Contains(enc, "correct horse") {
		t.Fatal("plaintext in hash")
	}
	if !h.Verify(enc, "correct horse battery") {
		t.Fatal("right password rejected")
	}
	if h.Verify(enc, "correct horse batterY") {
		t.Fatal("wrong password accepted")
	}
	enc2, _ := h.Hash("correct horse battery")
	if enc2 == enc {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1024,t=1,p=1$AAAA$AAAA", "$argon2id$v=19$m=999999999,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=1024,t=99,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "garbage$$$"} {
		if h.Verify(bad, "x") {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
}

func TestThrottleLockoutAndBackoff(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	th := newThrottle(func() time.Time { return now })
	for i := 0; i < throttleThreshold; i++ {
		if ok, _ := th.allowed("ip:a"); !ok {
			t.Fatalf("blocked after %d failures", i)
		}
		th.fail("ip:a")
	}
	ok, retry := th.allowed("ip:a")
	if ok || retry <= 0 {
		t.Fatalf("not locked: ok=%v retry=%v", ok, retry)
	}
	if ok, _ := th.allowed("ip:b"); !ok {
		t.Fatal("other key locked")
	}
	now = now.Add(retry + time.Second)
	if ok, _ := th.allowed("ip:a"); !ok {
		t.Fatal("still locked after the backoff")
	}
	th.fail("ip:a")
	_, retry2 := th.allowed("ip:a")
	if retry2 <= retry {
		t.Fatalf("backoff did not grow: %v then %v", retry, retry2)
	}
	now = now.Add(retry2 + time.Second)
	th.success("ip:a")
	if ok, _ := th.allowed("ip:a"); !ok {
		t.Fatal("success did not reset")
	}
}

// A table full of locked entries fails closed: a new address is refused,
// and the pinned administrator lock holds regardless of table pressure.
func TestThrottleSaturationFailsClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	th := newThrottle(func() time.Time { return now })
	th.maxKeys = 50
	th.pin("user:admin")
	for i := 0; i < throttleThreshold; i++ {
		th.fail("user:admin")
	}
	for k := 0; k < th.maxKeys; k++ {
		for i := 0; i < throttleThreshold; i++ {
			th.fail(fmt.Sprintf("ip:198.51.100.%d", k))
		}
	}
	// One more address: cannot be recorded, so it is refused.
	th.fail("ip:203.0.113.1")
	if ok, retry := th.allowed("ip:203.0.113.1"); ok || retry <= 0 {
		t.Fatal("unrecordable key allowed while the table is full of locks")
	}
	if ok, _ := th.allowed("user:admin"); ok {
		t.Fatal("pinned user lock lost under table pressure")
	}
	if _, ok := th.m["user:admin"]; ok || th.pinned["user:admin"] == nil {
		t.Fatal("pinned key in the evictable table")
	}
	// Once the locks end, new keys are allowed again; the user lock ran out
	// as well.
	now = now.Add(throttleMax + time.Second)
	if ok, _ := th.allowed("ip:203.0.113.1"); !ok {
		t.Fatal("still saturated after the locks ended")
	}
	if ok, _ := th.allowed("user:admin"); !ok {
		t.Fatal("user lock never ended")
	}
}
