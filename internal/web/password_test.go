package web

import (
	"strings"
	"testing"
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
