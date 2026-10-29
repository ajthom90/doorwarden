package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ajthom90/doorwarden/internal/model"
)

// Apex support must not change the fingerprint of a non-apex service (that
// would quarantine every stored approval); an apex service's differs.
func TestFingerprintApex(t *testing.T) {
	s := model.Service{Key: "static:site", Name: "site", Zone: "example.test",
		Backend: model.Backend{Scheme: "http", Host: "192.0.2.5", Port: 80}, Options: model.Options{Middlewares: []string{"b", "a"}}}
	b, _ := json.Marshal([]any{"v2", s.Key, s.Name, "", s.Zone, "http", "192.0.2.5", 80, false, false, []string{"b", "a"}})
	sum := sha256.Sum256(b)
	if got := Fingerprint(s); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("non-apex fingerprint changed: %s", got)
	}
	a := s
	a.Options.Apex = true
	if Fingerprint(a) == Fingerprint(s) {
		t.Fatal("apex not part of the fingerprint")
	}
}
