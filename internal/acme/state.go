package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ajthom90/doorwarden/internal/store"
)

// Persistent ACME bookkeeping lives in the store's kv table as JSON under the
// "acme/" prefix (no migration needed):
//
//	acme/attempt/<cert id>              attemptState (backoff, rate-limit park)
//	acme/fv/<issuer>/<name>             failed validations (unix times, last hour)
//	acme/orders/<issuer>                orders placed (last 7 days; pending until resolved)
//	acme/park/<issuer>                  issuer account parked (rate limited) until
//	acme/account/<issuer>/key           base64 of the box-sealed account key PEM
//	acme/account/<issuer>/reg/<dirhash> registration resource (JSON, not secret)
//	acme/issuer/<issuer>/directory      explicit staging->production override
//	acme/notified/<id>/<threshold>/<na> expiry notification already sent
//
// Read-modify-write sequences hold Manager.stateMu.

type attemptState struct {
	Failures    int       `json:"failures"`
	NextAttempt time.Time `json:"next_attempt"`
	ParkedUntil time.Time `json:"parked_until"`
	LastError   string    `json:"last_error"`
}

// orderEvent is one order placed with an issuer's account. It is written
// with Pending set before the order starts and resolved (OK or failed)
// when it ends; an event still pending after a crash may have produced a
// certificate, so it counts toward every order guard.
type orderEvent struct {
	T       int64  `json:"t"`
	Set     string `json:"set"`
	OK      bool   `json:"ok"`
	Pending bool   `json:"pending,omitempty"`
}

// settingsBackend is the part of the store kv state goes through (tests
// substitute a failing one).
type settingsBackend interface {
	GetSetting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
}

var _ settingsBackend = (*store.Store)(nil)

type kvStore struct{ st settingsBackend }

func (k kvStore) getJSON(ctx context.Context, key string, v any) (bool, error) {
	s, ok, err := k.st.GetSetting(ctx, key)
	if err != nil || !ok || s == "" {
		return false, err
	}
	if err := json.Unmarshal([]byte(s), v); err != nil {
		return false, fmt.Errorf("acme: corrupt state %s: %w", key, err)
	}
	return true, nil
}

func (k kvStore) putJSON(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return k.st.SetSetting(ctx, key, string(b))
}

func attemptKey(id string) string         { return "acme/attempt/" + id }
func fvKey(issuer, name string) string    { return "acme/fv/" + issuer + "/" + name }
func ordersKey(issuer string) string      { return "acme/orders/" + issuer }
func accountParkKey(issuer string) string { return "acme/park/" + issuer }
func accountKeyKey(issuer string) string  { return "acme/account/" + issuer + "/key" }
func overrideKey(issuer string) string    { return overrideKeyPrefix + issuer + overrideKeySuffix }

const (
	overrideKeyPrefix = "acme/issuer/"
	overrideKeySuffix = "/directory"
)

func regKey(issuer, dirURL string) string {
	h := sha256.Sum256([]byte(dirURL))
	return "acme/account/" + issuer + "/reg/" + hex.EncodeToString(h[:8])
}
func notifiedKey(id string, threshold time.Duration, notAfter time.Time) string {
	return fmt.Sprintf("acme/notified/%s/%d/%d", id, int64(threshold/time.Hour), notAfter.Unix())
}
