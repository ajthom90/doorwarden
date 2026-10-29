package acme

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/config"
)

// auditWordRe is the audit's list of credential words, independent of
// secretKeyRe/secretWordRe: a lego Additional variable whose name contains
// one of them (as a whole '_'-separated word for the short ones) must be
// treated as a credential.
var auditWordRe = regexp.MustCompile(`(?i)(token|secret|key|pass|hmac|credential|auth|private|passwd|bearer|cookie|session|signature|seed|(^|_)(otp|totp|pin|pwd)(_|$))`)

func TestAdditionalCredentialWordsAreCredentials(t *testing.T) {
	n := 0
	for _, p := range generatedCatalog {
		for _, v := range p.Additional {
			if !auditWordRe.MatchString(v) {
				continue
			}
			n++
			if !isCredentialSetting(p, strings.ToLower(v), v) {
				t.Errorf("%s: Additional variable %s looks like a credential but is not treated as one", p.Name, v)
			}
		}
	}
	if n == 0 {
		t.Fatal("audit matched nothing; catalog or word list broken")
	}
}

// NICMANAGER_API_OTP (a TOTP secret) is documented by lego under
// Additional; it must be registered for redaction.
func TestNicmanagerOTPRedacted(t *testing.T) {
	cfg := testConfig()
	cfg.Providers["nic"] = config.ProviderCfg{Type: "nicmanager", Extra: map[string]any{"api_otp": "JBSWY3DPEHPK3PXP"}}
	h := newHarness(t, cfg, nil)
	if got := h.m.red.redact("totp JBSWY3DPEHPK3PXP rejected"); strings.Contains(got, "JBSWY3DPEHPK3PXP") {
		t.Fatalf("OTP secret not redacted: %q", got)
	}
	cat, _ := LookupChallengeProvider("nicmanager")
	if !isCredentialSetting(cat, "api_otp", "NICMANAGER_API_OTP") {
		t.Fatal("NICMANAGER_API_OTP not a credential")
	}
}

// credentialOverrides forces a specific variable into the credential set
// even when its name does not look like one.
func TestCredentialOverrides(t *testing.T) {
	cat, _ := LookupChallengeProvider("edgeone")
	if isCredentialSetting(cat, "zones_mapping", "EDGEONE_ZONES_MAPPING") {
		t.Fatal("test premise: EDGEONE_ZONES_MAPPING is not a credential by name")
	}
	credentialOverrides["edgeone"] = append(credentialOverrides["edgeone"], "EDGEONE_ZONES_MAPPING")
	t.Cleanup(func() { delete(credentialOverrides, "edgeone") })
	if !isCredentialSetting(cat, "zones_mapping", "EDGEONE_ZONES_MAPPING") {
		t.Fatal("override not applied")
	}
	// Every override names a variable its provider documents.
	for typ, vars := range credentialOverrides {
		p, ok := LookupChallengeProvider(typ)
		if !ok {
			t.Errorf("override for unknown provider %s", typ)
			continue
		}
		for _, v := range vars {
			found := false
			for _, e := range p.EnvVars {
				found = found || e == v
			}
			if !found {
				t.Errorf("override %s.%s is not a documented variable", typ, v)
			}
		}
	}
}
