package config

import (
	"strings"
	"testing"
)

// An unknown records.provider type is rejected in every record mode, not
// only wildcard.
func TestRecordsProviderUnknownTypeEveryMode(t *testing.T) {
	for _, mode := range []string{"per-host", "wildcard", ""} {
		yml := strings.Replace(base, "cf: {type: cloudflare", "cf: {type: no-such-dns", 1)
		yml = strings.Replace(yml, "records: {provider: cf, mode: per-host}", "records: {provider: cf, mode: "+mode+"}", 1)
		yml = strings.Replace(yml, ", dns_provider: cf", ", dns_provider: chal", 1)
		yml = strings.Replace(yml, "uni: {type: unifi", "chal: {type: cloudflare, api_token: t}\n  uni: {type: unifi", 1)
		errs := mustLoad(t, yml).Validate(caps(true))
		if !hasErr(errs, `records.provider "cf" has unknown type "no-such-dns"`) {
			t.Errorf("mode %q: errs = %v", mode, errs)
		}
	}
	// mode off: the provider is not used for records.
	yml := strings.Replace(base, "cf: {type: cloudflare", "cf: {type: no-such-dns", 1)
	yml = strings.Replace(yml, "mode: per-host}", "mode: off}", 1)
	if hasErr(mustLoad(t, yml).Validate(caps(true)), "records.provider") {
		t.Error("mode off still checks records.provider")
	}
}
