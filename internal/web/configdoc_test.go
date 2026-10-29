package web

import (
	"strings"
	"testing"
)

const docYAML = `zones:
  - name: example.test
    target_ip: 192.0.2.10
providers:
  cf: {type: cloudflare, api_token: "s3cr3t-cf", zone_id: zid}
  env: {type: route53, secret_access_key: "${AWS_SECRET}", region: "${R:-us-east-1}", access_key_id: "${AK:-s3cr3t-default}"}
  ref: {type: pihole, password: "secret:pihole"}
issuers:
  le: {email: a@example.test, eab_kid: kid, eab_hmac: s3cr3t-hmac}
sources:
  truenas: {url: "https://192.0.2.20", api_key: s3cr3t-truenas}
notifications:
  webhooks:
    - {url: "https://hooks.example.test/s3cr3t-path", secret: s3cr3t-wh, headers: {Authorization: "Bearer s3cr3t-hdr"}}
  ntfy:
    - {server: "https://ntfy.example.test", topic: s3cr3t-topic, token: s3cr3t-ntfy}
  smtp:
    - {host: mail.example.test, username: u, password: s3cr3t-smtp, from: a@example.test, to: [b@example.test]}
middlewares:
  auth:
    basicAuth:
      users: ["admin:$apr1$s3cr3t-htpasswd"]
settings: {default_zone: example.test}
`

func TestMaskConfig(t *testing.T) {
	out, err := MaskConfig([]byte(docYAML))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "s3cr3t") {
		t.Fatalf("secret leaked:\n%s", s)
	}
	for _, want := range []string{"secret:pihole", "${AWS_SECRET}", "kid", "a@example.test", "mail.example.test", "192.0.2.10", "type: cloudflare", Masked} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	// A placeholder with a default may embed a secret: masked.
	if strings.Contains(s, "${AK:-") {
		t.Errorf("defaulted placeholder shown:\n%s", s)
	}
}

// A masked document PUT back unchanged keeps every secret.
func TestMergeMaskedRoundTrip(t *testing.T) {
	masked, err := MaskConfig([]byte(docYAML))
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(masked), "default_zone: example.test", "default_zone: example.test, dry_run: true", 1)
	merged, err := MergeMasked([]byte(edited), []byte(docYAML))
	if err != nil {
		t.Fatal(err)
	}
	m := string(merged)
	for _, want := range []string{"s3cr3t-cf", "s3cr3t-hmac", "s3cr3t-truenas", "s3cr3t-path", "s3cr3t-wh", "Bearer s3cr3t-hdr",
		"s3cr3t-topic", "s3cr3t-ntfy", "s3cr3t-smtp", "s3cr3t-htpasswd", "s3cr3t-default", "dry_run: true", "secret:pihole", "${AWS_SECRET}"} {
		if !strings.Contains(m, want) {
			t.Errorf("merged lost %q:\n%s", want, m)
		}
	}
	if strings.Contains(m, Masked) {
		t.Errorf("placeholder left:\n%s", m)
	}
	// A new value replaces the old one.
	changed := strings.Replace(string(masked), "api_token: "+quoteMasked(), `api_token: "new-token"`, 1)
	merged, err = MergeMasked([]byte(changed), []byte(docYAML))
	if err != nil || !strings.Contains(string(merged), "new-token") || strings.Contains(string(merged), "s3cr3t-cf") {
		t.Fatalf("replace: %v\n%s", err, merged)
	}
}

func quoteMasked() string { return `'` + Masked + `'` }

func TestMergeMaskedRejects(t *testing.T) {
	// A placeholder where the old document has no value.
	if _, err := MergeMasked([]byte("providers:\n  x: {type: cloudflare, api_token: '"+Masked+"'}\n"), []byte(docYAML)); err == nil {
		t.Fatal("placeholder without an old value accepted")
	}
	// A placeholder in a non-secret field.
	if _, err := MergeMasked([]byte("settings: {default_zone: '"+Masked+"'}\n"), []byte(docYAML)); err == nil {
		t.Fatal("placeholder in a plain field accepted")
	}
	if _, err := MergeMasked([]byte("a: [unclosed"), []byte(docYAML)); err == nil {
		t.Fatal("bad yaml accepted")
	}
}

func TestScrubConfigError(t *testing.T) {
	got := scrubConfigError("parse: cannot unmarshal !!str `s3cr3t-x` into int; s3cr3t-cf is wrong", []string{"s3cr3t-cf"})
	if strings.Contains(got, "s3cr3t") {
		t.Fatalf("scrub: %s", got)
	}
}
