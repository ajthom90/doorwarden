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

func mergeErr(t *testing.T, newDoc, oldDoc string) error {
	t.Helper()
	_, err := MergeMasked([]byte(newDoc), []byte(oldDoc))
	return err
}

// E1: a masked secret never follows a destination change: changing the
// url/host/server/type next to (or above) it, or moving it to a list
// entry with a different identity, requires re-entering it.
func TestMergeMaskedDestinationChange(t *testing.T) {
	old := `notifications:
  ntfy:
    - {server: "https://ntfy.example.test", topic: t1, token: s3cr3t-ntfy}
  smtp:
    - {host: mail.example.test, username: u, password: s3cr3t-smtp, from: a@example.test, to: [b@example.test]}
sources:
  truenas: {url: "https://192.0.2.20", api_key: s3cr3t-truenas}
providers:
  cf: {type: cloudflare, api_token: s3cr3t-cf}
`
	cases := map[string]string{
		"smtp host": strings.Replace(old, "password: s3cr3t-smtp", "password: '<masked>'", 1),
		"ntfy server": strings.Replace(strings.Replace(old, "token: s3cr3t-ntfy", "token: '<masked>'", 1),
			"https://ntfy.example.test", "https://evil.example.test", 1),
		"truenas url": strings.Replace(strings.Replace(old, "api_key: s3cr3t-truenas", "api_key: '<masked>'", 1),
			"https://192.0.2.20", "https://198.51.100.66", 1),
		"provider type": strings.Replace(strings.Replace(old, "api_token: s3cr3t-cf", "api_token: '<masked>'", 1),
			"type: cloudflare", "type: pihole", 1),
	}
	cases["smtp host"] = strings.Replace(cases["smtp host"], "host: mail.example.test", "host: mail.evil.example.test", 1)
	for name, doc := range cases {
		err := mergeErr(t, doc, old)
		if err == nil || !strings.Contains(err.Error(), "re-enter") {
			t.Errorf("%s: masked secret carried across a destination change: %v", name, err)
		}
	}
	// Unchanged destination: kept.
	same := strings.Replace(old, "password: s3cr3t-smtp", "password: '<masked>'", 1)
	out, err := MergeMasked([]byte(same), []byte(old))
	if err != nil || !strings.Contains(string(out), "s3cr3t-smtp") {
		t.Fatalf("unchanged destination: %v\n%s", err, out)
	}
}

// List entries are matched by identity, not index: reordering keeps each
// secret with its own entry; inserting an entry before another does not
// hand it the other's secret; ambiguous identities are refused.
func TestMergeMaskedListIdentity(t *testing.T) {
	old := `notifications:
  ntfy:
    - {server: "https://a.example.test", topic: ta, token: s3cr3t-a}
    - {server: "https://b.example.test", topic: tb, token: s3cr3t-b}
`
	swapped := `notifications:
  ntfy:
    - {server: "https://b.example.test", topic: tb, token: '<masked>'}
    - {server: "https://a.example.test", topic: ta, token: '<masked>'}
`
	out, err := MergeMasked([]byte(swapped), []byte(old))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Index(s, "s3cr3t-b") > strings.Index(s, "s3cr3t-a") {
		t.Fatalf("reorder moved secrets between entries:\n%s", s)
	}
	inserted := `notifications:
  ntfy:
    - {server: "https://evil.example.test", topic: ta, token: '<masked>'}
    - {server: "https://a.example.test", topic: ta, token: '<masked>'}
    - {server: "https://b.example.test", topic: tb, token: '<masked>'}
`
	if err := mergeErr(t, inserted, old); err == nil || !strings.Contains(err.Error(), "re-enter") {
		t.Fatalf("inserted entry inherited a secret: %v", err)
	}
	ambOld := `notifications:
  ntfy:
    - {server: "https://a.example.test", topic: t, token: s3cr3t-1}
    - {server: "https://a.example.test", topic: t, token: s3cr3t-2, priority: 3}
`
	ambNew := `notifications:
  ntfy:
    - {server: "https://a.example.test", topic: t, token: '<masked>', priority: 3}
    - {server: "https://a.example.test", topic: t, token: '<masked>'}
`
	if err := mergeErr(t, ambNew, ambOld); err == nil || !strings.Contains(err.Error(), "re-enter") {
		t.Fatalf("ambiguous identity accepted: %v", err)
	}
	// Scalar lists of secrets (basicAuth users) only keep values when
	// the list keeps its length.
	uOld := "middlewares:\n  a:\n    basicAuth:\n      users: [\"u1:s3cr3t-1\", \"u2:s3cr3t-2\"]\n"
	uNew := "middlewares:\n  a:\n    basicAuth:\n      users: ['<masked>']\n"
	if err := mergeErr(t, uNew, uOld); err == nil {
		t.Fatal("shrunk secret list kept a value by index")
	}
}

// E2: ${VAR} is accepted only in secret-bearing fields; a new or changed
// ${VAR} in a free-text field (it would be echoed via the API) is refused,
// while one already in the stored file may stay.
func TestMergeRejectsEnvRefInPlainFields(t *testing.T) {
	old := "zones:\n  - name: example.test\n    target_ip: 192.0.2.10\nproviders:\n  cf: {type: cloudflare, api_token: \"${CF_TOKEN}\", zone_id: \"${ZID}\"}\n"
	for _, doc := range []string{
		"zones:\n  - name: \"${HOME}\"\n    target_ip: 192.0.2.10\nproviders:\n  cf: {type: cloudflare, api_token: \"${CF_TOKEN}\", zone_id: \"${ZID}\"}\n",
		old + "settings: {default_zone: \"${OTHER}\"}\n",
		"zones:\n  - name: example.test\n    target_ip: \"x${AWS_SECRET}\"\nproviders:\n  cf: {type: cloudflare, api_token: \"${CF_TOKEN}\", zone_id: \"${ZID}\"}\n",
	} {
		if err := mergeErr(t, doc, old); err == nil || !strings.Contains(err.Error(), "${") {
			t.Errorf("env reference in a plain field accepted: %v\n%s", err, doc)
		}
	}
	// Unchanged plain-field reference and a new secret-field reference.
	ok := strings.Replace(old, "${CF_TOKEN}", "${CF_TOKEN_2}", 1)
	if err := mergeErr(t, ok, old); err != nil {
		t.Fatalf("secret-field reference refused: %v", err)
	}
}

// E3: credential-bearing header maps anywhere (middleware headers) are
// masked, and comments never reach GET output.
func TestMaskHeadersAndComments(t *testing.T) {
	doc := `# admin note: the token is s3cr3t-comment
middlewares:
  h:
    headers:
      customRequestHeaders:
        Authorization: "Bearer s3cr3t-auth"
        Cookie: "sid=s3cr3t-cookie"
        X-Api-Key: s3cr3t-key
        X-Custom-Credential: s3cr3t-cred
        X-Plain: visible-value # trailing s3cr3t-line
settings: {default_zone: example.test} # s3cr3t-foot
`
	out, err := MaskConfig([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "s3cr3t") || strings.Contains(s, "#") {
		t.Fatalf("leak:\n%s", s)
	}
	if !strings.Contains(s, "visible-value") {
		t.Fatalf("plain header masked:\n%s", s)
	}
}
