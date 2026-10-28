package config

import (
	"reflect"
	"testing"
)

func TestTraefikDefaults(t *testing.T) {
	c := mustLoad(t, base)
	want := Traefik{DynamicDir: "/etc/traefik/dynamic", EntryPoint: "websecure", CertPathPrefix: "/certs"}
	if !reflect.DeepEqual(c.Traefik, want) {
		t.Fatalf("got %+v", c.Traefik)
	}
	if errs := c.Validate(caps(true)); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestTraefikAndMiddlewaresDecode(t *testing.T) {
	yml := base + `
traefik:
  dynamic_dir: /srv/dyn
  entry_point: https
  cert_path_prefix: /data/certs
  external_middlewares: [crowdsec@docker]
middlewares:
  auth:
    forwardAuth:
      address: "http://192.0.2.50:9091/verify?u=${U}"
      trustForwardHeader: true
  hdrs:
    headers: {}
static:
  - name: wiki
    host: 198.51.100.7
    middlewares: [auth@file, hdrs, crowdsec@docker]
`
	c, err := loadStr(t, yml, map[string]string{"U": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Traefik.DynamicDir != "/srv/dyn" || c.Traefik.EntryPoint != "https" || c.Traefik.CertPathPrefix != "/data/certs" ||
		!reflect.DeepEqual(c.Traefik.ExternalMiddlewares, []string{"crowdsec@docker"}) {
		t.Fatalf("traefik %+v", c.Traefik)
	}
	fa := c.Middlewares["auth"]["forwardAuth"].(map[string]any)
	if fa["address"] != "http://192.0.2.50:9091/verify?u=x" || fa["trustForwardHeader"] != true {
		t.Fatalf("auth %#v", fa)
	}
	if errs := c.Validate(caps(true)); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestTraefikUnknownKeyFails(t *testing.T) {
	if _, err := loadStr(t, base+"traefik:\n  dynamic_directory: /x\n", nil); err == nil {
		t.Fatal("unknown traefik key accepted")
	}
}

func TestMiddlewareValidation(t *testing.T) {
	cases := map[string]string{
		"bad name": `
middlewares:
  "a b":
    headers: {}
`,
		"name with provider": `
middlewares:
  auth@file:
    headers: {}
`,
		"two types": `
middlewares:
  auth:
    headers: {}
    basicAuth: {}
`,
		"no type": `
middlewares:
  auth: {}
`,
		"scalar options": `
middlewares:
  auth:
    basicAuth: users
`,
		"undefined static ref": `
static:
  - name: wiki
    host: 198.51.100.7
    middlewares: [missing@file]
`,
		"other provider not allowlisted": `
static:
  - name: wiki
    host: 198.51.100.7
    middlewares: [crowdsec@docker]
`,
		"bad static ref": `
static:
  - name: wiki
    host: 198.51.100.7
    middlewares: ["a b"]
`,
		"unqualified external": `
traefik:
  external_middlewares: [crowdsec]
`,
		"bad entry point": `
traefik:
  entry_point: "web secure"
`,
		"relative dynamic dir": `
traefik:
  dynamic_dir: dyn
`,
		"relative cert prefix": `
traefik:
  cert_path_prefix: certs
`,
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			errs := mustLoad(t, base+extra).Validate(caps(true))
			if len(errs) == 0 {
				t.Fatal("no error")
			}
		})
	}
}

// A static service referencing a definition that is itself invalid is also
// reported (it would render fail-closed).
func TestStaticRefToInvalidDefinition(t *testing.T) {
	yml := base + `
middlewares:
  auth:
    headers: {}
    basicAuth: {}
static:
  - name: wiki
    host: 198.51.100.7
    middlewares: [auth]
`
	errs := mustLoad(t, yml).Validate(caps(true))
	if !hasErr(errs, "static[0]") || !hasErr(errs, `middlewares "auth"`) {
		t.Fatalf("errs %v", errs)
	}
}

// Placeholders under middlewares stay exact strings, like under providers:
// header values and secrets must not be retyped (0123 -> 83, 1e3 -> 1000).
func TestMiddlewarePlaceholdersStayStrings(t *testing.T) {
	for _, v := range []string{"0123", "1e3", "0x1F", "true", "null", "~", "12", "a: b", "{{x}}"} {
		yml := base + `
middlewares:
  hdr:
    headers:
      customRequestHeaders:
        X-Key: ${V}
      sslRedirect: ${V}
`
		c, err := loadStr(t, yml, map[string]string{"V": v})
		if err != nil {
			t.Fatal(err)
		}
		h := c.Middlewares["hdr"]["headers"].(map[string]any)
		if got := h["customRequestHeaders"].(map[string]any)["X-Key"]; got != v {
			t.Errorf("%q became %#v", v, got)
		}
		if got := h["sslRedirect"]; got != v {
			t.Errorf("%q became %#v", v, got)
		}
	}
}

// Outside providers and middlewares, typed substitution is unchanged.
func TestTypedSubstitutionOutsideMiddlewaresUnchanged(t *testing.T) {
	yml := base + `
settings:
  dry_run: ${D}
middlewares:
  hdr:
    headers: {}
`
	c, err := loadStr(t, yml, map[string]string{"D": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Settings.DryRun {
		t.Fatal("dry_run not typed")
	}
}

func TestMiddlewareChainAndTemplateValidation(t *testing.T) {
	for name, extra := range map[string]string{
		"chain to undefined": `
middlewares:
  Auth:
    chain:
      middlewares: [nope]
`,
		"Chain to undefined": `
middlewares:
  Auth:
    Chain:
      Middlewares: [nope]
`,
		"CHAIN cycle": `
middlewares:
  a:
    CHAIN:
      middlewares: [b]
  b:
    chain:
      MIDDLEWARES: [a]
`,
		"case-duplicate type keys": `
middlewares:
  a:
    headers: {}
    Headers: {}
`,
		"template": `
middlewares:
  hdr:
    headers:
      customRequestHeaders:
        X-A: "{{ .Foo }}"
`,
		"template via env": `
middlewares:
  hdr:
    headers:
      customRequestHeaders:
        X-A: "${T}"
`,
	} {
		t.Run(name, func(t *testing.T) {
			c, err := loadStr(t, base+extra, map[string]string{"T": "a}}b"})
			if err != nil {
				t.Fatal(err)
			}
			if errs := c.Validate(caps(true)); len(errs) == 0 {
				t.Fatal("no error")
			}
		})
	}
	ok := base + `
traefik:
  external_middlewares: [crowdsec@docker]
middlewares:
  hdr:
    headers: {}
  both:
    chain:
      middlewares: [hdr, crowdsec@docker]
static:
  - name: wiki
    host: 198.51.100.7
    middlewares: [both@file]
`
	if errs := mustLoad(t, ok).Validate(caps(true)); len(errs) != 0 {
		t.Fatal(errs)
	}
}
