package config

import (
	"strings"
	"testing"
)

const twoZones = `
zones:
  - name: example.test
    target_ip: 192.0.2.10
  - name: home.example.test
    target_ip: 192.0.2.11
settings: {default_zone: example.test}
`

func TestStaticApexYAMLAndProblems(t *testing.T) {
	s := mustLoad(t, base+"static:\n  - {name: site, host: 192.0.2.1, apex: true}\n").Static[0]
	if !s.Apex {
		t.Fatalf("%+v", s)
	}
	s.Rename = "x"
	if p := strings.Join(s.Problems(), ";"); !strings.Contains(p, "apex and rename are mutually exclusive") {
		t.Fatalf("problems = %q", p)
	}
}

// One apex entry per (resolved) zone; entries in different zones, a
// subdomain zone included, are independent; www stays an ordinary entry.
func TestValidateStaticApexPerZone(t *testing.T) {
	yml := twoZones + `static:
  - {name: site, host: 192.0.2.1, apex: true}
  - {name: www, host: 192.0.2.1}
  - {name: home, host: 192.0.2.2, zone: home.example.test, apex: true}
`
	if errs := mustLoad(t, yml).Validate(caps(true)); len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	dup := yml + "  - {name: other, host: 192.0.2.3, zone: Example.Test., apex: true}\n"
	errs := mustLoad(t, dup).Validate(caps(true))
	if !hasErr(errs, "static[3] other: zone example.test already has an apex entry (static[0])") {
		t.Fatalf("errs = %v", errs)
	}
}

func TestValidateStaticApexZoneProblems(t *testing.T) {
	yml := `
zones:
  - name: a.test
    target_ip: 192.0.2.10
  - name: b.test
    target_ip: 192.0.2.11
static:
  - {name: site, host: 192.0.2.1, apex: true}
  - {name: bad, host: 192.0.2.1, zone: c.test, apex: true}
`
	errs := mustLoad(t, yml).Validate(caps(true))
	if !hasErr(errs, "static[0] site: apex needs a zone") || !hasErr(errs, "static[1] bad: apex zone \"c.test\" is not a configured zone") {
		t.Fatalf("errs = %v", errs)
	}
	bad := `
zones:
  - name: Bad_Zone.test
    target_ip: 192.0.2.10
static:
  - {name: site, host: 192.0.2.1, apex: true}
`
	errs = mustLoad(t, bad).Validate(caps(true))
	if !hasErr(errs, "static[0] site: zone \"bad_zone.test\" is not a valid host name for an apex entry") {
		t.Fatalf("errs = %v", errs)
	}
}
