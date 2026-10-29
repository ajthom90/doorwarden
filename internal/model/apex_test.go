package model

import (
	"errors"
	"strings"
	"testing"
)

// An apex service's hostname is the zone name itself (normalized), never
// "<slug>.<zone>".
func TestHostnameApex(t *testing.T) {
	zones := []string{"Example.Test.", "home.example.test"}
	cases := []struct {
		name string
		svc  Service
		want string
		err  string
	}{
		{"apex", Service{Name: "site", Zone: "example.test", Options: Options{Apex: true}}, "example.test", ""},
		{"apex default zone", Service{Name: "site", Options: Options{Apex: true}}, "example.test", ""},
		{"apex subzone", Service{Name: "home", Zone: "home.example.test", Options: Options{Apex: true}}, "home.example.test", ""},
		{"www ordinary", Service{Name: "www", Zone: "example.test"}, "www.example.test", ""},
		{"apex ignores a stale rename", Service{Name: "site", Zone: "example.test", Options: Options{Apex: true, Rename: "x"}}, "example.test", ""},
		{"apex unknown zone", Service{Name: "site", Zone: "other.test", Options: Options{Apex: true}}, "", "unknown zone"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Hostname(c.svc, zones, "example.test")
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

// A zone name that is not a valid DNS host name (IDN in Unicode form, an IP,
// a wildcard) cannot be published as an apex.
func TestHostnameApexInvalidZone(t *testing.T) {
	for _, z := range []string{"bücher.test", "192.0.2.1", "*.example.test", "bad_zone.test"} {
		_, err := Hostname(Service{Name: "x", Zone: z, Options: Options{Apex: true}}, []string{z}, "")
		if err == nil {
			t.Errorf("zone %q: apex accepted", z)
		}
	}
	if h, err := Hostname(Service{Name: "x", Zone: "xn--bcher-kva.test", Options: Options{Apex: true}}, []string{"xn--bcher-kva.test"}, ""); err != nil || h != "xn--bcher-kva.test" {
		t.Fatalf("punycode zone: %q %v", h, err)
	}
}

// The UI cannot rename an apex service.
func TestUIOverridesRenameApexRefused(t *testing.T) {
	svc := Service{Name: "site", Zone: "example.test", Options: Options{Apex: true},
		Backend: Backend{Scheme: "http", Host: "192.0.2.5", Port: 80}}
	r := "other"
	err := UIOverrides{Rename: &r}.Validate(svc, []string{"example.test"}, "")
	var oe *OverrideError
	if !errors.As(err, &oe) || !strings.Contains(oe.Msg, "apex") {
		t.Fatalf("err = %v", err)
	}
	p := 8080
	if err := (UIOverrides{Port: &p}).Validate(svc, []string{"example.test"}, ""); err != nil {
		t.Fatalf("port override on apex: %v", err)
	}
}
