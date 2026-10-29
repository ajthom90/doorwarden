package model

import (
	"strings"
	"testing"
)

func TestUIOverridesParseAndApply(t *testing.T) {
	o, err := ParseUIOverrides(`{"rename":"web","port":8443,"skip":true,"skip_verify":true}`)
	if err != nil {
		t.Fatal(err)
	}
	s := Service{Key: "k", Name: "app", Backend: Backend{Scheme: "https", Host: "198.51.100.5", Port: 443}}
	got := ApplyUI(s, o)
	if got.Options.Rename != "web" || got.Backend.Port != 8443 || !got.Options.Skip || !got.Backend.SkipVerify {
		t.Fatalf("applied = %+v", got)
	}
	if o, err := ParseUIOverrides(""); err != nil || !o.Empty() {
		t.Fatalf("empty: %+v %v", o, err)
	}
	if o, err := ParseUIOverrides("{}"); err != nil || !o.Empty() {
		t.Fatalf("{}: %+v %v", o, err)
	}
	for _, bad := range []string{`{"middlewares":[]}`, `{"port":"x"}`, `not json`, `{} {}`} {
		if _, err := ParseUIOverrides(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	j, err := o.JSON()
	if err != nil || !strings.Contains(j, `"rename":"web"`) {
		t.Fatalf("json = %s %v", j, err)
	}
}

func TestUIOverridesValidate(t *testing.T) {
	base := Service{Key: "k", Name: "app", Zone: "example.test", Backend: Backend{Scheme: "http", Host: "198.51.100.5", Port: 80}}
	zones := []string{"example.test"}
	p := func(i int) *int { return &i }
	s := func(v string) *string { return &v }
	b := func(v bool) *bool { return &v }
	ok := []UIOverrides{{Rename: s("web")}, {Port: p(8080)}, {Skip: b(true)}, {Skip: b(false)}}
	for _, o := range ok {
		if err := o.Validate(base, zones, ""); err != nil {
			t.Errorf("%+v: %v", o, err)
		}
	}
	bad := []UIOverrides{{Rename: s("Bad Name")}, {Rename: s("")}, {Rename: s("a.b")}, {Rename: s(strings.Repeat("a", 64))},
		{Port: p(0)}, {Port: p(70000)}, {SkipVerify: b(true)}}
	for _, o := range bad {
		if err := o.Validate(base, zones, ""); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
	https := base
	https.Backend.Scheme = "https"
	if err := (UIOverrides{SkipVerify: b(true)}).Validate(https, zones, ""); err != nil {
		t.Fatal(err)
	}
}
