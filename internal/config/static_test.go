package config

import (
	"strings"
	"testing"
)

func TestStaticProblems(t *testing.T) {
	bad := map[string]StaticService{
		"name":         {Host: "192.0.2.1", Port: 80},
		"host or up":   {Name: "a"},
		"scheme":       {Name: "a", Host: "h.example.test", Scheme: "ftp"},
		"port":         {Name: "a", Host: "h.example.test", Port: 70000},
		"host scheme":  {Name: "a", Host: "http://h.example.test"},
		"host path":    {Name: "a", Host: "h.example.test/x"},
		"host port":    {Name: "a", Host: "h.example.test:80"},
		"host space":   {Name: "a", Host: "h .example.test"},
		"up scheme":    {Name: "a", Upstream: "ftp://h.example.test"},
		"up path":      {Name: "a", Upstream: "http://h.example.test/x"},
		"up user":      {Name: "a", Upstream: "http://u:p@h.example.test"},
		"up query":     {Name: "a", Upstream: "http://h.example.test?x=1"},
		"up host":      {Name: "a", Upstream: "http://:80"},
		"up port":      {Name: "a", Upstream: "http://h.example.test:99999"},
		"skip http":    {Name: "a", Host: "h.example.test", Scheme: "http", SkipVerify: true},
		"skip upstr":   {Name: "a", Upstream: "http://h.example.test", SkipVerify: true},
		"conflict":     {Name: "a", Upstream: "https://h.example.test", Scheme: "http"},
		"port clash":   {Name: "a", Upstream: "http://h.example.test:81", Port: 82},
		"up fragment":  {Name: "a", Upstream: "http://h.example.test#"},
		"bad id":       {Name: "a", ID: "a b", Host: "h.example.test"},
		"id slash":     {Name: "a", ID: "a/b", Host: "h.example.test"},
		"host quote":   {Name: "a", Host: "h\"x.example.test"},
		"host brace":   {Name: "a", Host: "h{x}.example.test"},
		"host dotdot":  {Name: "a", Host: "a..example.test"},
		"host lead -":  {Name: "a", Host: "-a.example.test"},
		"host trail.":  {Name: "a", Host: "a.example.test."},
		"host label64": {Name: "a", Host: strings.Repeat("a", 64) + ".example.test"},
		"host 254":     {Name: "a", Host: strings.Repeat("a.", 127)},
		"host unicode": {Name: "a", Host: "h\u00e9.example.test"},
		"slugless":     {Name: "!!!", Host: "192.0.2.1"},
	}
	for n, s := range bad {
		if len(s.Problems()) == 0 {
			t.Errorf("%s: expected problems", n)
		}
	}
	good := []StaticService{
		{Name: "a", Host: "192.0.2.1"},
		{Name: "a", Host: "static-app.example.test", Port: 8080},
		{Name: "a", Host: "2001:db8::1"},
		{Name: "a", Host: "host_1.sub-domain.example.test"},
		{Name: "a", Upstream: "http://h.example.test:8080", Port: 8080},
		{Name: "a", Upstream: "http://h.example.test", Port: 8080},
		{Name: "a", Host: "[2001:db8::1]"},
		{Name: "a", Upstream: "https://198.51.100.7:8443", SkipVerify: true},
		{Name: "!!!", ID: "x", Host: "192.0.2.1"},
	}
	for _, s := range good {
		if p := s.Problems(); len(p) != 0 {
			t.Errorf("%+v: %v", s, p)
		}
	}
}

func TestStaticTargetDefaults(t *testing.T) {
	cases := []struct {
		s        StaticService
		sc, host string
		port     int
	}{
		{StaticService{Host: "h.example.test"}, "http", "h.example.test", 80},
		{StaticService{Host: "h.example.test", SkipVerify: true}, "https", "h.example.test", 443},
		{StaticService{Host: "h.example.test", Port: 8080, Scheme: "https"}, "https", "h.example.test", 8080},
		{StaticService{Upstream: "https://198.51.100.7:8443", Host: "ignored"}, "https", "198.51.100.7", 8443},
		{StaticService{Upstream: "http://h.example.test"}, "http", "h.example.test", 80},
		{StaticService{Upstream: "http://h.example.test", Port: 8080}, "http", "h.example.test", 8080},
		{StaticService{Upstream: "https://h.example.test", Port: 8080}, "https", "h.example.test", 8080},
		{StaticService{Upstream: "http://h.example.test:9000", Port: 9000}, "http", "h.example.test", 9000},
		{StaticService{Upstream: "https://h.example.test"}, "https", "h.example.test", 443},
		{StaticService{Host: "[2001:db8::1]"}, "http", "2001:db8::1", 80},
	}
	for _, c := range cases {
		sc, h, p := c.s.Target()
		if sc != c.sc || h != c.host || p != c.port {
			t.Errorf("%+v -> %s %s %d", c.s, sc, h, p)
		}
	}
}

func TestStaticKey(t *testing.T) {
	if k := (StaticService{ID: "x1", Name: "A b"}).Key(); k != "static:x1" {
		t.Fatal(k)
	}
	if k := (StaticService{Name: "My App"}).Key(); k != "static:my-app" {
		t.Fatal(k)
	}
}

func TestValidateStaticErrorsAndDuplicates(t *testing.T) {
	yml := base + "static:\n  - {name: ok, host: 192.0.2.1}\n  - {name: Bad, host: 'http://x'}\n  - {name: OK, host: 192.0.2.2}\n"
	errs := mustLoad(t, yml).Validate(caps(true))
	if !hasErr(errs, "static[1] Bad:") || !hasErr(errs, "static[2] OK: duplicate key static:ok") {
		t.Fatalf("errs = %v", errs)
	}
	for _, e := range errs {
		if strings.HasPrefix(e.Error(), "static[0]") {
			t.Fatalf("unexpected %v", e)
		}
	}
}

func TestStaticYAMLFields(t *testing.T) {
	yml := base + "static:\n  - {id: i, name: n, host: 192.0.2.1, scheme: https, zone: example.test, skip_verify: true, websockets: true, middlewares: [a, b], rename: r, skip: true}\n"
	s := mustLoad(t, yml).Static[0]
	if s.ID != "i" || s.Scheme != "https" || s.Zone != "example.test" || !s.SkipVerify || !s.Websockets || len(s.Middlewares) != 2 || s.Rename != "r" || !s.Skip {
		t.Fatalf("%+v", s)
	}
}
