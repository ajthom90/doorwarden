package acme

import (
	"testing"

	"github.com/ajthom90/doorwarden/internal/config"
)

func TestResolveDirectory(t *testing.T) {
	for _, tc := range []struct {
		in      string
		url     string
		staging bool
		ok      bool
	}{
		{"", LEStagingURL, true, true},
		{"staging", LEStagingURL, true, true},
		{"production", LEProductionURL, false, true},
		{"https://acme.example.test/dir", "https://acme.example.test/dir", false, true},
		{"https://localhost:14000/dir", "https://localhost:14000/dir", false, true},
		{"http://127.0.0.1:14000/dir", "http://127.0.0.1:14000/dir", false, true},
		{"http://[::1]:14000/dir", "http://[::1]:14000/dir", false, true},
		{"http://acme.example.test/dir", "", false, false},
		{"letsencrypt", "", false, false},
		{"ftp://acme.example.test", "", false, false},
		{"not a url", "", false, false},
	} {
		d, err := resolveDirectory(tc.in)
		if (err == nil) != tc.ok || d.URL != tc.url || d.Staging != tc.staging {
			t.Errorf("%q: %+v %v", tc.in, d, err)
		}
	}
}

func TestValidateIssuer(t *testing.T) {
	ok := []config.Issuer{
		{Directory: "staging", Email: "admin@example.test"},
		{Directory: "https://localhost:14000/dir"},
		{Directory: "https://acme.example.test/dir", EABKid: "k", EABHMAC: "h"},
	}
	for _, is := range ok {
		if err := validateIssuer("x", is); err != nil {
			t.Errorf("%+v: %v", is, err)
		}
	}
	bad := []config.Issuer{
		{Directory: "production"},
		{Directory: "staging", Email: "Admin <admin@example.test>"},
		{Directory: "https://acme.example.test/dir", EABKid: "k"},
	}
	for _, is := range bad {
		if err := validateIssuer("x", is); err == nil {
			t.Errorf("%+v accepted", is)
		}
	}
}
