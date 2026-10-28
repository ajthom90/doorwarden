package acme

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"

	"github.com/ajthom90/doorwarden/internal/config"
)

// Let's Encrypt directories.
const (
	LEStagingURL    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	LEProductionURL = "https://acme-v02.api.letsencrypt.org/directory"
)

// directory is a resolved issuer directory.
type directory struct {
	URL string
	// Staging is true for the Let's Encrypt staging directory only.
	Staging bool
	// LetsEncrypt is true for both Let's Encrypt directories.
	LetsEncrypt bool
}

// resolveDirectory maps an issuer directory setting: "staging" (also the
// empty default) => LE staging, "production" => LE production, anything else
// => a URL that must be https unless its host is a loopback name (tests).
// "letsencrypt" is rejected as ambiguous.
func resolveDirectory(dir string) (directory, error) {
	dir = strings.TrimSpace(dir)
	switch dir {
	case "", "staging":
		return directory{URL: LEStagingURL, Staging: true, LetsEncrypt: true}, nil
	case "production":
		return directory{URL: LEProductionURL, LetsEncrypt: true}, nil
	case "letsencrypt":
		return directory{}, errors.New(`directory "letsencrypt" is ambiguous: use "staging" or "production"`)
	}
	u, err := url.Parse(dir)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return directory{}, fmt.Errorf("directory %q must be staging, production or an https URL", dir)
	}
	if u.Scheme != "https" && !loopbackHost(u.Hostname()) {
		return directory{}, fmt.Errorf("directory %q must use https", dir)
	}
	d := directory{URL: dir}
	// Let's Encrypt's own URLs are recognized however they are written
	// (scheme and host case, trailing slash) and stored in canonical form.
	norm := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimRight(u.EscapedPath(), "/")
	if u.RawQuery == "" && u.Fragment == "" {
		switch norm {
		case LEStagingURL:
			d = directory{URL: LEStagingURL, Staging: true, LetsEncrypt: true}
		case LEProductionURL:
			d = directory{URL: LEProductionURL, LetsEncrypt: true}
		}
	}
	return d, nil
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// validateIssuer checks one issuer: directory, e-mail (required for Let's
// Encrypt) and EAB completeness.
func validateIssuer(name string, is config.Issuer) error {
	d, err := resolveDirectory(is.Directory)
	if err != nil {
		return fmt.Errorf("issuer %q: %w", name, err)
	}
	if is.Email == "" && d.LetsEncrypt {
		return fmt.Errorf("issuer %q: email is required for Let's Encrypt", name)
	}
	if is.Email != "" {
		if a, err := mail.ParseAddress(is.Email); err != nil || a.Address != is.Email {
			return fmt.Errorf("issuer %q: email %q is not a plain address", name, is.Email)
		}
	}
	if (is.EABKid == "") != (is.EABHMAC == "") {
		return fmt.Errorf("issuer %q: eab_kid and eab_hmac must be set together", name)
	}
	return nil
}
