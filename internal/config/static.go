package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ajthom90/doorwarden/internal/model"
)

// Key returns the stable service key: "static:<id>" if ID is set, else
// "static:<slug of name>". It is "" when neither yields a usable key.
func (s StaticService) Key() string {
	if id := strings.TrimSpace(s.ID); id != "" {
		return "static:" + id
	}
	slug, err := model.Slug(s.Name)
	if err != nil {
		return ""
	}
	return "static:" + slug
}

// Target returns the effective backend after applying defaults (Upstream URL
// overrides Host/Port; scheme http, or https with skip_verify; port 80/443 from
// the scheme). Only meaningful when Problems() is empty.
func (s StaticService) Target() (scheme, host string, port int) {
	scheme, host, port = s.Scheme, strings.TrimSpace(s.Host), s.Port
	if u := strings.TrimSpace(s.Upstream); u != "" {
		if pu, err := url.Parse(u); err == nil {
			scheme = pu.Scheme
			host = pu.Hostname()
			if p, err := strconv.Atoi(pu.Port()); err == nil {
				port = p
			} else {
				port = 0
			}
		}
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if scheme == "" {
		scheme = "http"
		if s.SkipVerify {
			scheme = "https"
		}
	}
	if port == 0 {
		port = 80
		if scheme == "https" {
			port = 443
		}
	}
	return scheme, host, port
}

// Problems returns every structural problem with the definition.
func (s StaticService) Problems() []string {
	var out []string
	add := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }

	if strings.TrimSpace(s.Name) == "" {
		add("name is required")
	} else if strings.TrimSpace(s.ID) == "" && s.Key() == "" {
		add("name %q has no characters usable in a key; set id", s.Name)
	}
	if s.Scheme != "" && s.Scheme != "http" && s.Scheme != "https" {
		add("scheme %q must be http or https", s.Scheme)
	}
	if s.Port < 0 || s.Port > 65535 {
		add("port %d out of range 1..65535", s.Port)
	}
	upScheme := ""
	up := strings.TrimSpace(s.Upstream)
	host := strings.TrimSpace(s.Host)
	switch {
	case up == "" && host == "":
		add("host or upstream is required")
	case up != "":
		u, err := url.Parse(up)
		switch {
		case err != nil:
			add("upstream is not a valid URL")
		case u.Scheme != "http" && u.Scheme != "https":
			add("upstream scheme must be http or https")
		case u.Hostname() == "":
			add("upstream has no host")
		case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
			add("upstream must be scheme://host[:port] without userinfo, path, query or fragment")
		default:
			upScheme = u.Scheme
			if ph := u.Port(); ph != "" {
				if n, err := strconv.Atoi(ph); err != nil || n < 1 || n > 65535 {
					add("upstream port %q out of range 1..65535", ph)
				}
			}
			if !validHost(u.Hostname()) {
				add("upstream host %q is invalid", u.Hostname())
			}
			if s.Scheme != "" && s.Scheme != u.Scheme {
				add("scheme %q conflicts with upstream scheme %q", s.Scheme, u.Scheme)
			}
		}
	}
	if host != "" && !validHostField(host) {
		add("host %q must be a bare hostname or IP (no scheme, path, whitespace or :port)", host)
	}
	if s.SkipVerify && (s.Scheme == "http" || upScheme == "http") {
		add("skip_verify requires https but scheme/upstream is http")
	}
	return out
}

func validHostField(h string) bool {
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		ip := net.ParseIP(h[1 : len(h)-1])
		return ip != nil && ip.To4() == nil
	}
	if net.ParseIP(h) != nil {
		return true
	}
	return validHost(h)
}

// validHost accepts hostnames and IPs (IPv6 unbracketed).
func validHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	return h != "" && !strings.ContainsAny(h, " \t\r\n/:@?#[]\\")
}
