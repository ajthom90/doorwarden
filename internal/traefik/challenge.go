package traefik

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// HTTP-01 challenge route (Options.Challenge).
//
// Traefik answers plain HTTP on its own entry point (traefik.http_entry_point,
// default "web"). Doorwarden renders, into ChallengeFile, one router there
// that matches exactly the host names an http-01 certificate is wanted for
// AND the path prefix /.well-known/acme-challenge/, and forwards those
// requests to Doorwarden's challenge server (acme.http01_backend) with the
// Host header passed through (lego's server matches the token on it). It has
// no TLS and no middleware, so no redirect to HTTPS applies to it, and it
// lives on the plain-HTTP entry point only, so it never shadows an HTTPS
// router. When no http-01 certificate is wanted the file is not rendered
// and Write removes it.
//
// Traefik's entry-point redirection (entryPoints.web.http.redirections) is a
// generated catch-all router with priority MaxInt-1, and a user router's
// priority is capped at MaxInt-1000; the redirection must therefore be given
// a low priority (redirections.entryPoint.priority: 1, see
// deploy/traefik/traefik.yml) for this router to receive challenge requests.

// ChallengeFile is the dynamic file holding the challenge router.
const ChallengeFile = "doorwarden-acme-http01.yml"

// ChallengeRouter names the challenge router and its service. Route names
// (Name) always end in a 10-hex-digit hash, so it never collides with one.
const ChallengeRouter = "doorwarden-acme-http01"

// ChallengePathPrefix is the ACME HTTP-01 path (RFC 8555 section 8.3).
const ChallengePathPrefix = "/.well-known/acme-challenge/"

// ChallengePriority is the challenge router's priority: far above any
// rule-length default of other routers on the entry point and below
// Traefik's reserved range for internal routers (MaxInt32-1000 on 32-bit).
const ChallengePriority = 1 << 30

// KindInvalidChallengeHost: a wanted http-01 name that cannot be matched
// exactly (wildcard, IP literal, malformed) is left out of the challenge
// router.
const KindInvalidChallengeHost = "invalid-challenge-host"

// Challenge configures the HTTP-01 challenge router.
type Challenge struct {
	// EntryPoint is Traefik's plain-HTTP entry point (required; must differ
	// from Options.EntryPoint).
	EntryPoint string
	// Backend is the URL of the challenge server as Traefik reaches it:
	// http(s)://host[:port], no userinfo, path, query or fragment.
	Backend string
	// Hosts are the wanted http-01 certificate names. Only valid exact DNS
	// names are matched; an empty list renders no file.
	Hosts []string
}

type challengeRouter struct {
	EntryPoints []string `yaml:"entryPoints"`
	Rule        string   `yaml:"rule"`
	Priority    int      `yaml:"priority"`
	Service     string   `yaml:"service"`
}

type challengeDocOut struct {
	HTTP struct {
		Routers  map[string]challengeRouter `yaml:"routers"`
		Services map[string]service         `yaml:"services"`
	} `yaml:"http"`
}

// checkBackend validates a challenge backend URL.
func checkBackend(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case raw == "" || err != nil || strings.ContainsAny(raw, " \t\r\n#`"):
		return fmt.Errorf("traefik: challenge backend %q is not a valid URL", raw)
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("traefik: challenge backend %q must be http:// or https://", raw)
	case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Hostname() == "":
		return fmt.Errorf("traefik: challenge backend %q must be scheme://host[:port]", raw)
	}
	return nil
}

// buildChallenge returns the content of ChallengeFile (nil when no host is
// usable) and Problems for the names left out. ep is the HTTPS entry point.
func buildChallenge(ch *Challenge, ep string) ([]byte, []Problem, error) {
	if ch == nil {
		return nil, nil, nil
	}
	if !validEntryPoint(ch.EntryPoint) {
		return nil, nil, fmt.Errorf("traefik: challenge entry point %q must be [A-Za-z0-9_-]+", ch.EntryPoint)
	}
	if ch.EntryPoint == ep {
		return nil, nil, fmt.Errorf("traefik: challenge entry point %q must differ from the HTTPS entry point", ch.EntryPoint)
	}
	if err := checkBackend(ch.Backend); err != nil {
		return nil, nil, err
	}
	var probs []Problem
	seen := map[string]bool{}
	var hosts []string
	for _, h := range ch.Hosts {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if !validRouteHostname(n) {
			probs = append(probs, Problem{Kind: KindInvalidChallengeHost, Hostname: h,
				Detail: fmt.Sprintf("%q is not an exact DNS name; not matched by the HTTP-01 challenge router", h)})
			continue
		}
		if !seen[n] {
			seen[n] = true
			hosts = append(hosts, n)
		}
	}
	if len(hosts) == 0 {
		return nil, probs, nil
	}
	sort.Strings(hosts)
	ms := make([]string, len(hosts))
	for i, h := range hosts {
		ms[i] = "Host(`" + h + "`)"
	}
	hostRule := ms[0]
	if len(ms) > 1 {
		hostRule = "(" + strings.Join(ms, " || ") + ")"
	}
	var d challengeDocOut
	d.HTTP.Routers = map[string]challengeRouter{ChallengeRouter: {
		EntryPoints: []string{ch.EntryPoint},
		Rule:        hostRule + " && PathPrefix(`" + ChallengePathPrefix + "`)",
		Priority:    ChallengePriority,
		Service:     ChallengeRouter,
	}}
	d.HTTP.Services = map[string]service{ChallengeRouter: {LoadBalancer: loadBalancer{
		Servers: []server{{URL: strings.TrimSuffix(ch.Backend, "/")}}, PassHostHeader: true}}}
	b, err := marshal(d)
	return b, probs, err
}
