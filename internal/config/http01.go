package config

import (
	"fmt"
	"net"
	"strings"
)

// UsesHTTP01 reports whether Doorwarden renders the HTTP-01 challenge route:
// acme.http01_listen is set and a zone with an issuer uses challenge http-01.
func (c *Config) UsesHTTP01() bool {
	if c.ACME.HTTP01Listen == "" {
		return false
	}
	for _, z := range c.Zones {
		if z.Certificate.Issuer != "" && z.Certificate.Challenge == "http-01" {
			return true
		}
	}
	return false
}

// HTTP01Warnings are the start-up warnings of the HTTP-01 challenge route
// (none when it is not in use): Doorwarden renders the route itself (it
// overrides a hand-made one) when acme.http01_backend is left at its
// default; that default cannot reach a loopback http01_listen; and
// Traefik's web redirection must have priority 1, which Doorwarden cannot
// check (Traefik's static configuration is not visible to it).
func (c *Config) HTTP01Warnings() []string {
	if !c.UsesHTTP01() {
		return nil
	}
	var out []string
	if c.ACME.http01BackendDefaulted {
		out = append(out, fmt.Sprintf("acme.http01: Doorwarden now renders the Traefik route for /.well-known/acme-challenge/ (%s) to %s, overriding a route you added yourself; set acme.http01_backend to the URL Traefik uses to reach acme.http01_listen if that default is wrong",
			"doorwarden-acme-http01.yml", c.ACME.HTTP01Backend))
		host, _, err := net.SplitHostPort(c.ACME.HTTP01Listen)
		if ip := net.ParseIP(host); err == nil && (strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()) {
			out = append(out, fmt.Sprintf("acme.http01_listen %q is a loopback address: the default acme.http01_backend %s cannot reach it; listen on all interfaces (e.g. \":%s\") or set acme.http01_backend",
				c.ACME.HTTP01Listen, c.ACME.HTTP01Backend, portOf(c.ACME.HTTP01Listen)))
		}
	}
	out = append(out, "acme.http01: ensure Traefik's web entry-point redirection has priority: 1 (traefik.yml entryPoints.web.http.redirections.entryPoint.priority), or HTTP-01 validation is redirected to HTTPS; see docs/deploy.md")
	return out
}

func portOf(hostport string) string {
	_, p, _ := net.SplitHostPort(hostport)
	return p
}
