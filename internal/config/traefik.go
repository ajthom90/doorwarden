package config

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/ajthom90/doorwarden/internal/model"
)

// validateTraefik checks the traefik settings, the middleware definitions
// and every static service's middleware references, using the same model
// predicates the Traefik renderer fails closed on.
func (c *Config) validateTraefik() []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	t := c.Traefik
	for _, p := range []struct{ name, v string }{
		{"traefik.dynamic_dir", t.DynamicDir}, {"traefik.cert_path_prefix", t.CertPathPrefix},
	} {
		switch {
		case p.v == "":
		case !strings.HasPrefix(p.v, "/") || strings.ContainsAny(p.v, "\x00\n\r"):
			add("%s %q must be an absolute path", p.name, p.v)
		case p.v != "/" && path.Clean(p.v) != strings.TrimRight(p.v, "/"):
			add("%s %q must be a clean path (no . or .. elements)", p.name, p.v)
		}
	}
	if ep := t.EntryPoint; ep != "" && !validEntryPoint(ep) {
		add("traefik.entry_point %q must be [A-Za-z0-9_-]+", ep)
	}
	for _, e := range t.ExternalMiddlewares {
		if err := model.ValidateExternalMiddleware(e); err != nil {
			add("traefik.external_middlewares: %v", err)
		}
	}

	valid, probs := model.ValidateMiddlewareDefs(c.MiddlewareDefs(), t.ExternalMiddlewares)
	names := make([]string, 0, len(probs))
	for n := range probs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		add("middlewares %q: %v", n, probs[n])
	}
	defined := func(n string) bool { return valid[n] }
	for i, st := range c.Static {
		for _, ref := range st.Middlewares {
			err := model.CheckMiddlewareRef(ref, defined, t.ExternalMiddlewares)
			if err == nil {
				continue
			}
			name, _, _ := strings.Cut(ref, "@")
			if _, exists := c.Middlewares[name]; exists && !valid[name] {
				add("static[%d] %s: middleware %q refers to an invalid definition (see middlewares %q); the route would not be rendered",
					i, st.Name, ref, name)
				continue
			}
			add("static[%d] %s: %v; the route would not be rendered", i, st.Name, err)
		}
	}
	return errs
}

func validEntryPoint(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}
