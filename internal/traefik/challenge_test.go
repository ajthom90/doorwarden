package traefik

import (
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/store"
	"gopkg.in/yaml.v3"
)

type challengeDoc struct {
	HTTP struct {
		Routers  map[string]map[string]any `yaml:"routers"`
		Services map[string]struct {
			LoadBalancer struct {
				Servers []struct {
					URL string `yaml:"url"`
				} `yaml:"servers"`
				PassHostHeader *bool `yaml:"passHostHeader"`
			} `yaml:"loadBalancer"`
		} `yaml:"services"`
		Middlewares map[string]any `yaml:"middlewares"`
	} `yaml:"http"`
}

func renderChallenge(t *testing.T, ch *Challenge) (Files, []Problem) {
	t.Helper()
	f, probs, err := Render([]store.Route{rt("static:www", "www", 80)}, nil, nil, Options{Challenge: ch})
	if err != nil {
		t.Fatal(err)
	}
	return f, probs
}

// The challenge router: its own file, plain-HTTP entry point, exact Host()
// matches of the wanted names only (sorted, deduplicated, lowercased) AND
// the challenge path, high priority, no TLS, no middleware, forwarding to
// the backend with the Host header passed (lego's server matches on it).
func TestRenderChallengeRoute(t *testing.T) {
	f, probs := renderChallenge(t, &Challenge{EntryPoint: "web", Backend: "http://doorwarden:8089",
		Hosts: []string{"www.example.test", "Example.Test.", "example.test"}})
	for _, p := range probs {
		if p.Kind == KindInvalidChallengeHost {
			t.Fatalf("problems: %v", probs)
		}
	}
	b, ok := f[ChallengeFile]
	if !ok || !strings.HasPrefix(string(b), Header) {
		t.Fatalf("files: %v", f)
	}
	var d challengeDoc
	if err := yaml.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	r := d.HTTP.Routers[ChallengeRouter]
	if len(d.HTTP.Routers) != 1 || r == nil {
		t.Fatalf("routers: %v", d.HTTP.Routers)
	}
	wantRule := "(Host(`example.test`) || Host(`www.example.test`)) && PathPrefix(`/.well-known/acme-challenge/`)"
	if r["rule"] != wantRule {
		t.Fatalf("rule = %v", r["rule"])
	}
	if eps, _ := r["entryPoints"].([]any); len(eps) != 1 || eps[0] != "web" {
		t.Fatalf("entryPoints = %v", r["entryPoints"])
	}
	if r["priority"] != ChallengePriority || r["service"] != ChallengeRouter {
		t.Fatalf("router = %v", r)
	}
	for _, k := range []string{"tls", "middlewares"} {
		if _, has := r[k]; has {
			t.Fatalf("challenge router has %s: %v", k, r)
		}
	}
	if len(d.HTTP.Middlewares) != 0 {
		t.Fatalf("middlewares rendered: %v", d.HTTP.Middlewares)
	}
	s := d.HTTP.Services[ChallengeRouter].LoadBalancer
	if len(s.Servers) != 1 || s.Servers[0].URL != "http://doorwarden:8089" || s.PassHostHeader == nil || !*s.PassHostHeader {
		t.Fatalf("service = %+v", s)
	}
	// The HTTPS routes file is unchanged by the challenge route.
	plain, _ := renderChallenge(t, nil)
	if string(plain[RoutesFile]) != string(f[RoutesFile]) || string(plain[TLSFile]) != string(f[TLSFile]) {
		t.Fatal("challenge route changed the routes or TLS file")
	}
	if strings.Contains(string(f[RoutesFile]), "acme-challenge") {
		t.Fatal("challenge route in the routes file")
	}
	// A single host needs no parentheses.
	f, _ = renderChallenge(t, &Challenge{EntryPoint: "web", Backend: "http://doorwarden:8089", Hosts: []string{"example.test"}})
	if !strings.Contains(string(f[ChallengeFile]), "rule: Host(`example.test`) && PathPrefix(`/.well-known/acme-challenge/`)") {
		t.Fatalf("single host:\n%s", f[ChallengeFile])
	}
}

// No challenge (nil, or no usable host): no file, so Write removes a stale
// one. Never a catch-all: wildcard, IP and malformed names are dropped with
// a Problem.
func TestRenderChallengeAbsentAndHostFilter(t *testing.T) {
	for _, ch := range []*Challenge{nil, {EntryPoint: "web", Backend: "http://doorwarden:8089"}} {
		if f, _ := renderChallenge(t, ch); f[ChallengeFile] != nil {
			t.Fatalf("%+v: challenge file rendered", ch)
		}
	}
	f, probs := renderChallenge(t, &Challenge{EntryPoint: "web", Backend: "http://doorwarden:8089",
		Hosts: []string{"*.example.test", "192.0.2.1", "bad`host", "", "ok.example.test"}})
	if !strings.Contains(string(f[ChallengeFile]), "rule: Host(`ok.example.test`) && PathPrefix") {
		t.Fatalf("file:\n%s", f[ChallengeFile])
	}
	n := 0
	for _, p := range probs {
		if p.Kind == KindInvalidChallengeHost {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("problems: %v", probs)
	}
}

func TestRenderChallengeBadOptions(t *testing.T) {
	for _, ch := range []*Challenge{
		{EntryPoint: "we b", Backend: "http://doorwarden:8089", Hosts: []string{"example.test"}},
		{EntryPoint: "websecure", Backend: "http://doorwarden:8089", Hosts: []string{"example.test"}},
		{EntryPoint: "web", Backend: "ftp://doorwarden:8089", Hosts: []string{"example.test"}},
		{EntryPoint: "web", Backend: "http://doorwarden:8089/x", Hosts: []string{"example.test"}},
		{EntryPoint: "web", Backend: "http://u:p@doorwarden:8089", Hosts: []string{"example.test"}},
		{EntryPoint: "web", Backend: "", Hosts: []string{"example.test"}},
	} {
		if _, _, err := Render(nil, nil, nil, Options{Challenge: ch}); err == nil {
			t.Errorf("%+v accepted", ch)
		}
	}
}
