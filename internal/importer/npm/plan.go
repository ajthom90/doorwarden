package npm

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
	"gopkg.in/yaml.v3"
)

// Class says how a proxy host maps onto Doorwarden.
type Class string

const (
	ClassAuto   Class = "auto"   // matches a discovered TrueNAS app backend
	ClassLabel  Class = "label"  // matches a discovered Docker container
	ClassStatic Class = "static" // needs a static: entry
)

// Mapping is the classification of one domain of one NPM proxy host.
type Mapping struct {
	Domain          string
	ForwardTo       string
	Class           Class
	Reason          string
	Flags           []string
	SuggestedStatic *config.StaticService
	MatchedService  string
	// Skipped is non-empty when no paste-ready entry may be emitted for this
	// static host; --yaml prints it as a comment instead.
	Skipped string
}

// clean replaces control characters (C0/C1, ESC, newlines, tabs), Unicode
// format/bidi characters (Cf, zero-width, RLO etc.) and line/paragraph
// separators with '?', so untrusted NPM text can
// neither break out of a YAML comment nor inject terminal escape sequences.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
			(r >= 0x200b && r <= 0x200f) || r == 0xfeff {
			return '?'
		}
		return r
	}, s)
}

// DiscoveredService is one entry of the --discovered JSON file: a JSON array
// of {"key":"truenas:myapp","name":"myapp","host":"192.0.2.10","port":8080}.
// Keys starting "truenas:" classify as auto, "docker:" as label.
type DiscoveredService struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// LoadDiscovered reads a --discovered file.
func LoadDiscovered(path string) ([]model.Service, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var in []DiscoveredService
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("parse discovered services %s: %w", path, err)
	}
	out := make([]model.Service, 0, len(in))
	for _, d := range in {
		out = append(out, model.Service{Key: d.Key, Name: d.Name, Source: strings.SplitN(d.Key, ":", 2)[0],
			Backend: model.Backend{Scheme: "http", Host: d.Host, Port: d.Port}})
	}
	return out, nil
}

func normZone(z string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".") }

// zoneOf returns the longest configured zone containing domain.
func zoneOf(domain string, cfg *config.Config) (string, bool) {
	if cfg == nil {
		return "", false
	}
	best := ""
	for _, z := range cfg.Zones {
		n := normZone(z.Name)
		if n != "" && (domain == n || strings.HasSuffix(domain, "."+n)) && len(n) > len(best) {
			best = n
		}
	}
	return best, best != ""
}

func hostPort(scheme, host string, port int) string {
	return scheme + "://" + net.JoinHostPort(model.UnbracketHost(host), strconv.Itoa(port))
}

func sameHost(a, b string) bool {
	return strings.EqualFold(model.UnbracketHost(a), model.UnbracketHost(b))
}

// Plan classifies every domain of every proxy host. It performs no DNS
// lookups: hostname upstreams are judged textually.
func Plan(snap *Snapshot, discovered []model.Service, cfg *config.Config) []Mapping {
	certs := map[int]Certificate{}
	for _, c := range snap.Certificates {
		certs[c.ID] = c
	}
	targetIPs := map[string]bool{}
	if cfg != nil {
		for _, z := range cfg.Zones {
			if z.TargetIP != "" {
				targetIPs[z.TargetIP] = true
			}
		}
	}
	var out []Mapping
	for _, h := range snap.ProxyHosts {
		for _, dom := range h.Domains {
			out = append(out, planOne(h, dom, certs, discovered, cfg, targetIPs))
		}
	}
	return out
}

func planOne(h ProxyHost, dom string, certs map[int]Certificate, discovered []model.Service, cfg *config.Config, targetIPs map[string]bool) Mapping {
	scheme := strings.ToLower(h.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	m := Mapping{Domain: dom, ForwardTo: hostPort(scheme, h.Host, h.Port), Class: ClassStatic, Reason: "no discovered backend matches the forward target"}
	flag := func(f string, a ...any) { m.Flags = append(m.Flags, fmt.Sprintf(f, a...)) }

	for _, s := range discovered {
		if s.Backend.Port == h.Port && sameHost(s.Backend.Host, h.Host) {
			switch {
			case strings.HasPrefix(s.Key, "truenas:"):
				m.MatchedService = s.Key
				m.Class, m.Reason = ClassAuto, "forward target matches discovered TrueNAS app "+s.Name
			case strings.HasPrefix(s.Key, "docker:"):
				m.MatchedService = s.Key
				m.Class, m.Reason = ClassLabel, "forward target matches discovered Docker container "+s.Name+"; add doorwarden.* labels"
			default:
				continue
			}
			break
		}
	}

	if h.AdvancedConfigLen > 0 {
		// Refused: never auto/label, never a suggestion.
		m.Class, m.MatchedService = ClassStatic, ""
		m.Reason = "custom nginx config present: refused, review manually"
	}
	host := model.UnbracketHost(h.Host)
	ip := net.ParseIP(host)
	if ip == nil {
		flag("hostname upstream: verify")
	} else {
		if ip.IsLoopback() {
			flag("loopback upstream: not reachable from Doorwarden's network")
		} else if len(targetIPs) > 0 && !targetIPs[ip.String()] {
			flag("off-box upstream IP")
		}
	}
	if !h.Enabled {
		flag("disabled in NPM")
	}
	if h.AdvancedConfigLen > 0 {
		flag("custom nginx config present (%d bytes): REFUSED, not translated, review manually", h.AdvancedConfigLen)
	}
	if h.AccessListID != 0 {
		flag("access list attached (id %d): re-create as a Doorwarden middleware", h.AccessListID)
	}
	if !h.SSLForced {
		flag("ssl_forced off: plain HTTP was also served; Doorwarden redirects HTTP to HTTPS")
	}
	if scheme == "https" {
		flag("https upstream: NPM does not verify upstream certificates; skip_verify suggested")
	}
	if h.Websockets {
		flag("websockets")
	}
	if c, ok := certs[h.CertificateID]; ok && h.CertificateID != 0 {
		if !c.IsWildcard {
			flag("per-host certificate %q (non-wildcard)", c.NiceName)
		}
		for _, cd := range c.Domains {
			if _, in := zoneOf(strings.TrimPrefix(cd, "*."), cfg); !in && cfg != nil {
				flag("certificate covers %s outside configured zones", cd)
			}
		}
	}

	zone, inZone := zoneOf(dom, cfg)
	if !inZone {
		flag("domain outside configured zones - no zone")
	}
	if m.Class == ClassStatic {
		switch {
		case h.AdvancedConfigLen > 0:
			m.Skipped = "custom nginx config present - refused, review manually"
		case h.AccessListID != 0:
			m.Skipped = "NPM access list attached - recreate the restriction (middleware) first"
		case !h.Enabled:
			m.Skipped = "disabled in NPM"
		}
	}
	if m.Class == ClassStatic && inZone && m.Skipped == "" {
		m.SuggestedStatic = suggest(&m, h, dom, zone, scheme, host)
	}
	return m
}

func suggest(m *Mapping, h ProxyHost, dom, zone, scheme, host string) *config.StaticService {
	label := strings.TrimSuffix(dom, "."+zone)
	if dom == zone || strings.Contains(label, ".") || strings.HasPrefix(label, "*") {
		m.Flags = append(m.Flags, "hostname is not a single label under the zone: no static entry suggested")
		return nil
	}
	if slug, err := model.Slug(label); err != nil || slug != label {
		m.Flags = append(m.Flags, "label is not a valid DNS slug: no static entry suggested")
		return nil
	}
	s := &config.StaticService{ID: label, Name: label, Host: host, Port: h.Port, Scheme: scheme,
		Zone: zone, Websockets: h.Websockets, SkipVerify: scheme == "https"}
	if p := s.Problems(); len(p) > 0 {
		m.Flags = append(m.Flags, "forward target not usable as a static entry: "+strings.Join(p, "; "))
		return nil
	}
	return s
}

// Notes returns global observations not tied to one host (streams, access
// lists, redirections, dead hosts).
func Notes(snap *Snapshot) []string {
	var n []string
	add := func(c int, what string) {
		if c > 0 {
			n = append(n, fmt.Sprintf("%d %s present in NPM: not imported, handle manually", c, what))
		}
	}
	add(snap.Streams, "stream(s) (raw TCP/UDP forwards; Traefik routes here are HTTP only)")
	add(snap.AccessLists, "access list(s)")
	add(snap.Redirections, "redirection host(s)")
	add(snap.DeadHosts, "404/dead host(s)")
	return n
}

// Render writes the human table: Domain | Class | Target | Flags.
func Render(w io.Writer, ms []Mapping) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DOMAIN\tCLASS\tTARGET\tFLAGS")
	for _, m := range ms {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", clean(m.Domain), m.Class, clean(m.ForwardTo), clean(strings.Join(m.Flags, "; ")))
	}
	tw.Flush()
}

type yamlEntry struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	Scheme     string `yaml:"scheme"`
	Zone       string `yaml:"zone"`
	SkipVerify bool   `yaml:"skip_verify,omitempty"`
	Websockets bool   `yaml:"websockets,omitempty"`
}

// RenderYAML emits only the suggested static entries as a `static:` list,
// ready to paste into the config file.
func RenderYAML(w io.Writer, ms []Mapping) error {
	var entries []yamlEntry
	seen := map[string]bool{}
	for _, m := range ms {
		s := m.SuggestedStatic
		if s == nil || seen[s.ID+"@"+s.Zone] {
			continue
		}
		seen[s.ID+"@"+s.Zone] = true
		entries = append(entries, yamlEntry{s.ID, s.Name, s.Host, s.Port, s.Scheme, s.Zone, s.SkipVerify, s.Websockets})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, m := range ms {
		if m.Skipped != "" && m.Class == ClassStatic {
			if _, err := fmt.Fprintf(w, "# SKIPPED %s: %s\n", clean(m.Domain), clean(m.Skipped)); err != nil {
				return err
			}
		}
	}
	if len(entries) == 0 {
		_, err := fmt.Fprintln(w, "# no static entries suggested")
		return err
	}
	b, err := yaml.Marshal(map[string][]yamlEntry{"static": entries})
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// CertGuidance describes where NPM wildcard certificates live and how
// `doorwarden certs import-npm` imports them (every NPM certificate in
// live/, wildcards included, so the cutover needs no re-issuance).
func CertGuidance(snap *Snapshot) string {
	var b strings.Builder
	for _, c := range snap.Certificates {
		if !c.IsWildcard {
			continue
		}
		fmt.Fprintf(&b, "wildcard certificate %q (%s), expires %s\n  files: /etc/letsencrypt/live/npm-%d/ inside NPM\n  import: doorwarden certs import-npm -npm-dir <npm-letsencrypt>/live/npm-%d\n",
			clean(c.NiceName), clean(strings.Join(c.Domains, ", ")), clean(c.ExpiresOn), c.ID, c.ID)
	}
	if b.Len() == 0 {
		return "no wildcard certificates in NPM\n"
	}
	b.WriteString("  (<npm-letsencrypt> is the host directory NPM mounts at /etc/letsencrypt; -npm-dir <npm-letsencrypt> imports every NPM certificate; add -dry-run to check first)\n")
	return b.String()
}
