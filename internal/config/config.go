// Package config loads and validates the doorwarden YAML configuration.
//
// Note: in flow-style mappings placeholders must be quoted ({k: "${V}"}),
// because braces are YAML syntax.
//
// Placeholders under the top-level providers: and middlewares: keys always
// substitute as plain strings. A Traefik middleware option that is a bool or
// number and is written as a placeholder (sslRedirect: ${X}) therefore
// reaches the generated Traefik file as a quoted string ("true"); write such
// options literally if Traefik must see the typed value. Elsewhere an
// unquoted whole-value placeholder takes the bool/int/float type of its
// value.
package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Zones     []Zone                 `yaml:"zones"`
	Providers map[string]ProviderCfg `yaml:"providers"`
	Issuers   map[string]Issuer      `yaml:"issuers"`
	Sources   Sources                `yaml:"sources"`
	Static    []StaticService        `yaml:"static"`
	Settings  Settings               `yaml:"settings"`
	// Middlewares are Traefik middleware definitions, rendered verbatim
	// under http.middlewares: name -> {<one middleware type>: options}.
	Middlewares map[string]map[string]any `yaml:"middlewares"`
	Traefik     Traefik                   `yaml:"traefik"`
	// Notifications configures alert senders (see notify.go).
	Notifications Notifications `yaml:"notifications"`
	ACME          ACME          `yaml:"acme"`
	// Web configures API authentication (web.go).
	Web Web `yaml:"web"`
}

// MiddlewareDefs returns Middlewares as name -> definition (any), the shape
// model.ValidateMiddlewareDefs and the Traefik renderer take.
func (c *Config) MiddlewareDefs() map[string]any {
	out := make(map[string]any, len(c.Middlewares))
	for n, d := range c.Middlewares {
		out[n] = map[string]any(d)
	}
	return out
}

// Traefik configures the file-provider writer.
type Traefik struct {
	// DynamicDir is Traefik's watched file-provider directory (default
	// /etc/traefik/dynamic).
	DynamicDir string `yaml:"dynamic_dir"`
	// EntryPoint every router listens on (default websecure).
	EntryPoint string `yaml:"entry_point"`
	// CertPathPrefix is where Traefik sees doorwarden's certificate
	// directory (default /certs).
	CertPathPrefix string `yaml:"cert_path_prefix"`
	// ExternalMiddlewares allowlists qualified references (name@provider)
	// to middlewares defined outside doorwarden (e.g. crowdsec@docker).
	ExternalMiddlewares []string `yaml:"external_middlewares"`
	// FileMode is the permission of the rendered dynamic files: "0600"
	// (default; Traefik runs as the same UID) or "0640" (Traefik reads
	// through a dedicated shared group). The files can hold middleware
	// secrets.
	FileMode string `yaml:"file_mode"`
	// TraefikTLS: tls_min_version, sni_strict, serve_expired (tls.go).
	TraefikTLS `yaml:",inline"`
}

type Zone struct {
	Name        string      `yaml:"name"`
	TargetIP    string      `yaml:"target_ip"`
	Records     Records     `yaml:"records"`
	Certificate Certificate `yaml:"certificate"`
}

type Records struct {
	Provider string `yaml:"provider"`
	Mode     string `yaml:"mode"` // wildcard|per-host|off
}

type Certificate struct {
	Issuer      string `yaml:"issuer"`
	Strategy    string `yaml:"strategy"`  // wildcard|per-host|san
	Challenge   string `yaml:"challenge"` // dns-01|http-01
	DNSProvider string `yaml:"dns_provider"`
}

// ProviderCfg holds a provider's type plus arbitrary provider-specific settings.
// Secret-like values remain plain strings for now.
type ProviderCfg struct {
	Type  string         `yaml:"type"`
	Extra map[string]any `yaml:",inline"`
}

type Issuer struct {
	Directory string `yaml:"directory"` // letsencrypt|staging|production|URL
	Email     string `yaml:"email"`
	EABKid    string `yaml:"eab_kid"`
	EABHMAC   string `yaml:"eab_hmac"`
}

type Sources struct {
	TrueNAS *TrueNASSource `yaml:"truenas"`
	Docker  *DockerSource  `yaml:"docker"`
}

type TrueNASSource struct {
	URL      string `yaml:"url"`
	APIKey   string `yaml:"api_key"`
	Approval string `yaml:"approval"` // auto|approve|off; default approve
}

type DockerSource struct {
	Host     string `yaml:"host"`
	Approval string `yaml:"approval"` // auto|approve|off; default auto
}

// StaticService is a statically configured service. Without ID the service
// key derives from the name, so renaming such a service changes its key.
type StaticService struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Host        string   `yaml:"host"`
	Upstream    string   `yaml:"upstream"`
	Port        int      `yaml:"port"`
	Scheme      string   `yaml:"scheme"`
	Zone        string   `yaml:"zone"`
	SkipVerify  bool     `yaml:"skip_verify"`
	Websockets  bool     `yaml:"websockets"`
	Middlewares []string `yaml:"middlewares"`
	Rename      string   `yaml:"rename"`
	Skip        bool     `yaml:"skip"`
}

type Settings struct {
	DryRun       bool          `yaml:"dry_run"`
	GracePeriod  time.Duration `yaml:"grace_period"`
	PollInterval time.Duration `yaml:"poll_interval"`
	RenewBefore  time.Duration `yaml:"renew_before"`
	// DefaultZone is the zone for services that name none. Unset with exactly
	// one zone configured means that zone; unset with several means such
	// services are invalid.
	DefaultZone string `yaml:"default_zone"`
}

// Load reads path, substitutes environment variables, decodes strictly
// (unknown keys are errors) and applies defaults.
func Load(path string, env func(string) (string, bool)) (*Config, error) {
	if env == nil {
		env = os.LookupEnv
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return parse(raw, path, env)
}

// Parse is Load on the file's contents: substitute, decode strictly, apply
// defaults. It does not Validate.
func Parse(raw []byte, env func(string) (string, bool)) (*Config, error) {
	if env == nil {
		env = os.LookupEnv
	}
	return parse(raw, "(document)", env)
}

func parse(raw []byte, path string, env func(string) (string, bool)) (*Config, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := RejectMergeKeys(&root); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	var missing []string
	substituteNode(&root, env, &missing)
	if len(missing) > 0 {
		return nil, fmt.Errorf("config %s: unset environment variable(s) with no default: %s", path, strings.Join(missing, ", "))
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return nil, fmt.Errorf("re-encode config %s: %w", path, ScrubEnvValues(err, raw, env))
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil && err != io.EOF {
		// The decoder quotes (a prefix of) the offending scalar, which may
		// be or contain a substituted env value: describeDecodeError never
		// quotes a scalar, and the scrub stays as defence in depth.
		return nil, fmt.Errorf("parse config %s: %w", path, ScrubEnvValues(describeDecodeError(err, out, &root), raw, env))
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) applyDefaults() {
	c.Notifications.applyDefaults()
	c.Web.applyDefaults()
	for name, is := range c.Issuers {
		if is.Directory == "" {
			is.Directory = "staging"
			c.Issuers[name] = is
		}
	}
	if c.Traefik.DynamicDir == "" {
		c.Traefik.DynamicDir = "/etc/traefik/dynamic"
	}
	if c.Traefik.EntryPoint == "" {
		c.Traefik.EntryPoint = "websecure"
	}
	if c.Traefik.CertPathPrefix == "" {
		c.Traefik.CertPathPrefix = "/certs"
	}
	c.Traefik.TraefikTLS.applyDefaults()
	// TrueNAS apps have no opt-in of their own: an unset approval fails
	// closed (every app waits for approval). Docker opts in per container
	// with labels, so its unset approval stays auto.
	if c.Sources.TrueNAS != nil && c.Sources.TrueNAS.Approval == "" {
		c.Sources.TrueNAS.Approval = "approve"
	}
	if c.Settings.GracePeriod == 0 {
		c.Settings.GracePeriod = 24 * time.Hour
	}
	if c.Settings.PollInterval == 0 {
		c.Settings.PollInterval = 30 * time.Second
	}
	if c.Settings.RenewBefore == 0 {
		c.Settings.RenewBefore = 720 * time.Hour
	}
}
