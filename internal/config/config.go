// Package config loads and validates the doorwarden YAML configuration.
//
// Note: in flow-style mappings placeholders must be quoted ({k: "${V}"}),
// because braces are YAML syntax.
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
	Approval string `yaml:"approval"` // auto|approve|off
}

type DockerSource struct {
	Host     string `yaml:"host"`
	Approval string `yaml:"approval"` // auto|approve|off
}

type StaticService struct {
	Name     string `yaml:"name"`
	Host     string `yaml:"host"`
	Upstream string `yaml:"upstream"`
	Port     int    `yaml:"port"`
}

type Settings struct {
	DryRun       bool          `yaml:"dry_run"`
	GracePeriod  time.Duration `yaml:"grace_period"`
	PollInterval time.Duration `yaml:"poll_interval"`
	RenewBefore  time.Duration `yaml:"renew_before"`
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
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	var missing []string
	substituteNode(&root, env, &missing)
	if len(missing) > 0 {
		return nil, fmt.Errorf("config %s: unset environment variable(s) with no default: %s", path, strings.Join(missing, ", "))
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return nil, fmt.Errorf("re-encode config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil && err != io.EOF {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) applyDefaults() {
	for name, is := range c.Issuers {
		if is.Directory == "" {
			is.Directory = "staging"
			c.Issuers[name] = is
		}
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
