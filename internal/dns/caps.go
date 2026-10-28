package dns

import "github.com/ajthom90/doorwarden/internal/config"

// ConfigCaps adapts the registry to the capability lookup that
// config.Config.Validate expects. dns imports config; config must not import dns.
func ConfigCaps() func(providerType string) (config.Capabilities, bool) {
	return func(typ string) (config.Capabilities, bool) {
		c, ok := CapsFor(typ)
		if !ok {
			return config.Capabilities{}, false
		}
		return config.Capabilities{WildcardA: c.WildcardA}, true
	}
}
