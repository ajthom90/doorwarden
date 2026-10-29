// Package providers blank-imports every real DNS provider so they register
// themselves. Add each new real provider here. The in-memory "fake"
// provider is deliberately not imported: it registers only in tests and the
// UI demo that import internal/dns/providers/fake directly, so the server
// binary rejects `type: fake` as an unknown provider type.
package providers

import (
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/adguard"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/cloudflare"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/pihole"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/rfc2136"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/route53"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/technitium"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/unifi"
)
