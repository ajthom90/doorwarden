// Package providers blank-imports every DNS provider so they register
// themselves. Add each new real provider here.
package providers

import (
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/cloudflare"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/fake"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/rfc2136"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/route53"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/technitium"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/unifi"
)
