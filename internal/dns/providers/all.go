// Package providers blank-imports every DNS provider so they register
// themselves. Add each new real provider here.
package providers

import (
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/cloudflare"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers/fake"
)
