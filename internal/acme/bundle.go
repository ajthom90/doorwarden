package acme

import (
	"fmt"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Bundle is an issued or imported certificate. Key is a secrets.Secret and
// never appears in fmt, JSON, YAML or slog output; String and GoString omit
// it as well.
type Bundle struct {
	ID       string
	Zone     string
	Names    []string
	Issuer   string
	Staging  bool
	Managed  bool
	NotAfter time.Time
	// Dir is the certificate directory relative to the certs root ("<id>");
	// the files are Dir/fullchain.pem and Dir/privkey.pem.
	Dir string
	// ChainPEM is the leaf followed by its intermediates.
	ChainPEM []byte
	// Key is the PEM private key. Read it only with Key.Reveal().
	Key secrets.Secret
}

// String describes the bundle without key material.
func (b *Bundle) String() string {
	if b == nil {
		return "<nil bundle>"
	}
	return fmt.Sprintf("cert %s zone=%s names=[%s] issuer=%s staging=%t managed=%t not_after=%s key=[redacted]",
		b.ID, b.Zone, strings.Join(b.Names, ","), b.Issuer, b.Staging, b.Managed, b.NotAfter.UTC().Format(time.RFC3339))
}

// GoString is String (so %#v never reaches the key either).
func (b *Bundle) GoString() string { return b.String() }
