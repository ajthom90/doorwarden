package dns

import (
	"fmt"
	"log/slog"
)

const redactedText = "[redacted]"

// Redacted is embedded in the small struct a provider keeps its credential
// material in. Provider structs hold that struct by pointer (a field such as
// `cr *creds`), so even a dereferenced copy of the provider formatted with %v,
// %+v or %#v prints only a pointer, and the credential struct itself prints as
// "[redacted]" through every common formatting path.
type Redacted struct{}

// String implements fmt.Stringer.
func (Redacted) String() string { return redactedText }

// GoString implements fmt.GoStringer.
func (Redacted) GoString() string { return redactedText }

// Format implements fmt.Formatter so every verb prints the redaction.
func (Redacted) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redactedText)) }

// MarshalJSON implements json.Marshaler.
func (Redacted) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedText + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (Redacted) MarshalText() ([]byte, error) { return []byte(redactedText), nil }

// LogValue implements slog.LogValuer.
func (Redacted) LogValue() slog.Value { return slog.StringValue(redactedText) }
