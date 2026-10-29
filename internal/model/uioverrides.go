package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// UIOverrides are the overrides an operator sets in the UI, stored as JSON
// in services.overrides_json. They are the top layer of model.Merge's
// precedence (ui > config > label). Deliberately absent: middlewares (an
// operator cannot drop an auth middleware from the UI; that stays in
// labels and config) and the backend host.
type UIOverrides struct {
	// Skip true unpublishes the service; false publishes it even if a label
	// or the config skips it.
	Skip *bool `json:"skip,omitempty"`
	// Rename is the hostname label (a lowercase DNS label).
	Rename *string `json:"rename,omitempty"`
	// Port replaces the backend port.
	Port *int `json:"port,omitempty"`
	// SkipVerify skips TLS verification of an https backend (self-signed
	// TrueNAS apps).
	SkipVerify *bool `json:"skip_verify,omitempty"`
}

// OverrideError is an invalid override (safe to show to the operator).
type OverrideError struct{ Msg string }

func (e *OverrideError) Error() string { return "invalid override: " + e.Msg }

// Empty reports whether no override is set.
func (o UIOverrides) Empty() bool {
	return o.Skip == nil && o.Rename == nil && o.Port == nil && o.SkipVerify == nil
}

// ParseUIOverrides decodes stored overrides strictly (unknown fields and
// trailing data are errors). "" and "{}" are empty.
func ParseUIOverrides(s string) (UIOverrides, error) {
	var o UIOverrides
	if s == "" {
		return o, nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return UIOverrides{}, fmt.Errorf("overrides: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return UIOverrides{}, errors.New("overrides: trailing data")
	}
	return o, nil
}

// JSON encodes o for storage.
func (o UIOverrides) JSON() (string, error) {
	b, err := json.Marshal(o)
	return string(b), err
}

// Overrides converts o to a Merge layer.
func (o UIOverrides) Overrides() Overrides {
	return Overrides{Skip: o.Skip, Rename: o.Rename, Port: o.Port, SkipVerify: o.SkipVerify}
}

// ApplyUI applies o to svc.
func ApplyUI(svc Service, o UIOverrides) Service { return Apply(svc, o.Overrides()) }

// Validate checks o against the service it applies to: rename must be a
// lowercase DNS label giving a valid hostname, the resulting backend must
// pass ValidateBackend, and skip_verify is only for https backends.
func (o UIOverrides) Validate(svc Service, zones []string, defaultZone string) error {
	if o.Rename != nil {
		r := *o.Rename
		if sl, err := Slug(r); err != nil || sl != r {
			return &OverrideError{Msg: fmt.Sprintf("rename %q must be a lowercase DNS label (a-z, 0-9, -; at most 63 characters)", r)}
		}
	}
	if o.Port != nil && (*o.Port < 1 || *o.Port > 65535) {
		return &OverrideError{Msg: fmt.Sprintf("port %d out of range 1..65535", *o.Port)}
	}
	got := ApplyUI(svc, o)
	if o.SkipVerify != nil && *o.SkipVerify && got.Backend.Scheme != "https" {
		return &OverrideError{Msg: "skip_verify applies only to https backends"}
	}
	if o.Port != nil || o.SkipVerify != nil {
		if err := ValidateBackend(got.Backend); err != nil {
			return &OverrideError{Msg: err.Error()}
		}
	}
	if o.Rename != nil {
		if _, err := Hostname(got, zones, defaultZone); err != nil {
			return &OverrideError{Msg: err.Error()}
		}
	}
	return nil
}
