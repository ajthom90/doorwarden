package model

import (
	"errors"
	"testing"
)

func TestParseMiddlewareRef(t *testing.T) {
	ok := map[string][2]string{
		"auth":           {"auth", ""},
		"auth@file":      {"auth", "file"},
		"x_y.z-1@docker": {"x_y.z-1", "docker"},
		"noop@internal":  {"noop", "internal"},
	}
	for ref, want := range ok {
		n, p, err := ParseMiddlewareRef(ref)
		if err != nil || n != want[0] || p != want[1] {
			t.Errorf("%q: got %q %q %v", ref, n, p, err)
		}
	}
	for _, ref := range []string{"", "@file", "auth@", "a@b@c", "a b", "a/b", "a`b", "a\nb", "a:b", "a@fi le", "ä"} {
		if _, _, err := ParseMiddlewareRef(ref); !errors.Is(err, ErrInvalidMiddlewareRef) {
			t.Errorf("%q: want ErrInvalidMiddlewareRef, got %v", ref, err)
		}
	}
}

func TestValidMiddlewareName(t *testing.T) {
	for _, n := range []string{"auth", "A_b.c-1"} {
		if !ValidMiddlewareName(n) {
			t.Errorf("%q rejected", n)
		}
	}
	for _, n := range []string{"", "auth@file", "a b", "a/b", "a:b"} {
		if ValidMiddlewareName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestValidateMiddlewareDef(t *testing.T) {
	good := []any{
		map[string]any{"basicAuth": map[string]any{"users": []any{"u:h"}}},
		map[string]any{"headers": map[string]any{}},
		map[string]any{"forwardAuth": map[any]any{"address": "http://192.0.2.1"}},
	}
	for _, d := range good {
		if err := ValidateMiddlewareDef(d); err != nil {
			t.Errorf("%v: %v", d, err)
		}
	}
	bad := []any{
		nil,
		"basicAuth",
		map[string]any{},
		map[string]any{"basicAuth": map[string]any{}, "headers": map[string]any{}},
		map[string]any{"basicAuth": "users"},
		map[string]any{"basicAuth": nil},
		map[string]any{"basic auth": map[string]any{}},
		map[any]any{1: map[string]any{}},
	}
	for _, d := range bad {
		if err := ValidateMiddlewareDef(d); err == nil {
			t.Errorf("%#v accepted", d)
		}
	}
}

func TestCheckMiddlewareRef(t *testing.T) {
	defs := map[string]bool{"auth": true}
	defined := func(n string) bool { return defs[n] }
	ext := []string{"crowdsec@docker", "noop@internal", "hand@file"}
	for _, ref := range []string{"auth", "auth@file", "crowdsec@docker", "noop@internal", "hand@file", "hand"} {
		if err := CheckMiddlewareRef(ref, defined, ext); err != nil {
			t.Errorf("%q: %v", ref, err)
		}
	}
	for _, ref := range []string{"missing", "missing@file", "auth@docker", "crowdsec", "crowdsec@file", "x@internal"} {
		if err := CheckMiddlewareRef(ref, defined, ext); !errors.Is(err, ErrUndefinedMiddleware) {
			t.Errorf("%q: want ErrUndefinedMiddleware, got %v", ref, err)
		}
	}
	if err := CheckMiddlewareRef("a b", defined, ext); !errors.Is(err, ErrInvalidMiddlewareRef) {
		t.Errorf("bad charset: %v", err)
	}
}

func TestValidateExternalMiddleware(t *testing.T) {
	for _, r := range []string{"crowdsec@docker", "hand@file"} {
		if err := ValidateExternalMiddleware(r); err != nil {
			t.Errorf("%q: %v", r, err)
		}
	}
	for _, r := range []string{"crowdsec", "", "a b@docker"} {
		if err := ValidateExternalMiddleware(r); err == nil {
			t.Errorf("%q accepted", r)
		}
	}
}
