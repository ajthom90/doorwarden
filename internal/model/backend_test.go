package model

import (
	"errors"
	"testing"
)

func TestValidHost(t *testing.T) {
	ok := []string{"app", "app.example.test", "a-b_c.example.test", "198.51.100.5", "2001:db8::1",
		"[2001:db8::1]", "::1", "localhost"}
	bad := []string{"", " app", "app ", "a b", "app\n", "a/b", "user@app", "app:8080", "198.51.100.5:80",
		"[198.51.100.5]", "[app]", "-app", "app-", "a..b", "http://app", "[2001:db8::1]:80",
		string(make([]byte, 254))}
	for _, h := range ok {
		if !ValidHost(h) {
			t.Errorf("ValidHost(%q) = false", h)
		}
	}
	for _, h := range bad {
		if ValidHost(h) {
			t.Errorf("ValidHost(%q) = true", h)
		}
	}
}

func TestValidateBackend(t *testing.T) {
	good := []Backend{
		{Scheme: "http", Host: "198.51.100.5", Port: 80},
		{Scheme: "https", Host: "app", Port: 65535, SkipVerify: true},
		{Scheme: "http", Host: "2001:db8::1", Port: 1},
	}
	for _, b := range good {
		if err := ValidateBackend(b); err != nil {
			t.Errorf("%+v: %v", b, err)
		}
	}
	bad := []Backend{
		{},
		{Scheme: "", Host: "app", Port: 80},
		{Scheme: "h2c", Host: "app", Port: 80},
		{Scheme: "HTTP", Host: "app", Port: 80},
		{Scheme: "http", Host: "", Port: 80},
		{Scheme: "http", Host: "app", Port: 0},
		{Scheme: "http", Host: "app", Port: 70000},
		{Scheme: "http", Host: "app", Port: -1},
		{Scheme: "http", Host: "a b", Port: 80},
		{Scheme: "http", Host: "app:80", Port: 80},
	}
	for _, b := range bad {
		if err := ValidateBackend(b); err == nil {
			t.Errorf("%+v accepted", b)
		} else if !errors.Is(err, ErrInvalidBackend) {
			t.Errorf("%+v: not ErrInvalidBackend: %v", b, err)
		}
	}
}
