package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	fakeKey   = "fake-master-key-0123456789abcdef"
	fakeOther = "other-fake-master-key-0123456789"
	plain     = "fake-plaintext-value-XYZZY"
)

func mustBox(t *testing.T, key string) *Box {
	t.Helper()
	b, err := NewBox(key)
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	return b
}

func TestRoundtrip(t *testing.T) {
	b := mustBox(t, fakeKey)
	sealed, err := b.Seal([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(plain)) {
		t.Fatal("sealed contains plaintext")
	}
	got, err := b.Open(sealed)
	if err != nil || string(got) != plain {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestEmptyPlaintext(t *testing.T) {
	b := mustBox(t, fakeKey)
	sealed, err := b.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Open(sealed)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSealsDiffer(t *testing.T) {
	b := mustBox(t, fakeKey)
	a, _ := b.Seal([]byte(plain))
	c, _ := b.Seal([]byte(plain))
	if bytes.Equal(a, c) {
		t.Fatal("two seals identical")
	}
}

func TestWrongKey(t *testing.T) {
	sealed, _ := mustBox(t, fakeKey).Seal([]byte(plain))
	_, err := mustBox(t, fakeOther).Open(sealed)
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestTampered(t *testing.T) {
	b := mustBox(t, fakeKey)
	sealed, _ := b.Seal([]byte(plain))
	for i := range sealed {
		c := append([]byte(nil), sealed...)
		c[i] ^= 0x01
		if _, err := b.Open(c); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("byte %d: want ErrDecrypt, got %v", i, err)
		}
	}
}

func TestTruncatedAndGarbage(t *testing.T) {
	b := mustBox(t, fakeKey)
	sealed, _ := b.Seal([]byte(plain))
	for n := 0; n < len(sealed); n++ {
		if _, err := b.Open(sealed[:n]); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("len %d: want ErrDecrypt, got %v", n, err)
		}
	}
	if _, err := b.Open(nil); !errors.Is(err, ErrDecrypt) {
		t.Fatal("nil input")
	}
}

func TestBadMasterKey(t *testing.T) {
	for _, k := range []string{"", "short", "123456789012345"} {
		if _, err := NewBox(k); err == nil {
			t.Fatalf("key %q accepted", k)
		}
	}
	if _, err := NewBox("1234567890123456"); err != nil {
		t.Fatalf("16-byte key rejected: %v", err)
	}
}

func TestReveal(t *testing.T) {
	if Secret(plain).Reveal() != plain {
		t.Fatal("reveal")
	}
}

func TestFormatRedacts(t *testing.T) {
	s := Secret(plain)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10s"} {
		for _, arg := range []any{s, &s, struct{ S Secret }{s}, []Secret{s}, map[string]Secret{"k": s}} {
			out := fmt.Sprintf(verb, arg)
			if strings.Contains(out, plain) || strings.Contains(out, fmt.Sprintf("%x", plain)) {
				t.Fatalf("%s leaked: %s", verb, out)
			}
		}
	}
	if s.String() != "[redacted]" || s.GoString() != "[redacted]" {
		t.Fatal("String/GoString")
	}
	if fmt.Sprintf("%v", s) != "[redacted]" {
		t.Fatalf("got %q", fmt.Sprintf("%v", s))
	}
}

func TestSlogRedacts(t *testing.T) {
	s := Secret(plain)
	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer
		l := slog.New(mk(&buf))
		l.Info("msg", "token", s, slog.Any("p", &s), slog.Group("g", "t", s))
		out := buf.String()
		if strings.Contains(out, plain) {
			t.Fatalf("%s leaked: %s", name, out)
		}
		if !strings.Contains(out, "[redacted]") {
			t.Fatalf("%s missing redaction: %s", name, out)
		}
	}
}

type holder struct {
	Name  string `json:"name" yaml:"name"`
	Token Secret `json:"token" yaml:"token"`
}

func TestMarshalRedacts(t *testing.T) {
	h := holder{"n", Secret(plain)}
	j, err := json.Marshal(h)
	if err != nil || strings.Contains(string(j), plain) || !strings.Contains(string(j), "[redacted]") {
		t.Fatalf("json: %s %v", j, err)
	}
	jp, _ := json.Marshal(&h)
	if strings.Contains(string(jp), plain) {
		t.Fatal("json ptr leak")
	}
	y, err := yaml.Marshal(h)
	if err != nil || strings.Contains(string(y), plain) || !strings.Contains(string(y), "[redacted]") {
		t.Fatalf("yaml: %s %v", y, err)
	}
	m, _ := json.Marshal(map[Secret]int{Secret("k"): 1})
	_ = m
	tx, err := Secret(plain).MarshalText()
	if err != nil || string(tx) != "[redacted]" {
		t.Fatalf("text: %s %v", tx, err)
	}
}
