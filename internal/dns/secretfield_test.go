package dns_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

type mapResolver map[string]string

func (m mapResolver) Resolve(ref string) (secrets.Secret, error) {
	v, ok := m[ref]
	if !ok {
		return "", errors.New("no such secret")
	}
	return secrets.Secret(v), nil
}

func TestResolveField(t *testing.T) {
	sr := mapResolver{"tok": "s3cret-value"}
	cases := []struct {
		name    string
		cfg     map[string]any
		sr      dns.SecretResolver
		want    string
		wantErr string
	}{
		{"missing", map[string]any{}, sr, "", `"k"`},
		{"nil value", map[string]any{"k": nil}, sr, "", `"k"`},
		{"empty", map[string]any{"k": ""}, sr, "", `"k"`},
		{"non-string", map[string]any{"k": 5}, sr, "", `"k"`},
		{"literal", map[string]any{"k": "plain"}, sr, "plain", ""},
		{"literal nil resolver", map[string]any{"k": "plain"}, nil, "plain", ""},
		{"ref", map[string]any{"k": "secret:tok"}, sr, "s3cret-value", ""},
		{"ref nil resolver", map[string]any{"k": "secret:tok"}, nil, "", `"k"`},
		{"ref unknown", map[string]any{"k": "secret:zzz"}, sr, "", `"k"`},
		{"ref empty", map[string]any{"k": "secret:"}, sr, "", `"k"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := dns.ResolveField(c.cfg, c.sr, "k")
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v", err)
				}
				if strings.Contains(err.Error(), "s3cret-value") {
					t.Fatal("secret leaked in error")
				}
				return
			}
			if err != nil || got.Reveal() != c.want {
				t.Fatalf("got %q err %v", got.Reveal(), err)
			}
		})
	}
}
