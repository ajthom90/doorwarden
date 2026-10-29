package model

import (
	"reflect"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func TestMerge(t *testing.T) {
	tests := []struct {
		name          string
		label, cfg, u Overrides
		want          Overrides
	}{
		{"empty", Overrides{}, Overrides{}, Overrides{}, Overrides{}},
		{"label only", Overrides{Port: ptr(80)}, Overrides{}, Overrides{}, Overrides{Port: ptr(80)}},
		{"cfg over label", Overrides{Port: ptr(80)}, Overrides{Port: ptr(81)}, Overrides{}, Overrides{Port: ptr(81)}},
		{"ui over all", Overrides{Port: ptr(80)}, Overrides{Port: ptr(81)}, Overrides{Port: ptr(82)}, Overrides{Port: ptr(82)}},
		{"explicit false overrides", Overrides{Websockets: ptr(true), Skip: ptr(true)}, Overrides{Websockets: ptr(false)}, Overrides{Skip: ptr(false)},
			Overrides{Websockets: ptr(false), Skip: ptr(false)}},
		{"explicit zero port", Overrides{Port: ptr(80)}, Overrides{}, Overrides{Port: ptr(0)}, Overrides{Port: ptr(0)}},
		{"empty slice overrides", Overrides{Middlewares: ptr([]string{"a"})}, Overrides{Middlewares: ptr([]string{})}, Overrides{}, Overrides{Middlewares: ptr([]string{})}},
		{"empty string overrides", Overrides{Rename: ptr("x")}, Overrides{}, Overrides{Rename: ptr("")}, Overrides{Rename: ptr("")}},
		{"per field mix", Overrides{Zone: ptr("a.test"), Scheme: ptr("http")}, Overrides{Scheme: ptr("https")}, Overrides{SkipVerify: ptr(true)},
			Overrides{Zone: ptr("a.test"), Scheme: ptr("https"), SkipVerify: ptr(true)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Merge(tt.label, tt.cfg, tt.u)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v want %+v", got, tt.want)
			}
		})
	}
}

func TestApply(t *testing.T) {
	base := Service{
		Name:    "web",
		Zone:    "example.test",
		Backend: Backend{Scheme: "http", Host: "192.0.2.10", Port: 80},
		Options: Options{Websockets: true, Middlewares: []string{"a"}},
	}
	got := Apply(base, Overrides{
		Name: ptr("web2"), Zone: ptr("lab.example.test"), Scheme: ptr("https"), Port: ptr(0), SkipVerify: ptr(true),
		Skip: ptr(true), Websockets: ptr(false), Middlewares: ptr([]string{}), Rename: ptr("r"),
	})
	want := Service{
		Name:    "web2",
		Zone:    "lab.example.test",
		Backend: Backend{Scheme: "https", Host: "192.0.2.10", Port: 0, SkipVerify: true},
		Options: Options{Skip: true, Websockets: false, Middlewares: []string{}, Rename: "r"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if same := Apply(base, Overrides{}); !reflect.DeepEqual(same, base) {
		t.Fatalf("empty overrides changed service: %+v", same)
	}
}
