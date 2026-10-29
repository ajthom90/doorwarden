package model

import (
	"strings"
	"testing"
)

func TestSlug(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"mixed", "My_App.v2", "my-app-v2", false},
		{"upper", "GRAFANA", "grafana", false},
		{"leading digit", "1password", "1password", false},
		{"trim hyphens", "--web--", "web", false},
		{"collapse", "a___b...c", "a-b-c", false},
		{"unicode dropped", "café-app", "caf-app", false},
		{"empty", "", "", true},
		{"all invalid", "___...", "", true},
		{"only unicode", "日本", "", true},
		{"truncate", strings.Repeat("a", 70), strings.Repeat("a", 63), false},
		{"truncate trims hyphen", strings.Repeat("a", 62) + "-bbb", strings.Repeat("a", 62), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Slug(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestHostname(t *testing.T) {
	zones := []string{"Example.Test.", "lab.example.test"}
	tests := []struct {
		name    string
		svc     Service
		def     string
		want    string
		wantErr bool
	}{
		{"default zone", Service{Name: "My_App.v2"}, "example.test", "my-app-v2.example.test", false},
		{"svc zone wins", Service{Name: "web", Zone: "LAB.example.test."}, "example.test", "web.lab.example.test", false},
		{"default normalized", Service{Name: "web"}, "EXAMPLE.TEST.", "web.example.test", false},
		{"rename wins", Service{Name: "web", Options: Options{Rename: "Photos_2"}}, "example.test", "photos-2.example.test", false},
		{"unknown zone", Service{Name: "web", Zone: "other.test"}, "example.test", "", true},
		{"no zone", Service{Name: "web"}, "", "", true},
		{"bad name", Service{Name: "___"}, "example.test", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hostname(tt.svc, zones, tt.def)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}
