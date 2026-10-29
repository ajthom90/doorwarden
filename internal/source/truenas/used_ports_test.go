package truenas

import (
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/model"
)

func appWithPorts(name, portals, usedPorts string) string {
	return `{"name":"` + name + `","state":"RUNNING","portals":` + portals +
		`,"active_workloads":{"containers":1,"used_ports":` + usedPorts + `}}`
}

// Final-review H2: a portal port must be one of the app's own published host
// ports (active_workloads.used_ports) when app.query reports them.
func TestPortalPortValidatedAgainstUsedPorts(t *testing.T) {
	used := `[{"container_port":"80","protocol":"tcp","host_ports":[{"host_port":"30001","host_ip":"0.0.0.0"}]},` +
		`{"container_port":443,"protocol":"tcp","host_ports":[{"host_port":30002,"host_ip":"::"}]}]`
	t.Run("matching portal", func(t *testing.T) {
		svc, _ := list1(t, appsJSON(appWithPorts("a", `{"Web UI":"http://0.0.0.0:30001/"}`, used)), nil)
		if svc.State != model.StateDiscovered || svc.Backend.Port != 30001 {
			t.Fatalf("%+v", svc)
		}
		svc, _ = list1(t, appsJSON(appWithPorts("a", `{"Web UI":"https://0.0.0.0:30002/"}`, used)), nil)
		if svc.State != model.StateDiscovered || svc.Backend.Port != 30002 {
			t.Fatalf("numeric ports: %+v", svc)
		}
	})
	t.Run("non-matching Web UI dropped, another portal matches", func(t *testing.T) {
		svc, _ := list1(t, appsJSON(appWithPorts("a", `{"Web UI":"http://0.0.0.0:8443/","Other":"http://0.0.0.0:30001/"}`, used)), nil)
		if svc.State != model.StateDiscovered || svc.Backend.Port != 30001 {
			t.Fatalf("%+v", svc)
		}
	})
	t.Run("no portal matches: Error, no backend", func(t *testing.T) {
		svc, s := list1(t, appsJSON(appWithPorts("a", `{"Web UI":"http://0.0.0.0:22/"}`, used)), nil)
		if svc.State != model.StateError || svc.Backend.Host != "" || svc.Backend.Port != 0 {
			t.Fatalf("%+v", svc)
		}
		if w := s.Warnings(); len(w) != 1 || !strings.Contains(w[0], "22") {
			t.Fatalf("warnings %v", w)
		}
	})
	t.Run("udp ports do not count", func(t *testing.T) {
		u := `[{"container_port":"53","protocol":"udp","host_ports":[{"host_port":"30001","host_ip":"0.0.0.0"}]}]`
		svc, _ := list1(t, appsJSON(appWithPorts("a", `{"Web UI":"http://0.0.0.0:30001/"}`, u)), nil)
		if svc.State != model.StateError {
			t.Fatalf("%+v", svc)
		}
	})
	t.Run("no used_ports reported: portal kept (approval covers the port)", func(t *testing.T) {
		svc, _ := list1(t, appsJSON(appWithPorts("a", `{"Web UI":"http://0.0.0.0:30001/"}`, `[]`)), nil)
		if svc.State != model.StateDiscovered || svc.Backend.Port != 30001 {
			t.Fatalf("%+v", svc)
		}
	})
}

// Error carries no backend (T6 contract).
func TestPortalLessErrorHasNoBackend(t *testing.T) {
	svc, _ := list1(t, appsJSON(appJSON("a", "RUNNING", `{}`)), nil)
	if svc.State != model.StateError || svc.Backend.Host != "" || svc.Backend.Port != 0 {
		t.Fatalf("%+v", svc)
	}
}
