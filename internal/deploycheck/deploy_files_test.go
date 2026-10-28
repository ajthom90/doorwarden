package deploycheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func loadYAML(t *testing.T, rel string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return m
}

func sub(t *testing.T, m map[string]any, path ...string) map[string]any {
	t.Helper()
	cur := m
	for _, p := range path {
		n, ok := cur[p].(map[string]any)
		if !ok {
			t.Fatalf("missing %s", strings.Join(path, "."))
		}
		cur = n
	}
	return cur
}

func TestComposeSafety(t *testing.T) {
	c := loadYAML(t, "deploy/compose.truenas.yml")
	svcs := sub(t, c, "services")
	for _, n := range []string{"doorwarden", "traefik", "docker-socket-proxy"} {
		s := sub(t, svcs, n)
		if s["restart"] == nil || s["image"] == nil {
			t.Errorf("%s: restart/image missing", n)
		}
	}
	sp := sub(t, svcs, "docker-socket-proxy")
	if _, has := sp["ports"]; has {
		t.Error("socket proxy must not publish ports")
	}
	env := sub(t, sp, "environment")
	if env["POST"] != "0" || env["CONTAINERS"] != "1" {
		t.Errorf("socket proxy env %v", env)
	}
	for k, v := range env {
		if k != "CONTAINERS" && v != "0" {
			t.Errorf("socket proxy %s=%v, want 0", k, v)
		}
	}
	vols, _ := sp["volumes"].([]any)
	if len(vols) != 1 || !strings.HasSuffix(vols[0].(string), "/docker.sock:/var/run/docker.sock:ro") {
		t.Errorf("socket must be mounted read-only: %v", vols)
	}
	if sp["networks"].([]any)[0] != "socket" || sub(t, c, "networks", "socket")["internal"] != true {
		t.Error("socket proxy must sit on the internal network only")
	}
	if strings.Contains(sp["image"].(string), ":latest") || !strings.Contains(sp["image"].(string), ":") {
		t.Error("socket proxy image must be pinned")
	}
	tr := sub(t, svcs, "traefik")
	if strings.HasSuffix(tr["image"].(string), ":latest") {
		t.Error("traefik must be pinned")
	}
	var certsRO, dynRO bool
	for _, v := range tr["volumes"].([]any) {
		s := v.(string)
		certsRO = certsRO || strings.HasSuffix(s, ":/certs:ro")
		dynRO = dynRO || strings.HasSuffix(s, ":/etc/traefik/dynamic:ro")
		if strings.Contains(s, "docker.sock") {
			t.Error("traefik must not mount the docker socket")
		}
	}
	if !certsRO || !dynRO {
		t.Error("traefik certs and dynamic dir must be read-only")
	}
	dw := sub(t, svcs, "doorwarden")
	var dynRW bool
	for _, v := range dw["volumes"].([]any) {
		dynRW = dynRW || strings.HasSuffix(v.(string), ":/etc/traefik/dynamic:rw")
	}
	if !dynRW {
		t.Error("doorwarden needs rw dynamic dir")
	}
	raw, _ := os.ReadFile("../../deploy/compose.truenas.yml")
	if strings.Contains(strings.ToLower(string(raw)), "certificatesresolvers") {
		t.Error("compose must not configure ACME in Traefik")
	}
}

func TestTraefikStatic(t *testing.T) {
	c := loadYAML(t, "deploy/traefik/traefik.yml")
	for _, bad := range []string{"certificatesResolvers", "api"} {
		if _, ok := c[bad]; ok {
			t.Errorf("%s must not be set (dashboard/api off, no resolvers)", bad)
		}
	}
	if _, ok := sub(t, c, "providers")["docker"]; ok {
		t.Error("docker provider must not be enabled")
	}
	if sub(t, c, "providers", "file")["directory"] != "/etc/traefik/dynamic" {
		t.Error("file provider directory")
	}
	web := sub(t, c, "entryPoints", "web")
	if web["address"] != ":80" {
		t.Error("web address")
	}
	redir := sub(t, web, "http", "redirections", "entryPoint")
	if redir["to"] != "websecure" || redir["permanent"] != true || redir["scheme"] != "https" {
		t.Errorf("redirect %v", redir)
	}
	if sub(t, c, "entryPoints", "websecure")["address"] != ":443" {
		t.Error("websecure address")
	}
	if sub(t, c, "accessLog")["format"] != "json" {
		t.Error("access log json")
	}
}

func TestComposeConfigWithDocker(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose unavailable")
	}
	env := filepath.Join(t.TempDir(), "dummy.env")
	os.WriteFile(env, []byte("DOORWARDEN_MASTER_KEY=dummy\n"), 0o600)
	out, err := exec.Command("docker", "compose", "--env-file", env, "-f", "../../deploy/compose.truenas.yml", "config", "-q").CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose config: %v\n%s", err, out)
	}
}
