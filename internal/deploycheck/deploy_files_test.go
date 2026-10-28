package deploycheck

import (
	"regexp"

	"github.com/ajthom90/doorwarden/internal/source/docker"
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
	if !strings.HasPrefix(sp["image"].(string), "wollomatic/socket-proxy:") || strings.HasSuffix(sp["image"].(string), ":latest") {
		t.Errorf("proxy must be the pinned allowlist proxy, got %v", sp["image"])
	}
	if _, has := sp["ports"]; has {
		t.Error("socket proxy must not publish ports")
	}
	if _, has := sp["expose"]; has {
		t.Error("socket proxy should not expose ports")
	}
	if sp["read_only"] != true {
		t.Error("proxy rootfs must be read_only")
	}
	if caps, _ := sp["cap_drop"].([]any); len(caps) != 1 || caps[0] != "ALL" {
		t.Errorf("cap_drop %v", sp["cap_drop"])
	}
	if sec, _ := sp["security_opt"].([]any); len(sec) != 1 || sec[0] != "no-new-privileges:true" {
		t.Errorf("security_opt %v", sp["security_opt"])
	}
	vols, _ := sp["volumes"].([]any)
	if len(vols) != 1 || vols[0] != "/var/run/docker.sock:/var/run/docker.sock:ro" {
		t.Errorf("socket mount: %v", vols)
	}
	nets, _ := sp["networks"].([]any)
	if len(nets) != 1 || nets[0] != "socket" || sub(t, c, "networks", "socket")["internal"] != true {
		t.Error("socket proxy must sit only on the internal socket network")
	}
	for name, v := range svcs {
		if name == "docker-socket-proxy" {
			continue
		}
		ns, _ := v.(map[string]any)["networks"].([]any)
		shares := false
		for _, n := range ns {
			shares = shares || n == "socket"
		}
		if shares && name != "doorwarden" {
			t.Errorf("service %s must not share the proxy network", name)
		}
	}
	// Allowlist: exactly one flag set per method, only GET, only the list path.
	var get string
	for _, a := range sp["command"].([]any) {
		f := a.(string)
		if strings.HasPrefix(f, "-allow") && !strings.HasPrefix(f, "-allowGET=") && !strings.HasPrefix(f, "-allowfrom=") {
			t.Errorf("unexpected allow flag %q (only GET on containers/json is permitted)", f)
		}
		if v, ok := strings.CutPrefix(f, "-allowGET="); ok {
			get = strings.ReplaceAll(v, "$$", "$") // compose escape
		}
	}
	if get == "" || strings.Contains(get, ".*") || strings.Contains(get, "|") {
		t.Fatalf("allowGET %q must be one exact pattern", get)
	}
	re := regexp.MustCompile(get)
	if !re.MatchString(docker.ContainersListPath) {
		t.Errorf("allowlist %q does not permit the docker source path %q", get, docker.ContainersListPath)
	}
	for _, bad := range []string{"/containers/abc/json", "/containers/abc/archive", "/containers/json/x", "/v1.45/containers/json", "/version", "/exec/x/start", "/containers/abc/logs"} {
		if re.MatchString(bad) {
			t.Errorf("allowlist %q must not permit %q", get, bad)
		}
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
	// Hardening on all three services, and only traefik publishes ports.
	var users []any
	for _, n := range []string{"doorwarden", "traefik", "docker-socket-proxy"} {
		sv := sub(t, svcs, n)
		if caps, _ := sv["cap_drop"].([]any); len(caps) != 1 || caps[0] != "ALL" {
			t.Errorf("%s: cap_drop %v", n, sv["cap_drop"])
		}
		if sec, _ := sv["security_opt"].([]any); len(sec) != 1 || sec[0] != "no-new-privileges:true" {
			t.Errorf("%s: security_opt %v", n, sv["security_opt"])
		}
		if sv["read_only"] != true {
			t.Errorf("%s: read_only %v", n, sv["read_only"])
		}
		_, hasPorts := sv["ports"]
		if hasPorts != (n == "traefik") {
			t.Errorf("%s: ports published=%v (only traefik may publish)", n, hasPorts)
		}
		if n != "docker-socket-proxy" {
			users = append(users, sv["user"])
		}
	}
	if users[0] != "65532:65532" || users[0] != users[1] {
		t.Errorf("doorwarden and traefik must share user 65532:65532, got %v", users)
	}
	var tports []string
	for _, p := range sub(t, svcs, "traefik")["ports"].([]any) {
		tports = append(tports, p.(string))
	}
	if len(tports) != 2 || !strings.HasSuffix(tports[0], ":80") || !strings.HasSuffix(tports[1], ":443") {
		t.Errorf("traefik ports %v", tports)
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
	os.WriteFile(env, []byte("DOORWARDEN_MASTER_KEY=dummy\nDOORWARDEN_TAG=1.0.0\n"), 0o600)
	out, err := exec.Command("docker", "compose", "--env-file", env, "-f", "../../deploy/compose.truenas.yml", "config", "-q").CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose config: %v\n%s", err, out)
	}
}

// The docker source must issue exactly one request, built from the exported
// path constant; a second request site means the proxy allowlist needs review.
func TestDockerSourceSingleEndpoint(t *testing.T) {
	b, err := os.ReadFile("../source/docker/docker.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if n := strings.Count(src, "http.NewRequest"); n != 1 {
		t.Errorf("docker source has %d request sites, want 1: update the proxy allowlist explicitly", n)
	}
	if !strings.Contains(src, "ContainersListPath") {
		t.Error("docker source must build its URL from ContainersListPath")
	}
}

func TestReleaseWorkflowLatestOnlyForStable(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf map[string]any
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	src := string(b)
	cond := "enable=${{ !contains(github.ref_name, '-') }}"
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "value=latest") && !strings.Contains(line, cond) {
			t.Errorf("latest tag lacks stable-only condition: %q", line)
		}
	}
	if !strings.Contains(src, "value=latest,"+cond) {
		t.Error("latest tag rule missing")
	}
	perms := sub(t, wf, "permissions")
	if perms["contents"] != "read" {
		t.Error("top-level permissions")
	}
	ci := loadYAML(t, ".github/workflows/ci.yml")
	if sub(t, ci, "permissions")["contents"] != "read" {
		t.Error("ci.yml needs top-level permissions: contents: read")
	}
}

func TestEnvExampleHasNoUsableSecrets(t *testing.T) {
	b, _ := os.ReadFile("../../deploy/.env.example")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "DOORWARDEN_MASTER_KEY=") && strings.TrimPrefix(l, "DOORWARDEN_MASTER_KEY=") != "" {
			t.Errorf("master key must be empty in the example: %q", l)
		}
		if strings.Contains(l, "change-me") && !strings.HasPrefix(l, "#") {
			t.Errorf("placeholder secret: %q", l)
		}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return
	}
	if exec.Command("docker", "compose", "version").Run() != nil {
		return
	}
	cmd := exec.Command("docker", "compose", "--env-file", "../../deploy/.env.example", "-f", "../../deploy/compose.truenas.yml", "config", "-q")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Errorf("compose accepted the unmodified .env.example: %s", out)
	}
	cmd = exec.Command("docker", "compose", "--env-file", "../../deploy/.env.example", "-f", "../../deploy/compose.truenas.yml", "config", "-q")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "DOORWARDEN_MASTER_KEY=x", "DOORWARDEN_TAG=1.0.0"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("compose config with required vars set: %v\n%s", err, out)
	}
}
