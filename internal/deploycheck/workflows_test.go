package deploycheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	pinnedUsesRE  = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	versionCommRE = regexp.MustCompile(`^#\s*v?\d+(\.\d+)*\S*$`)
)

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func hasPackagesWrite(perms *yaml.Node) bool {
	p := mapGet(perms, "packages")
	return p != nil && p.Value == "write"
}

// lintWorkflowDir returns every policy violation found in dir/*.yml.
func lintWorkflowDir(dir string) ([]string, int, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, 0, err
	}
	var bad []string
	add := func(f, format string, a ...any) {
		bad = append(bad, filepath.Base(f)+": "+fmt.Sprintf(format, a...))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, 0, err
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return nil, 0, fmt.Errorf("%s: %w", f, err)
		}
		root := doc.Content[0]
		if mapGet(root, "permissions") == nil {
			add(f, "missing top-level permissions")
		}
		if on := mapGet(root, "on"); on != nil && on.Kind == yaml.MappingNode && mapGet(on, "pull_request_target") != nil {
			add(f, "pull_request_target is forbidden")
		}
		jobs := mapGet(root, "jobs")
		if jobs == nil || jobs.Kind != yaml.MappingNode {
			add(f, "no jobs")
			continue
		}
		writers := []string{}
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			name, job := jobs.Content[i].Value, jobs.Content[i+1]
			if hasPackagesWrite(mapGet(job, "permissions")) {
				writers = append(writers, name)
			}
			steps := mapGet(job, "steps")
			if steps == nil {
				continue
			}
			for _, st := range steps.Content {
				u := mapGet(st, "uses")
				if u == nil || strings.HasPrefix(u.Value, "./") {
					continue
				}
				if !pinnedUsesRE.MatchString(u.Value) {
					add(f, "job %s: %q is not pinned to a 40-hex commit SHA", name, u.Value)
				}
				if !versionCommRE.MatchString(strings.TrimSpace(u.LineComment)) {
					add(f, "job %s: %q lacks a trailing version comment (got %q)", name, u.Value, u.LineComment)
				}
				if strings.HasPrefix(u.Value, "actions/checkout@") {
					with := mapGet(st, "with")
					if pc := mapGet(with, "persist-credentials"); pc == nil || pc.Value != "false" {
						add(f, "job %s: checkout must set persist-credentials: false", name)
					}
				}
			}
		}
		if filepath.Base(f) == "release.yml" {
			if len(writers) != 1 || writers[0] != "image" {
				add(f, "packages: write must be held only by the image job, got %v", writers)
			}
			if hasPackagesWrite(mapGet(root, "permissions")) {
				add(f, "top-level permissions must not grant packages: write")
			}
		} else if len(writers) > 0 {
			add(f, "unexpected packages: write in jobs %v", writers)
		}
	}
	return bad, len(files), nil
}

func TestWorkflowsHardened(t *testing.T) {
	bad, n, err := lintWorkflowDir(filepath.Join("..", "..", ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no workflows found")
	}
	for _, b := range bad {
		t.Error(b)
	}
}

func TestWorkflowLintCatchesRegressions(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	good := string(src)
	cases := map[string]string{
		"floating tag":  strings.Replace(good, "docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9", "docker/login-action@v3", 1),
		"no comment":    strings.Replace(good, " # v3.7.0", "", 1),
		"target":        strings.Replace(good, "on:\n", "on:\n  pull_request_target:\n", 1),
		"persist creds": strings.Replace(good, "persist-credentials: false", "persist-credentials: true", 1),
		"test writes":   strings.Replace(good, "  test:\n    runs-on: ubuntu-latest\n", "  test:\n    runs-on: ubuntu-latest\n    permissions:\n      packages: write\n", 1),
	}
	for name, mutated := range cases {
		if mutated == good {
			t.Fatalf("%s: mutation did not apply", name)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "release.yml"), []byte(mutated), 0o600); err != nil {
			t.Fatal(err)
		}
		bad, _, err := lintWorkflowDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(bad) == 0 {
			t.Errorf("%s: lint did not flag the mutation", name)
		}
	}
}
