// Package deploycheck holds tests over the repository's deployment artifacts
// (scripts, compose and Traefik files). It has no non-test code.
package deploycheck

import (
	"os/exec"
	"testing"
)

func TestVerifyScript(t *testing.T) {
	for _, tool := range []string{"bash", "openssl", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	out, err := exec.Command("bash", "../../scripts/verify_test.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("verify_test.sh: %v\n%s", err, out)
	}
	t.Log(string(out))
}
