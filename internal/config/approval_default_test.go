package config

import "testing"

// TrueNAS has no per-app opt-in, so an unset approval fails closed
// ("approve"); docker keeps its empty value (auto: labels are the opt-in).
func TestTrueNASApprovalDefaultsToApprove(t *testing.T) {
	c := mustLoad(t, base+`sources:
  truenas: {url: "https://192.0.2.20", api_key: k}
  docker: {host: "unix:///var/run/docker.sock"}
`)
	if c.Sources.TrueNAS.Approval != "approve" {
		t.Fatalf("truenas approval = %q", c.Sources.TrueNAS.Approval)
	}
	if c.Sources.Docker.Approval != "" && c.Sources.Docker.Approval != "auto" {
		t.Fatalf("docker approval = %q", c.Sources.Docker.Approval)
	}
	c = mustLoad(t, base+`sources:
  truenas: {url: "https://192.0.2.20", api_key: k, approval: auto}
`)
	if c.Sources.TrueNAS.Approval != "auto" {
		t.Fatalf("explicit approval overridden: %q", c.Sources.TrueNAS.Approval)
	}
}
