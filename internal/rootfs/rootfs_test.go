package rootfs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestHostOverlayPlanIncludesRecoveredReadonlyBinds(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{
		RootfsMode: "host-overlay",
		RepoPath:   "/repo",
		Workdir:    "/work",
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	var roTargets []string
	for _, bind := range plan.Binds {
		if bind.ReadOnly {
			roTargets = append(roTargets, bind.Target)
		}
	}

	wantRO := []string{"/bin", "/sbin", "/usr", "/lib", "/lib64"}
	for _, target := range wantRO {
		if !slices.Contains(roTargets, target) {
			t.Fatalf("readonly binds missing %q; got %#v", target, roTargets)
		}
	}
}

func TestHostOverlayPlanCreatesWritableRuntimeDirsWithoutHostBinds(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{
		RootfsMode:     "host-overlay",
		RepoPath:       "/home/user/repo",
		Workdir:        "/workspace",
		DockerEnabled:  true,
		DockerDataRoot: "/var/lib/docker",
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	var foundWorkdirBind bool
	for _, bind := range plan.Binds {
		if bind.Source == "/home/user/repo" && bind.Target == "/workspace" {
			foundWorkdirBind = true
		}
	}

	wantWritableDirs := []string{"/tmp", "/var/tmp", "/run", "/var/run", "/var/cache", "/var/lib/docker"}
	for _, target := range wantWritableDirs {
		if !slices.Contains(plan.WritableDirs, target) {
			t.Fatalf("WritableDirs missing %q; got %#v", target, plan.WritableDirs)
		}
		if bindTargetExists(plan.Binds, target) {
			t.Fatalf("host bind for writable runtime dir %q must not exist; binds=%#v", target, plan.Binds)
		}
	}
	if !foundWorkdirBind {
		t.Fatalf("expected repo path to be mounted rw at workdir; binds=%#v", plan.Binds)
	}
}

func TestGeneratedEtcFilesUseGatewayDNSInMonitorMode(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{
		RootfsMode:   "host-overlay",
		RepoPath:     "/repo",
		Workdir:      "/work",
		NetworkMode:  "monitor",
		GatewayIP:    "100.96.0.1",
		SandboxHostn: "box",
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	files := map[string]string{}
	for _, f := range plan.GeneratedFiles {
		files[f.Path] = f.Content
	}

	for _, p := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/hostname", "/etc/passwd", "/etc/group"} {
		if _, ok := files[p]; !ok {
			t.Fatalf("generated file %q missing; got keys=%#v", p, mapsKeys(files))
		}
	}

	resolv := files["/etc/resolv.conf"]
	if !strings.Contains(resolv, "nameserver 100.96.0.1") {
		t.Fatalf("resolv.conf = %q, want nameserver gateway", resolv)
	}
	if strings.Contains(resolv, "127.0.0.1") {
		t.Fatalf("resolv.conf = %q, must not use localhost nameserver in monitor mode", resolv)
	}
}

func TestBuildPlanGeneratesDockerDaemonConfigWithProxySettings(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{
		RootfsMode:       "host-overlay",
		DockerEnabled:    true,
		DockerDataRoot:   "/var/lib/docker",
		DockerSocketPath: "/var/run/docker.sock",
		DockerHTTPProxy:  "http://100.96.0.1:18080",
		DockerHTTPSProxy: "http://100.96.0.1:18080",
		DockerNoProxy:    "127.0.0.1,localhost",
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	var daemon GeneratedFile
	var found bool
	for _, file := range plan.GeneratedFiles {
		if file.Path == "/etc/docker/daemon.json" {
			daemon = file
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("generated docker daemon config missing; files=%#v", plan.GeneratedFiles)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(daemon.Content), &parsed); err != nil {
		t.Fatalf("daemon.json decode error: %v\ncontent=%s", err, daemon.Content)
	}

	if got := parsed["data-root"]; got != "/var/lib/docker" {
		t.Fatalf("data-root = %#v, want %q", got, "/var/lib/docker")
	}
	hosts, ok := parsed["hosts"].([]any)
	if !ok || len(hosts) != 1 || hosts[0] != "unix:///var/run/docker.sock" {
		t.Fatalf("hosts = %#v, want unix socket host", parsed["hosts"])
	}
	proxies, ok := parsed["proxies"].(map[string]any)
	if !ok {
		t.Fatalf("proxies = %#v, want object", parsed["proxies"])
	}
	if got := proxies["http-proxy"]; got != "http://100.96.0.1:18080" {
		t.Fatalf("http-proxy = %#v, want host proxy URL", got)
	}
	if got := proxies["https-proxy"]; got != "http://100.96.0.1:18080" {
		t.Fatalf("https-proxy = %#v, want host proxy URL", got)
	}
	if got := proxies["no-proxy"]; got != "127.0.0.1,localhost" {
		t.Fatalf("no-proxy = %#v, want localhost bypass list", got)
	}
}

func TestResolveInitShimCopiesSiblingBinaryIntoBundle(t *testing.T) {
	temp := t.TempDir()
	exePath := filepath.Join(temp, "bin", "box")
	if err := os.MkdirAll(filepath.Dir(exePath), 0o755); err != nil {
		t.Fatalf("MkdirAll(exe dir): %v", err)
	}
	if err := os.WriteFile(exePath, []byte("box"), 0o755); err != nil {
		t.Fatalf("WriteFile(exe): %v", err)
	}

	siblingShim := filepath.Join(filepath.Dir(exePath), "box-initshim")
	const shimContents = "#!/bin/sh\necho shim\n"
	if err := os.WriteFile(siblingShim, []byte(shimContents), 0o755); err != nil {
		t.Fatalf("WriteFile(sibling shim): %v", err)
	}

	bundleDir := filepath.Join(temp, "bundle")
	result, err := Apply(ApplyRequest{
		BundleDir:      bundleDir,
		ExecutablePath: exePath,
	})
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}

	gotPath := result.InitShimBundlePath
	if gotPath == "" {
		t.Fatalf("Apply() returned empty InitShimBundlePath")
	}
	wantPath := filepath.Join(bundleDir, "rootfs", "box-initshim")
	if gotPath != wantPath {
		t.Fatalf("InitShimBundlePath = %q, want %q", gotPath, wantPath)
	}
	gotBytes, err := os.ReadFile(gotPath)
	if err != nil {
		t.Fatalf("ReadFile(copied shim): %v", err)
	}
	if string(gotBytes) != shimContents {
		t.Fatalf("copied shim content = %q, want %q", string(gotBytes), shimContents)
	}
}

func TestBuildPlanRejectsUnknownRootfsMode(t *testing.T) {
	_, err := BuildPlan(PlanRequest{
		RootfsMode: "mystery",
	})
	if err == nil {
		t.Fatalf("BuildPlan() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "unsupported rootfs mode") {
		t.Fatalf("BuildPlan() error = %q, want unsupported rootfs mode", err.Error())
	}
}

func TestApplyRejectsGeneratedFilePathTraversal(t *testing.T) {
	temp := t.TempDir()
	shim := filepath.Join(temp, "shim")
	if err := os.WriteFile(shim, []byte("shim"), 0o755); err != nil {
		t.Fatalf("WriteFile(shim): %v", err)
	}

	_, err := Apply(ApplyRequest{
		BundleDir:    filepath.Join(temp, "bundle"),
		InitShimPath: shim,
		Plan: Plan{
			GeneratedFiles: []GeneratedFile{
				{Path: "../../escape", Content: "x", Mode: 0o644},
			},
		},
	})
	if err == nil {
		t.Fatalf("Apply() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "escapes rootfs") {
		t.Fatalf("Apply() error = %q, want contains %q", err.Error(), "escapes rootfs")
	}
}

func mapsKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func bindTargetExists(binds []Bind, target string) bool {
	for _, bind := range binds {
		if bind.Target == target {
			return true
		}
	}
	return false
}
