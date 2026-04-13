package rootfs

import (
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
	if _, err := os.Stat("/etc/ssl"); err == nil && !slices.Contains(roTargets, "/etc/ssl") {
		t.Fatalf("readonly binds missing optional trust store /etc/ssl; got %#v", roTargets)
	}
}

func TestHostOverlayPlanCreatesWritableRuntimeDirsWithoutHostBinds(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{
		RootfsMode: "host-overlay",
		RepoPath:   "/home/user/repo",
		Workdir:    "/workspace",
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

	wantWritableDirs := []string{"/tmp", "/var/tmp", "/run", "/var/run", "/var/cache"}
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

func TestGeneratedEtcFilesUseGatewayDNSInEnforceMode(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{
		RootfsMode:   "host-overlay",
		RepoPath:     "/repo",
		Workdir:      "/work",
		NetworkMode:  "enforce",
		GatewayIP:    "100.96.0.1",
		SandboxHostn: "box",
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	for _, file := range plan.GeneratedFiles {
		if file.Path != "/etc/resolv.conf" {
			continue
		}
		if !strings.Contains(file.Content, "nameserver 100.96.0.1") {
			t.Fatalf("resolv.conf = %q, want nameserver gateway", file.Content)
		}
		if strings.Contains(file.Content, "127.0.0.1") {
			t.Fatalf("resolv.conf = %q, must not use localhost nameserver in enforce mode", file.Content)
		}
		return
	}

	t.Fatalf("generated resolv.conf missing from plan: %#v", plan.GeneratedFiles)
}

func TestBuildPlanStagesRuntimeCACertWhenProvided(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{
		RootfsMode:       "host-overlay",
		RepoPath:         "/repo",
		Workdir:          "/work",
		RuntimeCACertPEM: "-----BEGIN CERTIFICATE-----\nruntime\n-----END CERTIFICATE-----\n",
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	for _, file := range plan.GeneratedFiles {
		if file.Path != RuntimeCACertPath {
			continue
		}
		if !strings.Contains(file.Content, "BEGIN CERTIFICATE") {
			t.Fatalf("runtime CA content = %q, want PEM", file.Content)
		}
		return
	}

	t.Fatalf("generated runtime CA file missing from plan: %#v", plan.GeneratedFiles)
}

func TestBuildPlanStagesTrustedCACertWhenRequested(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{
		RootfsMode:        "host-overlay",
		TrustedCACertPEM:  "-----BEGIN CERTIFICATE-----\nbox\n-----END CERTIFICATE-----\n",
		TrustedCACertPath: TrustedCABundlePath,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	for _, file := range plan.GeneratedFiles {
		if file.Path != TrustedCABundlePath {
			continue
		}
		if file.Content != "-----BEGIN CERTIFICATE-----\nbox\n-----END CERTIFICATE-----\n" {
			t.Fatalf("trusted CA content = %q, want requested PEM", file.Content)
		}
		if file.Mode != 0o644 {
			t.Fatalf("trusted CA mode = %v, want 0644", file.Mode)
		}
		return
	}

	t.Fatalf("trusted CA file missing from plan: %#v", plan.GeneratedFiles)
}

func TestBuildPlanStagesRuntimeAndTrustedCACertsWhenBothProvided(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{
		RootfsMode:        "host-overlay",
		RuntimeCACertPEM:  "-----BEGIN CERTIFICATE-----\nruntime\n-----END CERTIFICATE-----\n",
		TrustedCACertPEM:  "-----BEGIN CERTIFICATE-----\ntrusted\n-----END CERTIFICATE-----\n",
		TrustedCACertPath: TrustedCABundlePath,
	})
	if err != nil {
		t.Fatalf("BuildPlan() error: %v", err)
	}

	var sawRuntime bool
	var sawTrusted bool
	for _, file := range plan.GeneratedFiles {
		switch file.Path {
		case RuntimeCACertPath:
			sawRuntime = strings.Contains(file.Content, "runtime")
		case TrustedCABundlePath:
			sawTrusted = strings.Contains(file.Content, "trusted")
		}
	}
	if !sawRuntime || !sawTrusted {
		t.Fatalf("generated files = %#v, want runtime CA and trusted bundle", plan.GeneratedFiles)
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

func TestApplyCreatesBindTargetDirectoriesInBundle(t *testing.T) {
	temp := t.TempDir()
	shim := filepath.Join(temp, "box-initshim")
	if err := os.WriteFile(shim, []byte("shim"), 0o755); err != nil {
		t.Fatalf("WriteFile(shim): %v", err)
	}

	bundleDir := filepath.Join(temp, "bundle")
	_, err := Apply(ApplyRequest{
		BundleDir:    bundleDir,
		InitShimPath: shim,
		Plan: Plan{
			Binds: []Bind{
				{Source: "/opt/tools/bin", Target: "/tmp/opencode-prefix/bin", ReadOnly: true},
				{Source: "/repo", Target: "/workspace", ReadOnly: false},
			},
		},
	})
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}

	for _, target := range []string{"/tmp/opencode-prefix/bin", "/workspace"} {
		staged := filepath.Join(bundleDir, "rootfs", strings.TrimPrefix(filepath.Clean(target), "/"))
		info, err := os.Stat(staged)
		if err != nil {
			t.Fatalf("Stat(%q): %v", staged, err)
		}
		if !info.IsDir() {
			t.Fatalf("staged bind target %q is not a directory", staged)
		}
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
