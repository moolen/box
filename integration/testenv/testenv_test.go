package testenv

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gvisor-net/internal/config"
)

func TestFindModuleRoot(t *testing.T) {
	t.Parallel()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}

	root, err := findModuleRoot(cwd)
	if err != nil {
		t.Fatalf("findModuleRoot() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %q missing go.mod: %v", root, err)
	}
}

func TestInvalidPackageReturnsBuildError(t *testing.T) {
	t.Parallel()

	output := filepath.Join(t.TempDir(), "box-test-bin")
	err := buildPackage("./cmd/definitely-not-a-package", output)
	if err == nil {
		t.Fatal("buildPackage() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "go build") {
		t.Fatalf("buildPackage() error = %q, want mention of go build", err)
	}
}

func TestGoBuildArgsDisableVCSStamping(t *testing.T) {
	t.Parallel()

	got := goBuildArgs("./cmd/box", "/tmp/box")
	want := []string{"build", "-buildvcs=false", "-o", "/tmp/box", "./cmd/box"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("goBuildArgs() = %#v, want %#v", got, want)
	}
}

func TestWriteOpenCodeMonitorConfig(t *testing.T) {
	t.Parallel()

	hostBinDir := "/tmp/opencode-bin"
	hostPath := "/tmp/opencode-bin:/usr/bin:/bin"
	path := WriteOpenCodeMonitorConfig(t, hostBinDir, hostPath)

	cfg, err := config.Load(path, t.TempDir())
	if err != nil {
		t.Fatalf("config.Load(%q) error = %v", path, err)
	}

	if !cfg.Sandbox.InheritEnv {
		t.Fatalf("sandbox.inherit_env = %t, want true", cfg.Sandbox.InheritEnv)
	}
	if !containsString(cfg.Sandbox.Env, "PATH="+hostPath) {
		t.Fatalf("sandbox.env = %#v, want PATH=%q entry", cfg.Sandbox.Env, hostPath)
	}
	if !containsString(cfg.Mounts.ExtraRO, hostBinDir) {
		t.Fatalf("mounts.extra_ro = %#v, want %q", cfg.Mounts.ExtraRO, hostBinDir)
	}
	if cfg.Network.Mode != "monitor" {
		t.Fatalf("network.mode = %q, want monitor", cfg.Network.Mode)
	}
	if !cfg.Network.TransparentProxy.Enabled {
		t.Fatalf("network.transparent_proxy.enabled = %t, want true", cfg.Network.TransparentProxy.Enabled)
	}
	if len(cfg.Policy.Egress) != 0 {
		t.Fatalf("policy.egress = %#v, want empty list", cfg.Policy.Egress)
	}
}

func TestWriteEnforceConfig(t *testing.T) {
	t.Parallel()

	path := WriteEnforceConfig(t, `
- hostname: example.com
  transport:
    - protocol: tcp
      ports: [443]
- cidr: 203.0.113.7/32
  icmp:
    - type: 8
      code: 0
`)

	cfg, err := config.Load(path, t.TempDir())
	if err != nil {
		t.Fatalf("config.Load(%q) error = %v", path, err)
	}

	if cfg.Network.Mode != "enforce" {
		t.Fatalf("network.mode = %q, want enforce", cfg.Network.Mode)
	}
	if cfg.Docker.Enabled {
		t.Fatalf("docker.enabled = %t, want false by default", cfg.Docker.Enabled)
	}
	if len(cfg.Policy.Egress) != 2 {
		t.Fatalf("policy.egress len = %d, want 2", len(cfg.Policy.Egress))
	}
	if cfg.Policy.Egress[0].Hostname != "example.com" {
		t.Fatalf("policy.egress[0].hostname = %q, want example.com", cfg.Policy.Egress[0].Hostname)
	}
	if cfg.Policy.Egress[1].CIDR != "203.0.113.7/32" {
		t.Fatalf("policy.egress[1].cidr = %q, want 203.0.113.7/32", cfg.Policy.Egress[1].CIDR)
	}
}

func TestWriteEnforceConfigUsesCustomDNSUpstreams(t *testing.T) {
	t.Parallel()

	path := WriteEnforceConfigWithDNSUpstreams(t, "[]", []string{"127.0.0.1:5301"})

	cfg, err := config.Load(path, t.TempDir())
	if err != nil {
		t.Fatalf("config.Load(%q) error = %v", path, err)
	}

	if !reflect.DeepEqual(cfg.Network.DNS.Upstream, []string{"127.0.0.1:5301"}) {
		t.Fatalf("network.dns.upstream = %#v, want %#v", cfg.Network.DNS.Upstream, []string{"127.0.0.1:5301"})
	}
	if len(cfg.Policy.Egress) != 0 {
		t.Fatalf("policy.egress = %#v, want empty list", cfg.Policy.Egress)
	}
}

func TestWriteEnforceDockerConfigEnablesDocker(t *testing.T) {
	t.Parallel()

	path := WriteEnforceDockerConfig(t, "[]")

	cfg, err := config.Load(path, t.TempDir())
	if err != nil {
		t.Fatalf("config.Load(%q) error = %v", path, err)
	}
	if !cfg.Docker.Enabled {
		t.Fatalf("docker.enabled = %t, want true", cfg.Docker.Enabled)
	}
}

func TestWriteOpenCodeMonitorConfigRejectsNonAbsoluteHostBinDir(t *testing.T) {
	t.Parallel()

	const marker = "TEST_WRITECONFIG_NONABS"
	if os.Getenv(marker) == "1" {
		WriteOpenCodeMonitorConfig(t, "relative/bin", "/usr/bin:/bin")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestWriteOpenCodeMonitorConfigRejectsNonAbsoluteHostBinDir$")
	cmd.Env = append(os.Environ(), marker+"=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected subprocess to fail for non-absolute hostBinDir, got nil error")
	}
}

func TestWriteDefaultConfigRandomizesProxyPorts(t *testing.T) {
	t.Parallel()

	moduleRoot, err := moduleRootFromWorkingDir()
	if err != nil {
		t.Fatalf("moduleRootFromWorkingDir() error = %v", err)
	}

	path := WriteDefaultConfig(t, moduleRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	content := string(data)
	if strings.Contains(content, "http_port: 18080") {
		t.Fatalf("default config still contains fixed http proxy port: %q", content)
	}
	if strings.Contains(content, "tls_port: 18443") {
		t.Fatalf("default config still contains fixed tls proxy port: %q", content)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
