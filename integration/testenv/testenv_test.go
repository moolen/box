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
	if !cfg.Network.Envoy.Enabled {
		t.Fatalf("network.envoy.enabled = %t, want true", cfg.Network.Envoy.Enabled)
	}
}

func TestWriteEnforceConfigEmitsNetworkPolicyRules(t *testing.T) {
	t.Parallel()

	path := WriteEnforceConfig(t, []string{"example.com"}, []string{"192.0.2.0/24"})

	cfg, err := config.Load(path, t.TempDir())
	if err != nil {
		t.Fatalf("config.Load(%q) error = %v", path, err)
	}

	if len(cfg.Network.Policy) != 2 {
		t.Fatalf("network.policy = %#v, want 2 rules", cfg.Network.Policy)
	}
	if cfg.Network.Policy[0].Hostname != "example.com" {
		t.Fatalf("network.policy[0].Hostname = %q, want example.com", cfg.Network.Policy[0].Hostname)
	}
	if !reflect.DeepEqual(cfg.Network.Policy[0].Ports, []int{80, 443}) {
		t.Fatalf("network.policy[0].Ports = %#v, want [80 443]", cfg.Network.Policy[0].Ports)
	}
	if cfg.Network.Policy[1].CIDR != "192.0.2.0/24" {
		t.Fatalf("network.policy[1].CIDR = %q, want 192.0.2.0/24", cfg.Network.Policy[1].CIDR)
	}
}

func TestStageBundledEnvoyCopiesBinaryNextToBuiltBox(t *testing.T) {
	t.Parallel()

	moduleRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(moduleRoot, "bin"), 0o755); err != nil {
		t.Fatalf("MkdirAll(bin) error = %v", err)
	}
	sourcePath := filepath.Join(moduleRoot, "bin", "envoy")
	if err := os.WriteFile(sourcePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(envoy) error = %v", err)
	}

	outputDir := t.TempDir()
	if err := stageBundledEnvoy(moduleRoot, outputDir); err != nil {
		t.Fatalf("stageBundledEnvoy() error = %v", err)
	}

	stagedPath := filepath.Join(outputDir, "envoy")
	content, err := os.ReadFile(stagedPath)
	if err != nil {
		t.Fatalf("ReadFile(staged envoy) error = %v", err)
	}
	if string(content) != "#!/bin/sh\nexit 0\n" {
		t.Fatalf("staged envoy content = %q, want copied binary", string(content))
	}

	info, err := os.Stat(stagedPath)
	if err != nil {
		t.Fatalf("Stat(staged envoy) error = %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("staged envoy mode = %v, want executable bits", info.Mode().Perm())
	}
}

func TestStageBundledEnvoyReturnsHelpfulErrorWhenMissingAndNoBuilderIsAvailable(t *testing.T) {
	t.Parallel()

	err := stageBundledEnvoyWithDeps(stageBundledEnvoyDeps{
		moduleRoot: t.TempDir(),
		outputDir:  t.TempDir(),
		stat: func(string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	})
	if err == nil {
		t.Fatal("stageBundledEnvoy() error = nil, want missing binary error")
	}
	if !strings.Contains(err.Error(), "bundled envoy binary") {
		t.Fatalf("stageBundledEnvoy() error = %q, want bundled envoy context", err.Error())
	}
}

func TestStageBundledEnvoyRunsEnvoypackWhenRequested(t *testing.T) {
	t.Parallel()

	outputDir := t.TempDir()
	var calls []string

	err := stageBundledEnvoyWithDeps(stageBundledEnvoyDeps{
		moduleRoot: t.TempDir(),
		outputDir:  outputDir,
		stat: func(string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		run: func(name string, args ...string) error {
			calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
			if err := os.WriteFile(filepath.Join(outputDir, "envoy"), []byte("envoy"), 0o755); err != nil {
				return err
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("stageBundledEnvoyWithDeps() error = %v", err)
	}

	want := "go run ./cmd/envoypack --output " + filepath.Join(outputDir, "envoy")
	if !reflect.DeepEqual(calls, []string{want}) {
		t.Fatalf("command calls = %#v, want %#v", calls, []string{want})
	}
	if _, err := os.Stat(filepath.Join(outputDir, "envoy")); err != nil {
		t.Fatalf("Stat(staged envoy) error = %v", err)
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
