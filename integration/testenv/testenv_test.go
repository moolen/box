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
